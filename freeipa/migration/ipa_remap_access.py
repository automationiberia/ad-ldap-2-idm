#!/usr/bin/env python3
# Copyright (C) 2026 BCN Consulting Lab
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Plan and apply OpenLDAP hostAccess/sudo → IdM HBAC / hostgroups / sudorule
==========================================================================

**LEGACY PATH** — use after ``ipa migrate-ds`` (native IdM users).
For **AD Trust**, use ``ipa_remap_trust_policy.py`` instead.

Two stages (same tool, different when/where you run it):

  PLAN (default — only reads LDIFs; does NOT talk to IdM)
    --list-bundles
    --bundle hg_web
      → always writes ipa_remap_access.d/ipa_remap_hg_web.sh
      → prints at most 50 lines on screen (rest only in the file)

  APPLY (--execute — local ``ipa`` CLI on IdM; AFTER migrate-ds)
    --bundle hg_web --execute

Hosts are NOT pre-created by default. After enroll, run the generated
``ipa_remap_<hg>_hosts.sh`` (FQDN list + hostgroup-add-member commands).

Default mode is **bundle** (vertical slice per hostgroup).

  python3 ipa_remap_access.py --list-bundles \\
    --users u.ldif --groups g.ldif --sudo s.ldif

  # On IdM, after migrate-ds:
  python3 ipa_remap_access.py ... --bundle hg_web --execute
  # enroll hosts listed in ipa_remap_hg_web_hosts.sh, then:
  bash ipa_remap_access.d/ipa_remap_hg_web_hosts.sh
"""

from __future__ import annotations

import argparse
import base64
import logging
import re
import shlex
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("IdMMigration")

SKIP_STDERR = (
    "already exists",
    "already a member",
    "this entry already exists",
    "no modifications",
    "entry is already",
)


# ==============================================================================
# LDIF PARSER (stdlib — line folding + Base64)
# ==============================================================================


class LDIFParser:
    """LDIF parser with no external dependencies (RFC 2849 folding + attr::)."""

    @staticmethod
    def parse_file(filepath: str | Path) -> list[dict[str, list[str]]]:
        path = Path(filepath)
        if not path.is_file():
            logger.error("File %s does not exist.", filepath)
            return []

        entries: list[dict[str, list[str]]] = []
        current: dict[str, list[str]] = defaultdict(list)
        current_attr: str | None = None

        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                if raw.startswith((" ", "\t")) and current_attr is not None:
                    current[current_attr][-1] += raw[1:].rstrip("\r\n")
                    continue

                line = raw.rstrip("\r\n")
                if not line or line.startswith("#"):
                    if current:
                        entries.append(dict(current))
                        current = defaultdict(list)
                        current_attr = None
                    continue

                if line.startswith(("version:", "search:", "result:", "controls:")):
                    continue

                if ":" not in line:
                    continue

                attr, rest = line.split(":", 1)
                attr = attr.strip()
                if rest.startswith(":"):
                    # attr:: base64
                    payload = rest[1:].strip()
                    try:
                        val = base64.b64decode(payload).decode("utf-8", errors="replace")
                    except Exception:  # noqa: BLE001
                        val = payload
                elif rest.startswith("<"):
                    continue  # attr:< URL
                else:
                    val = rest.strip()

                current[attr].append(val)
                current_attr = attr

            if current:
                entries.append(dict(current))

        logger.info("Parsed %d entries from %s", len(entries), filepath)
        return entries


# ==============================================================================
# BUSINESS LOGIC
# ==============================================================================


def check_uid_duplicates(user_entries: list[dict[str, list[str]]]) -> dict[str, list[str]]:
    """Find users that share the same uidNumber."""
    logger.info("=== 1. uidNumber DUPLICATE AUDIT ===")
    uid_map: dict[str, list[str]] = defaultdict(list)

    for entry in user_entries:
        uids = entry.get("uid", [])
        numbers = entry.get("uidNumber", [])
        if uids and numbers:
            uid_map[numbers[0]].append(uids[0])

    duplicates = {n: us for n, us in uid_map.items() if len(set(us)) > 1}
    if not duplicates:
        logger.info("OK — no duplicate uidNumber values.")
        return uid_map

    logger.warning("Found %d conflicting uidNumber value(s):", len(duplicates))
    print("\n=== uidNumber CONFLICTS (resolve before migrate-ds) ===")
    for num, users in sorted(duplicates.items(), key=lambda x: int(x[0]) if x[0].isdigit() else x[0]):
        uniq = sorted(set(users))
        logger.warning("  uidNumber=%s → %s", num, ", ".join(uniq))
        print(f"  uidNumber={num}: {', '.join(uniq)}")
    print("==============================================================\n")
    return uid_map


def sanitize_host(host_str: str) -> str:
    return host_str.strip().lower()


def to_fqdn(host: str, domain: str) -> str:
    host = sanitize_host(host)
    if host in ("*", "all"):
        return "ALL"
    if "." in host or not domain:
        return host
    return f"{host}.{domain}"


def derive_hostgroup_name(hostname: str) -> str:
    """Map a hostname to a FreeIPA hostgroup using generic lab prefixes."""
    host = hostname.lower().split(".", 1)[0]
    if host.startswith("jump"):
        return "hg_jump"
    if host.startswith("app"):
        return "hg_app"
    if host.startswith("mw"):
        return "hg_middleware"
    if host.startswith("db"):
        return "hg_database"
    if host.startswith("web"):
        return "hg_web"
    if host.startswith("batch"):
        return "hg_batch"
    if host.startswith("ci"):
        return "hg_cicd"
    # Optional patterns for other real-world prefixes
    if any(x in host for x in ("schana", "plhana", "hana")):
        return "hg_erp_db"
    if "sap" in host:
        return "hg_erp_app"
    return "hg_general"


def sanitize_rule_name(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", name).strip("._-") or "unnamed"


def normalize_generalized_time(value: str) -> str:
    """Normalize to YYYYMMDDhhmmssZ for IdM setattr."""
    v = value.strip()
    if re.fullmatch(r"\d{14}Z", v):
        return v
    if re.fullmatch(r"\d{14}\.\d+Z", v):
        return v.split(".", 1)[0] + "Z"
    if re.fullmatch(r"\d{14}", v):
        return v + "Z"
    logger.warning("Unnormalized sudo timestamp %r (passed through)", value)
    return v


# ==============================================================================
# MODEL + BUNDLES (vertical slices) / optional horizontal phases
# ==============================================================================

# Horizontal phases remain available via --mode phase.
PHASE_ORDER = ("hostgroups", "hbac", "sudo", "hosts")

# Preview at most this many command lines on the terminal (full list always in file).
SCREEN_PREVIEW_LINES = 50

# Output naming: ipa_remap_access.d/ipa_remap_<key>.sh
OUTPUT_DIR_DEFAULT = Path("ipa_remap_access.d")
OUTPUT_PREFIX = "ipa_remap_"

# Rules with hostcat=all / hostAccess=* (sudoHost=ALL). Apply after hostgroup pilots.
ALL_HOSTS_BUNDLE = "all_hosts"


def output_script_name(key: str) -> str:
    """Stable filename from bundle/phase key → ipa_remap_<key>.sh"""
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", key).strip("._-") or "unnamed"
    return f"{OUTPUT_PREFIX}{safe}.sh"


def hostgroup_add_cmd(hg: str) -> list[str]:
    return ["ipa", "hostgroup-add", hg]


def hbac_cmds_for_group(group_name: str, hgroups: set[str]) -> list[list[str]]:
    rule = sanitize_rule_name(f"hbac_{group_name}")
    cmds: list[list[str]] = [
        ["ipa", "hbacrule-add", rule, "--servicecat=all"],
        ["ipa", "hbacrule-add-user", rule, f"--groups={group_name}"],
    ]
    if "ALL" in hgroups:
        cmds.append(["ipa", "hbacrule-mod", rule, "--hostcat=all"])
    else:
        for hg in sorted(h for h in hgroups if h != "ALL"):
            cmds.append(["ipa", "hbacrule-add-host", rule, f"--hostgroups={hg}"])
    cmds.append(["ipa", "hbacrule-enable", rule])
    return cmds


def hbac_cmds_for_user(username: str, hgroups: set[str]) -> list[list[str]]:
    rule = sanitize_rule_name(f"hbac_user_{username}")
    cmds: list[list[str]] = [
        ["ipa", "hbacrule-add", rule, "--servicecat=all"],
        ["ipa", "hbacrule-add-user", rule, f"--users={username}"],
    ]
    if "ALL" in hgroups:
        cmds.append(["ipa", "hbacrule-mod", rule, "--hostcat=all"])
    else:
        for hg in sorted(h for h in hgroups if h != "ALL"):
            cmds.append(["ipa", "hbacrule-add-host", rule, f"--hostgroups={hg}"])
    cmds.append(["ipa", "hbacrule-enable", rule])
    return cmds


def hosts_cmds_for_hg(
    hg: str, members: set[str], *, precreate_hosts: bool
) -> list[list[str]]:
    """hostgroup-add-member (after enroll). Optional lab-only host-add --force."""
    cmds: list[list[str]] = []
    for fqdn in sorted(members):
        if precreate_hosts:
            cmds.append(["ipa", "host-add", fqdn, "--force"])
        cmds.append(["ipa", "hostgroup-add-member", hg, f"--hosts={fqdn}"])
    return cmds


def iter_sudo_rules(
    sudo_entries: list[dict[str, list[str]]],
    domain: str,
    *,
    precreate_hosts: bool,
) -> list[dict]:
    """
    Parse sudoRole entries into plans:
      {name, hostgroups: set|None(None=hostcat all), cmds, hosts_cmds}
    """
    plans: list[dict] = []
    registered_cmds: set[str] = set()

    for rule in sudo_entries:
        cn_list = rule.get("cn") or []
        if not cn_list:
            continue
        rule_cn = cn_list[0]
        if rule_cn.lower() == "defaults":
            logger.info("Skipping cn=defaults")
            continue

        rule_name = sanitize_rule_name(rule_cn).lower()
        sudo_users = rule.get("sudoUser") or []
        sudo_hosts = rule.get("sudoHost") or ["ALL"]
        sudo_commands = rule.get("sudoCommand") or []
        sudo_options = rule.get("sudoOption") or []
        not_before = rule.get("sudoNotBefore") or []
        not_after = rule.get("sudoNotAfter") or []
        runas = rule.get("sudoRunAsUser") or []

        # Only keep description from source LDIF (no generated migration notes).
        add_cmd = ["ipa", "sudorule-add", rule_name]
        if rule.get("description"):
            add_cmd.append(f"--desc={rule['description'][0]}")
        cmds: list[list[str]] = [add_cmd]
        hosts_cmds: list[list[str]] = []
        hgs: set[str] = set()
        hostcat_all = any(h.upper() == "ALL" for h in sudo_hosts)

        for user in sudo_users:
            if user.upper() == "ALL":
                cmds.append(["ipa", "sudorule-mod", rule_name, "--usercat=all"])
            elif user.startswith("%"):
                cmds.append(
                    ["ipa", "sudorule-add-user", rule_name, f"--groups={user[1:]}"]
                )
            else:
                cmds.append(["ipa", "sudorule-add-user", rule_name, f"--users={user}"])

        if hostcat_all:
            cmds.append(["ipa", "sudorule-mod", rule_name, "--hostcat=all"])
        else:
            for host in sudo_hosts:
                fqdn = to_fqdn(host, domain)
                if fqdn == "ALL":
                    hostcat_all = True
                    hgs.clear()
                    cmds.append(["ipa", "sudorule-mod", rule_name, "--hostcat=all"])
                    break
                hg = derive_hostgroup_name(fqdn)
                hgs.add(hg)
                if precreate_hosts:
                    hosts_cmds.append(["ipa", "host-add", fqdn, "--force"])
                hosts_cmds.append(
                    ["ipa", "hostgroup-add-member", hg, f"--hosts={fqdn}"]
                )
            if not hostcat_all:
                for hg in sorted(hgs):
                    cmds.append(
                        ["ipa", "sudorule-add-host", rule_name, f"--hostgroups={hg}"]
                    )

        if any(c == "ALL" for c in sudo_commands):
            cmds.append(["ipa", "sudorule-mod", rule_name, "--cmdcat=all"])
        else:
            for cmd in sudo_commands:
                if cmd not in registered_cmds:
                    cmds.append(["ipa", "sudocmd-add", cmd])
                    registered_cmds.add(cmd)
                cmds.append(
                    [
                        "ipa",
                        "sudorule-add-allow-command",
                        rule_name,
                        f"--sudocmds={cmd}",
                    ]
                )

        for ru in runas:
            if ru.upper() == "ALL":
                cmds.append(["ipa", "sudorule-mod", rule_name, "--runasusercat=all"])
            else:
                cmds.append(
                    ["ipa", "sudorule-add-runasuser", rule_name, f"--users={ru}"]
                )

        for opt in sudo_options:
            cmds.append(
                ["ipa", "sudorule-add-option", rule_name, f"--sudooption={opt}"]
            )

        if not_before or not_after:
            mod = ["ipa", "sudorule-mod", rule_name]
            if not_before:
                mod.append(
                    f"--setattr=sudonotbefore={normalize_generalized_time(not_before[0])}"
                )
            if not_after:
                mod.append(
                    f"--setattr=sudonotafter={normalize_generalized_time(not_after[0])}"
                )
            cmds.append(mod)

        cmds.append(["ipa", "sudorule-enable", rule_name])
        plans.append(
            {
                "name": rule_name,
                "hostgroups": None if hostcat_all else set(hgs),
                "cmds": cmds,
                "hosts_cmds": hosts_cmds,
            }
        )
    return plans


def collect_host_access(
    group_entries: list[dict[str, list[str]]],
    user_entries: list[dict[str, list[str]]],
    domain: str,
) -> tuple[
    set[str],
    dict[str, set[str]],
    dict[str, set[str]],
    dict[str, set[str]],
]:
    """Return (all_hosts, host_to_group, group_to_hgs, user_to_hgs)."""
    all_hosts: set[str] = set()
    host_to_group: dict[str, set[str]] = defaultdict(set)
    group_to_hgs: dict[str, set[str]] = defaultdict(set)
    user_to_hgs: dict[str, set[str]] = defaultdict(set)

    def ingest(target_map: dict[str, set[str]], subject: str, hosts: list[str]) -> None:
        for host in hosts:
            cleaned = sanitize_host(host)
            if cleaned in ("*", "all"):
                target_map[subject].add("ALL")
                continue
            fqdn = to_fqdn(cleaned, domain)
            all_hosts.add(fqdn)
            hg = derive_hostgroup_name(fqdn)
            host_to_group[hg].add(fqdn)
            target_map[subject].add(hg)

    for group in group_entries:
        name = (group.get("cn") or [None])[0]
        ha = group.get("hostAccess") or []
        if name and ha:
            ingest(group_to_hgs, name, ha)

    for user in user_entries:
        name = (user.get("uid") or [None])[0]
        ha = user.get("hostAccess") or []
        if name and ha:
            ingest(user_to_hgs, name, ha)

    return all_hosts, host_to_group, group_to_hgs, user_to_hgs


def build_bundles(
    group_entries: list[dict[str, list[str]]],
    user_entries: list[dict[str, list[str]]],
    sudo_entries: list[dict[str, list[str]]],
    domain: str,
    *,
    precreate_hosts: bool,
) -> dict[str, dict]:
    """
    Vertical slices keyed by hostgroup (plus ALL_HOSTS_BUNDLE).

    Each bundle:
      setup      — hostgroup-add + HBAC + sudo for this slice
      hosts_cmds — hostgroup-add-member (after enroll; written to *_hosts.sh)
      meta       — counts for listing
    """
    all_hosts, host_to_group, group_to_hgs, user_to_hgs = collect_host_access(
        group_entries, user_entries, domain
    )
    sudo_plans = iter_sudo_rules(
        sudo_entries, domain, precreate_hosts=precreate_hosts
    )
    for plan in sudo_plans:
        if plan["hostgroups"]:
            for hg in plan["hostgroups"]:
                host_to_group.setdefault(hg, set())

    bundle_keys = sorted(host_to_group.keys())
    bundles: dict[str, dict] = {}

    def ensure(key: str) -> dict:
        if key not in bundles:
            bundles[key] = {
                "setup": [],
                "hosts_cmds": [],
                "hbac_groups": set(),
                "hbac_users": set(),
                "sudo_rules": set(),
                "hosts": set(),
            }
        return bundles[key]

    for hg in bundle_keys:
        b = ensure(hg)
        b["setup"].append(hostgroup_add_cmd(hg))
        b["hosts"] = set(host_to_group.get(hg, set()))
        b["hosts_cmds"].extend(
            hosts_cmds_for_hg(
                hg, host_to_group.get(hg, set()), precreate_hosts=precreate_hosts
            )
        )

    # HBAC: put full rule in each referenced hostgroup bundle (idempotent on re-run).
    # Also ensure sibling hostgroups referenced by the same rule are created in-bundle.
    for group_name, hgroups in sorted(group_to_hgs.items()):
        cmds = hbac_cmds_for_group(group_name, hgroups)
        if "ALL" in hgroups:
            b = ensure(ALL_HOSTS_BUNDLE)
            b["setup"].extend(cmds)
            b["hbac_groups"].add(group_name)
            continue
        targets = sorted(h for h in hgroups if h != "ALL")
        for hg in targets:
            b = ensure(hg)
            for other in targets:
                if other != hg:
                    b["setup"].append(hostgroup_add_cmd(other))
            b["setup"].extend(cmds)
            b["hbac_groups"].add(group_name)

    for username, hgroups in sorted(user_to_hgs.items()):
        cmds = hbac_cmds_for_user(username, hgroups)
        if "ALL" in hgroups:
            b = ensure(ALL_HOSTS_BUNDLE)
            b["setup"].extend(cmds)
            b["hbac_users"].add(username)
            continue
        targets = sorted(h for h in hgroups if h != "ALL")
        for hg in targets:
            b = ensure(hg)
            for other in targets:
                if other != hg:
                    b["setup"].append(hostgroup_add_cmd(other))
            b["setup"].extend(cmds)
            b["hbac_users"].add(username)

    # Sudo: multi-hg rules go into each hg (idempotent); hostcat=all → all_hosts
    for plan in sudo_plans:
        if plan["hostgroups"] is None:
            b = ensure(ALL_HOSTS_BUNDLE)
            b["setup"].extend(plan["cmds"])
            b["sudo_rules"].add(plan["name"])
            b["hosts_cmds"].extend(plan["hosts_cmds"])
        else:
            for hg in sorted(plan["hostgroups"]):
                b = ensure(hg)
                b["setup"].extend(plan["cmds"])
                b["sudo_rules"].add(plan["name"])
                for cmd in plan["hosts_cmds"]:
                    if len(cmd) >= 3 and cmd[1] == "hostgroup-add-member":
                        if cmd[2] == hg:
                            b["hosts_cmds"].append(cmd)
                    elif precreate_hosts and cmd[:2] == ["ipa", "host-add"]:
                        fqdn = cmd[2]
                        if derive_hostgroup_name(fqdn) == hg:
                            b["hosts_cmds"].append(cmd)

    logger.info(
        "Bundles: %d hostgroups, all_hosts=%s, hosts=%d",
        len([k for k in bundles if k != ALL_HOSTS_BUNDLE]),
        ALL_HOSTS_BUNDLE in bundles,
        len(all_hosts),
    )
    return bundles


def build_phases(
    group_entries: list[dict[str, list[str]]],
    user_entries: list[dict[str, list[str]]],
    sudo_entries: list[dict[str, list[str]]],
    domain: str,
    *,
    precreate_hosts: bool,
) -> dict[str, list[list[str]]]:
    """Horizontal phases (legacy / bulk). Prefer --mode bundle for pilots."""
    _all_hosts, host_to_group, group_to_hgs, user_to_hgs = collect_host_access(
        group_entries, user_entries, domain
    )
    sudo_plans = iter_sudo_rules(
        sudo_entries, domain, precreate_hosts=precreate_hosts
    )
    for plan in sudo_plans:
        if plan["hostgroups"]:
            for hg in plan["hostgroups"]:
                host_to_group.setdefault(hg, set())

    hostgroups = [hostgroup_add_cmd(hg) for hg in sorted(host_to_group)]
    hbac: list[list[str]] = []
    for g, hgs in sorted(group_to_hgs.items()):
        hbac.extend(hbac_cmds_for_group(g, hgs))
    for u, hgs in sorted(user_to_hgs.items()):
        hbac.extend(hbac_cmds_for_user(u, hgs))
    sudo: list[list[str]] = []
    hosts: list[list[str]] = []
    for plan in sudo_plans:
        sudo.extend(plan["cmds"])
        hosts.extend(plan["hosts_cmds"])
    for hg, members in sorted(host_to_group.items()):
        hosts.extend(hosts_cmds_for_hg(hg, members, precreate_hosts=precreate_hosts))

    return {
        "hostgroups": hostgroups,
        "hbac": hbac,
        "sudo": sudo,
        "hosts": _dedupe_cmds(hosts),
    }


def _dedupe_cmds(cmds: list[list[str]]) -> list[list[str]]:
    out: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()
    for c in cmds:
        key = tuple(c)
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def dedupe_bundle_setup(cmds: list[list[str]]) -> list[list[str]]:
    """Drop duplicate hbacrule/sudorule blocks when a subject maps to many hgs."""
    return _dedupe_cmds(cmds)


# ==============================================================================
# OUTPUT / EXECUTION
# ==============================================================================


def write_hosts_file(
    path: Path,
    hg: str,
    hosts: set[str],
    commands: list[list[str]],
) -> None:
    """
    List of FQDNs + hostgroup-add-member commands for after enroll.

    Runnable with: bash ipa_remap_<hg>_hosts.sh
    """
    cmds = _dedupe_cmds(commands)
    lines = [
        "#!/usr/bin/env bash",
        f"# Hostgroup {hg} — inventory + membership (after enroll)",
        "# Generated by ipa_remap_access.py — review before applying",
        "# Requires: kinit admin; hosts already enrolled (ipa-client-install)",
        "",
        f"# --- Host inventory ({len(hosts)} FQDN) ---",
    ]
    for fqdn in sorted(hosts):
        lines.append(f"#   {fqdn}")
    lines += [
        "# --- end inventory ---",
        "",
        "set -euo pipefail",
        "",
        "if ! klist -s 2>/dev/null; then",
        '  echo "ERROR: no Kerberos ticket — run: kinit admin" >&2',
        "  exit 1",
        "fi",
        "",
        f'echo "==> Adding hosts to hostgroup {hg} ({len(cmds)} command(s))"',
        "",
    ]
    for cmd in cmds:
        lines.append(" ".join(shlex.quote(c) for c in cmd) + " || true")
    lines += ["", 'echo "==> Done"', ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    path.chmod(path.stat().st_mode | 0o111)
    logger.info(
        "Wrote %s (%d hosts, %d commands)", path.resolve(), len(hosts), len(cmds)
    )


def write_bash(path: Path, commands: list[list[str]], *, title: str = "") -> None:
    label = title or "selected commands"
    lines = [
        "#!/usr/bin/env bash",
        f"# Red Hat IdM / FreeIPA post-migration — {label}",
        "# Generated by ipa_remap_access.py — review before applying",
        "# Requires: kinit admin",
        "# Users/groups: already via ipa migrate-ds",
        "# Hosts: enroll, then bash ipa_remap_<hg>_hosts.sh",
        "",
        "set -euo pipefail",
        "",
        "if ! klist -s 2>/dev/null; then",
        '  echo "ERROR: no Kerberos ticket — run: kinit admin" >&2',
        "  exit 1",
        "fi",
        "",
        f'echo "==> Applying IdM post-migration ({label})"',
        "",
    ]
    for cmd in commands:
        lines.append(" ".join(shlex.quote(c) for c in cmd) + " || true")
    lines += ["", 'echo "==> Done"', ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    path.chmod(path.stat().st_mode | 0o111)
    logger.info("Wrote %s (%d commands)", path.resolve(), len(commands))


def require_ipa_cli() -> int | None:
    """Return exit code if ipa is missing; None if OK."""
    if shutil.which("ipa"):
        return None
    logger.error(
        "Command 'ipa' not found in PATH.\n"
        "  --list-bundles / script generation only need LDIFs (any host).\n"
        "  --execute must run on an IdM server (or client with ipa CLI),\n"
        "  AFTER migrate-ds, with: kinit admin"
    )
    return 2


def run_commands(commands: list[list[str]], continue_on_error: bool = True) -> int:
    missing = require_ipa_cli()
    if missing is not None:
        return missing
    errors = 0
    for cmd in commands:
        pretty = " ".join(shlex.quote(c) for c in cmd)
        logger.info("Running: %s", pretty)
        try:
            res = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError:
            logger.error("Command not found: %s", cmd[0])
            return 2
        except subprocess.TimeoutExpired:
            logger.error("Timeout: %s", pretty)
            errors += 1
            if not continue_on_error:
                return 1
            continue

        if res.returncode == 0:
            continue

        err = (res.stderr or res.stdout or "").strip()
        if any(m in err.lower() for m in SKIP_STDERR):
            logger.warning(
                "SKIP: %s", err.splitlines()[-1] if err else "already present"
            )
            continue

        logger.error("Error: %s", err)
        errors += 1
        if not continue_on_error:
            return 1
    return 1 if errors else 0


def print_commands(
    jobs: list[tuple[str, list[list[str]]]],
    *,
    written: list[tuple[str, Path]],
    preview_lines: int = SCREEN_PREVIEW_LINES,
) -> None:
    """Show a short preview on screen; full commands live in written files."""
    total = sum(len(c) for _, c in jobs)
    print(f"# DRY-RUN preview: {len(jobs)} job(s), {total} command(s) — IdM is NOT contacted")
    print("# Full list is always in the file(s). Only --execute runs them on IdM.")
    if written:
        print("# Files:")
        for name, path in written:
            print(f"#   {name} → {path}")
    print()

    lines_used = 0
    cmds_shown = 0
    truncated = False
    for name, cmds in jobs:
        header = f"# --- {name} ({len(cmds)} commands) ---"
        if lines_used + 1 > preview_lines:
            truncated = True
            break
        print(header)
        lines_used += 1
        for cmd in cmds:
            if lines_used >= preview_lines:
                truncated = True
                break
            print(" ".join(shlex.quote(c) for c in cmd))
            lines_used += 1
            cmds_shown += 1
        if truncated:
            break
        print()
        lines_used += 1

    if truncated or cmds_shown < total:
        print(
            f"# … screen preview stopped at {preview_lines} lines "
            f"({total - cmds_shown} more command(s) in the file(s) above)."
        )
        print()


def print_bundle_summary(bundles: dict[str, dict]) -> None:
    print("Bundles (vertical slices — apply one, test, then next):\n")
    print(
        f"{'BUNDLE':<20} {'hosts':>5} {'hbac_g':>6} {'hbac_u':>6} {'sudo':>5}  cmds"
    )
    print("-" * 60)
    for key in sorted(bundles, key=lambda k: (k == ALL_HOSTS_BUNDLE, k)):
        b = bundles[key]
        setup_n = len(dedupe_bundle_setup(b["setup"]))
        print(
            f"{key:<20} {len(b['hosts']):>5} {len(b['hbac_groups']):>6} "
            f"{len(b['hbac_users']):>6} {len(b['sudo_rules']):>5}  {setup_n}"
        )
    print()
    print("Outputs:")
    print("  ipa_remap_<hg>.sh         hostgroup + HBAC + sudo for that slice")
    print("  ipa_remap_<hg>_hosts.sh  FQDN list + hostgroup-add-member (after enroll)")
    print(f"  ipa_remap_{ALL_HOSTS_BUNDLE}.sh  rules with hostAccess=* / sudoHost=ALL")
    print()
    print("Pilot tip: apply setup, enroll hosts from *_hosts.sh, then:")
    print("  bash ipa_remap_access.d/ipa_remap_<hg>_hosts.sh")
    print("Apply all_hosts last.")
    print()
    print("Example:")
    print("  python3 ipa_remap_access.py ... --bundle hg_web")
    print("  # → writes ipa_remap_access.d/ipa_remap_hg_web.sh + short screen preview")
    print("  # on IdM after migrate-ds:")
    print("  python3 ipa_remap_access.py ... --bundle hg_web --execute")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="OpenLDAP LDIF → IdM post-migrate (bundles or phases)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--users", type=Path, help="ldap-users.ldif")
    p.add_argument("--groups", type=Path, help="ldap-groups.ldif")
    p.add_argument("--sudo", type=Path, dest="sudo_ldif", help="sudo-rules.ldif")
    p.add_argument(
        "--domain",
        default="bcnconsulting.com",
        help="DNS domain for short hostnames (default: bcnconsulting.com)",
    )
    p.add_argument(
        "--mode",
        choices=("bundle", "phase"),
        default="bundle",
        help=(
            "bundle (default): vertical slice per hostgroup "
            "(hostgroup+HBAC+sudo together for a functional pilot). "
            "phase: horizontal bulk (all hostgroups, then all HBAC, …)."
        ),
    )
    p.add_argument(
        "--bundle",
        metavar="NAME",
        help=f"Only this hostgroup bundle (e.g. hg_web), or {ALL_HOSTS_BUNDLE}",
    )
    p.add_argument(
        "--list-bundles",
        action="store_true",
        help="List hostgroup bundles and sizes, then exit",
    )
    p.add_argument(
        "--phase",
        choices=(*PHASE_ORDER, "all"),
        default="all",
        help="With --mode phase: which horizontal phase (default: all)",
    )
    p.add_argument(
        "--list-phases",
        action="store_true",
        help="Print horizontal phase order and exit",
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        default=OUTPUT_DIR_DEFAULT,
        help=f"Directory for scripts (default: {OUTPUT_DIR_DEFAULT})",
    )
    p.add_argument(
        "-o",
        "--output-script",
        type=Path,
        default=None,
        help="Override path for a single output script (default: <output-dir>/ipa_remap_<key>.sh)",
    )
    p.add_argument(
        "--preview-lines",
        type=int,
        default=SCREEN_PREVIEW_LINES,
        help=f"Max command lines to print on screen (default: {SCREEN_PREVIEW_LINES}; full list always in file)",
    )
    p.add_argument(
        "--precreate-hosts",
        action="store_true",
        help="Opt-in ipa host-add --force (lab only)",
    )
    p.add_argument(
        "--execute",
        action="store_true",
        help=(
            "Run the ipa commands via local subprocess (IdM host only). "
            "Default is dry-run: write ipa_remap_<key>.sh + short screen preview."
        ),
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Do not print the screen preview (files are still written)",
    )
    p.add_argument(
        "--uid-report-only",
        action="store_true",
        help="Only audit duplicate uidNumber values and exit",
    )
    p.add_argument(
        "--fail-on-uid-conflict",
        action="store_true",
        help="Exit non-zero if duplicate uidNumber values exist",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.list_phases:
        print("Horizontal phases (--mode phase):\n")
        print("  1. hostgroups")
        print("  2. hbac")
        print("  3. sudo")
        print("  4. hosts  (hostgroup-add-member after enroll)")
        print("\nPrefer --mode bundle for functional pilots (see --list-bundles).")
        return 0

    if not args.users and not args.groups and not args.sudo_ldif:
        if args.list_bundles:
            logger.error("Provide --users/--groups/--sudo to list bundles")
            return 2
        logger.error("Provide at least --users / --groups / --sudo")
        return 2

    user_entries = LDIFParser.parse_file(args.users) if args.users else []
    group_entries = LDIFParser.parse_file(args.groups) if args.groups else []
    sudo_entries = LDIFParser.parse_file(args.sudo_ldif) if args.sudo_ldif else []

    uid_map = check_uid_duplicates(user_entries) if user_entries else {}
    conflicts = {n: u for n, u in uid_map.items() if len(set(u)) > 1}

    if args.uid_report_only:
        return 1 if conflicts and args.fail_on_uid_conflict else 0
    if conflicts and args.fail_on_uid_conflict:
        logger.error("Aborting due to uidNumber conflicts (--fail-on-uid-conflict)")
        return 1

    if args.mode == "bundle" or args.list_bundles:
        bundles = build_bundles(
            group_entries,
            user_entries,
            sudo_entries,
            args.domain,
            precreate_hosts=args.precreate_hosts,
        )
        if args.list_bundles:
            print_bundle_summary(bundles)
            return 0

        keys = [args.bundle] if args.bundle else sorted(
            bundles, key=lambda k: (k == ALL_HOSTS_BUNDLE, k)
        )
        if args.bundle and args.bundle not in bundles:
            logger.error(
                "Unknown bundle %r. Use --list-bundles. Known: %s",
                args.bundle,
                ", ".join(sorted(bundles)),
            )
            return 2

        jobs: list[tuple[str, list[list[str]]]] = []
        for key in keys:
            b = bundles[key]
            setup = dedupe_bundle_setup(b["setup"])
            if setup:
                jobs.append((key, setup))

        # Always: inventory + hostgroup-add-member in *_hosts.sh (run after enroll)
        out = args.output_dir
        out.mkdir(parents=True, exist_ok=True)
        host_lists: list[tuple[str, Path]] = []
        for key in keys:
            b = bundles[key]
            host_set = b.get("hosts") or set()
            cmds = _dedupe_cmds(b.get("hosts_cmds") or [])
            if not host_set and not cmds:
                continue
            inv = out / f"{OUTPUT_PREFIX}{key}_hosts.sh"
            write_hosts_file(inv, key, host_set, cmds)
            host_lists.append((f"{key}_hosts.sh", inv.resolve()))

        if not jobs:
            if host_lists:
                logger.info(
                    "No setup commands; wrote %d host file(s) under %s",
                    len(host_lists),
                    out.resolve(),
                )
                return 0
            logger.warning("No commands for selected bundle(s).")
            return 0

        # Setup scripts only (membership stays in *_hosts.sh until after enroll)
        written: list[tuple[str, Path]] = []
        if args.output_script is not None and len(jobs) == 1:
            name, cmds = jobs[0]
            write_bash(args.output_script, cmds, title=f"bundle={name}")
            written.append((name, args.output_script.resolve()))
        else:
            if args.output_script is not None and len(jobs) > 1:
                logger.warning(
                    "-o/--output-script ignored for multiple jobs; "
                    "writing ipa_remap_<key>.sh under %s",
                    out,
                )
            for name, cmds in jobs:
                path = out / output_script_name(name)
                write_bash(path, cmds, title=f"bundle={name}")
                written.append((name, path.resolve()))

        written.extend(host_lists)

        readme = out / "README.txt"
        readme.write_text(
            "\n".join(
                [
                    "IdM access remap outputs",
                    "",
                    "  ipa_remap_<hg>.sh",
                    "      Create hostgroup + HBAC + sudo for that hostgroup slice.",
                    "",
                    "  ipa_remap_<hg>_hosts.sh",
                    "      FQDN inventory (comments) + hostgroup-add-member commands.",
                    "      Enroll hosts first, then: bash ipa_remap_<hg>_hosts.sh",
                    "",
                    f"  ipa_remap_{ALL_HOSTS_BUNDLE}.sh",
                    "      Rules that apply to every host (hostAccess=* / sudoHost=ALL).",
                    "      Apply last, after hostgroup pilots.",
                    "",
                    "Screen shows a short preview; the .sh files have the full list.",
                    "Apply on IdM AFTER migrate-ds:",
                    "  bash ipa_remap_access.d/ipa_remap_hg_web.sh",
                    "  # enroll hosts…",
                    "  bash ipa_remap_access.d/ipa_remap_hg_web_hosts.sh",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        if not args.quiet:
            print_commands(
                jobs,
                written=written,
                preview_lines=max(1, args.preview_lines),
            )

        if args.execute:
            rc = 0
            for name, cmds in jobs:
                logger.info("=== EXECUTE bundle=%s (%d commands) ===", name, len(cmds))
                if run_commands(cmds) != 0:
                    rc = 1
            return rc

        logger.info("Wrote %d script(s) under %s", len(written), out.resolve())
        return 0

    # --mode phase
    phases = build_phases(
        group_entries,
        user_entries,
        sudo_entries,
        args.domain,
        precreate_hosts=args.precreate_hosts,
    )
    selected = list(PHASE_ORDER) if args.phase == "all" else [args.phase]
    selected_cmds = [(n, phases[n]) for n in selected if phases.get(n)]
    if not any(cmds for _, cmds in selected_cmds):
        logger.warning("No IPA commands for selected phase(s).")
        return 0

    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    written: list[tuple[str, Path]] = []
    for name, cmds in selected_cmds:
        # phase keys → ipa_remap_phase_<name>.sh
        key = f"phase_{name}"
        path = (
            args.output_script
            if args.output_script is not None and len(selected_cmds) == 1
            else out / output_script_name(key)
        )
        write_bash(path, cmds, title=f"phase={name}")
        written.append((key, path.resolve()))

    if not args.quiet:
        print_commands(
            selected_cmds,
            written=written,
            preview_lines=max(1, args.preview_lines),
        )

    if args.execute:
        rc = 0
        for name, cmds in selected_cmds:
            logger.info("=== EXECUTE phase=%s (%d commands) ===", name, len(cmds))
            if run_commands(cmds) != 0:
                rc = 1
        return rc

    logger.info("Wrote %d script(s) under %s", len(written), out.resolve())
    return 0


if __name__ == "__main__":
    sys.exit(main())
