#!/usr/bin/env python3
# Copyright (C) 2026 BCN Consulting Lab
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared helpers for IdM migration / trust mapping scripts (stdlib only)."""

from __future__ import annotations

import base64
import csv
import json
import logging
import re
import shlex
import subprocess
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger("IdMMigration")

SKIP_STDERR = (
    "already exists",
    "already a member",
    "this entry already exists",
    "no modifications",
    "entry is already",
)

DEFAULT_TRUST_VIEW = "Default Trust View"
ALL_HOSTS_BUNDLE = "all_hosts"
SASL_PASSWORD_PREFIX = "{SASL}"


def principal_from_user_password(user_password: str | None) -> str | None:
    """
    Extract AD trust anchor from OpenLDAP userPassword when LSC stores it as
    ``{SASL}user@realm`` (often base64-encoded in LDIF as ``userPassword::``).

    Example decoded value: ``{SASL}ad_user1@win.iam.lab`` → ``ad_user1@win.iam.lab``
    """
    if not user_password:
        return None
    pw = user_password.strip()
    if pw.upper().startswith(SASL_PASSWORD_PREFIX):
        principal = pw[len(SASL_PASSWORD_PREFIX) :].strip()
        if "@" in principal and not principal.startswith("{"):
            return principal
        return None
    # Rare: cleartext UPN without {SASL} — only when not a hash scheme prefix
    if "@" in pw and not pw.startswith("{"):
        return pw
    return None


def principal_from_ldap_user(user: dict[str, list[str]]) -> str | None:
    """Prefer explicit principal attrs; fall back to {SASL} userPassword."""
    for attr in ("krbPrincipalName", "userPrincipalName"):
        for val in user.get(attr) or []:
            candidate = (val or "").strip()
            if candidate and "@" in candidate:
                return candidate
    for pw in user.get("userPassword") or []:
        principal = principal_from_user_password(pw)
        if principal:
            return principal
    return None


def _entry_attr(entry: dict[str, list[str]], *names: str) -> str:
    """Case-insensitive first attribute value from an LDAP entry."""
    lower_map = {k.lower(): v for k, v in entry.items()}
    for name in names:
        vals = lower_map.get(name.lower()) or []
        if vals and str(vals[0]).strip():
            return str(vals[0]).strip()
    return ""


def ad_principal_from_entry(entry: dict[str, list[str]], realm: str) -> str | None:
    """Trust anchor from an AD user (``userPrincipalName`` or ``sAMAccountName@realm``)."""
    upn = _entry_attr(entry, "userPrincipalName", "krbPrincipalName")
    if upn and "@" in upn:
        return upn
    sam = _entry_attr(entry, "sAMAccountName")
    if sam and realm:
        return f"{sam}@{realm}"
    return None


def idoverrideuser_option_args(
    row: dict[str, str],
    *,
    cli_style: str = "legacy",
) -> list[str]:
    """
    Extra ``ipa idoverrideuser-add`` flags for POSIX fields.

    **legacy** (default) — RHEL 8 / older ``ipa`` CLI:
      ``--login``, ``--uid`` (number), ``--gid``, ``--homedir``, ``--shell``, ``--gecos``

    **modern** — newer API-style names:
      ``--uid`` (login), ``--uidnumber``, ``--gidnumber``, ``--homedirectory``,
      ``--loginshell``, ``--gecos``

    Run ``ipa idoverrideuser-add --help`` on your IdM if unsure.
    """
    login = (row.get("login") or row.get("openldap_uid") or "").strip()
    uidn = (row.get("uid_number") or "").strip()
    gidn = (row.get("gid_number") or "").strip()
    home = (row.get("home_directory") or "").strip()
    shell = (row.get("login_shell") or "").strip()
    gecos = (row.get("gecos") or "").strip()
    args: list[str] = []
    if cli_style == "modern":
        if login:
            args.append(f"--uid={login}")
        if uidn:
            args.append(f"--uidnumber={uidn}")
        if gidn:
            args.append(f"--gidnumber={gidn}")
        if home:
            args.append(f"--homedirectory={home}")
        if shell:
            args.append(f"--loginshell={shell}")
    else:
        if login:
            args.append(f"--login={login}")
        if uidn:
            args.append(f"--uid={uidn}")
        if gidn:
            args.append(f"--gid={gidn}")
        if home:
            args.append(f"--homedir={home}")
        if shell:
            args.append(f"--shell={shell}")
    if gecos:
        args.append(f"--gecos={gecos}")
    return args


def is_ad_group_entry(entry: dict[str, list[str]]) -> bool:
    classes = {c.lower() for c in entry.get("objectClass", [])}
    return "group" in classes


def load_ad_groups_from_ldif(path: Path) -> list[dict[str, list[str]]]:
    entries = LDIFParser.parse_file(path)
    return [e for e in entries if is_ad_group_entry(e)]


def load_ad_groups_from_csv(path: Path) -> list[dict[str, list[str]]]:
    rows: list[dict[str, list[str]]] = []
    with path.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            entry: dict[str, list[str]] = {}
            for key, val in row.items():
                if val is not None and str(val).strip():
                    entry[key] = [str(val).strip()]
            if entry:
                rows.append(entry)
    return rows


def sniff_ad_export_format(path: Path) -> str:
    """Return ``csv`` or ``ldif`` from extension or first content lines."""
    suffix = path.suffix.lower()
    if suffix in (".csv", ".tsv"):
        return "csv"
    if suffix in (".ldif", ".ldap"):
        return "ldif"
    with path.open(encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            lower = line.lower()
            if lower.startswith(("dn:", "dn::", "version:", "search:", "result:")):
                return "ldif"
            if "," in line:
                return "csv"
            break
    logger.warning("Could not detect format for %s — trying LDIF parser", path)
    return "ldif"


def load_ad_groups_from_export(path: Path) -> list[dict[str, list[str]]]:
    """Load AD groups from ldapsearch LDIF or PowerShell CSV (auto-detect)."""
    fmt = sniff_ad_export_format(path)
    logger.info("Loading AD groups from %s (detected: %s)", path, fmt)
    if fmt == "csv":
        return load_ad_groups_from_csv(path)
    return load_ad_groups_from_ldif(path)


def is_ad_user_entry(entry: dict[str, list[str]]) -> bool:
    classes = {c.lower() for c in entry.get("objectClass", [])}
    return "user" in classes or "person" in classes


def load_ad_users_from_ldif(path: Path) -> list[dict[str, list[str]]]:
    entries = LDIFParser.parse_file(path)
    return [e for e in entries if is_ad_user_entry(e)]


def load_ad_users_from_csv(path: Path) -> list[dict[str, list[str]]]:
    return load_ad_groups_from_csv(path)


def load_ad_users_from_export(path: Path) -> list[dict[str, list[str]]]:
    """Load AD users from ldapsearch LDIF or PowerShell CSV (auto-detect)."""
    fmt = sniff_ad_export_format(path)
    logger.info("Loading AD users from %s (detected: %s)", path, fmt)
    if fmt == "csv":
        return load_ad_users_from_csv(path)
    return load_ad_users_from_ldif(path)


def build_ad_group_lookup(ad_groups: list[dict[str, list[str]]]) -> dict[str, str]:
    """
    Map normalized keys → canonical AD ``sAMAccountName``.

    Keys: lower(sAMAccountName), lower(cn) when distinct.
    """
    lookup: dict[str, str] = {}
    for entry in ad_groups:
        sam = _entry_attr(entry, "sAMAccountName")
        if not sam:
            continue
        lookup[sam.lower()] = sam
        cn = _entry_attr(entry, "cn")
        if cn and cn.lower() not in lookup:
            lookup[cn.lower()] = sam
    return lookup


def match_openldap_cn_to_ad_group(
    openldap_cn: str,
    lookup: dict[str, str],
    *,
    ad_prefix: str = "",
) -> str | None:
    """Resolve OpenLDAP ``cn`` to AD ``sAMAccountName`` if possible."""
    key = openldap_cn.strip().lower()
    if not key:
        return None
    if key in lookup:
        return lookup[key]
    prefix = ad_prefix.strip().lower()
    if prefix:
        prefixed = f"{prefix}{key}"
        if prefixed in lookup:
            return lookup[prefixed]
        for norm, sam in lookup.items():
            if norm.startswith(prefix) and norm[len(prefix) :] == key:
                return sam
    return None


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
                    payload = rest[1:].strip()
                    try:
                        val = base64.b64decode(payload).decode("utf-8", errors="replace")
                    except Exception:  # noqa: BLE001
                        val = payload
                elif rest.startswith("<"):
                    continue
                else:
                    val = rest.strip()

                current[attr].append(val)
                current_attr = attr

            if current:
                entries.append(dict(current))

        logger.info("Parsed %d entries from %s", len(entries), filepath)
        return entries


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
    if any(x in host for x in ("schana", "plhana", "hana")):
        return "hg_erp_db"
    if "sap" in host:
        return "hg_erp_app"
    return "hg_general"


def host_access_to_hostgroups(host_access: list[str], domain: str) -> set[str]:
    hgroups: set[str] = set()
    for host in host_access:
        cleaned = sanitize_host(host)
        if cleaned in ("*", "all"):
            hgroups.add("ALL")
            continue
        fqdn = to_fqdn(cleaned, domain)
        hgroups.add(derive_hostgroup_name(fqdn))
    return hgroups


def sanitize_rule_name(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", name).strip("._-") or "unnamed"


def sanitize_group_cn(name: str) -> str:
    return sanitize_rule_name(name)


def is_sudo_role(entry: dict[str, list[str]]) -> bool:
    classes = {c.lower() for c in entry.get("objectClass", [])}
    return "sudorole" in classes


def normalize_generalized_time(value: str) -> str:
    """Normalize to YYYYMMDDhhmmssZ for IdM ``sudorule-mod --setattr``."""
    v = value.strip()
    if re.fullmatch(r"\d{14}Z", v):
        return v
    if re.fullmatch(r"\d{14}\.\d+Z", v):
        return v.split(".", 1)[0] + "Z"
    if re.fullmatch(r"\d{14}", v):
        return v + "Z"
    logger.warning("Unnormalized sudo timestamp %r (passed through)", value)
    return v


def collect_sudo_catalog_rows(
    sudo_entries: list[dict[str, list[str]]],
    domain: str,
) -> list[dict]:
    """Parse ``sudoRole`` LDIF entries into policy-catalog ``sudo_rules`` rows."""
    rows: list[dict] = []
    for rule in sudo_entries:
        if not is_sudo_role(rule):
            continue
        cn_list = rule.get("cn") or []
        if not cn_list:
            continue
        rule_cn = cn_list[0]
        if rule_cn.lower() == "defaults":
            logger.info("Skipping sudoRole cn=defaults")
            continue

        sudo_users = rule.get("sudoUser") or []
        if not sudo_users:
            logger.warning("Skipping sudoRole cn=%r — no sudoUser", rule_cn)
            continue

        sudo_hosts = rule.get("sudoHost") or ["ALL"]
        sudo_commands = rule.get("sudoCommand") or []
        if not sudo_commands:
            # Common LSC export: host/runas ALL but sudoCommand omitted → full access
            sudo_commands = ["ALL"]

        host_tokens = ["*" if h.upper() == "ALL" else h for h in sudo_hosts]
        hgroups = sorted(host_access_to_hostgroups(host_tokens, domain))

        rows.append(
            {
                "openldap_cn": rule_cn,
                "sudo_users": sudo_users,
                "sudo_hosts": sudo_hosts,
                "sudo_commands": sudo_commands,
                "sudo_options": rule.get("sudoOption") or [],
                "sudo_runas": rule.get("sudoRunAsUser")
                or rule.get("sudoRunAs")
                or [],
                "sudo_not_before": rule.get("sudoNotBefore") or [],
                "sudo_not_after": rule.get("sudoNotAfter") or [],
                "sudo_order": rule.get("sudoOrder") or [],
                "description": (rule.get("description") or [""])[0],
                "hostgroups": hgroups,
            }
        )
    return sorted(rows, key=lambda r: r["openldap_cn"])


def sudo_subject_group_cn(sudo_user: str) -> str | None:
    """Return OpenLDAP group ``cn`` from ``sudoUser: %group``."""
    if sudo_user.startswith("%"):
        name = sudo_user[1:].strip()
        return name or None
    return None


def sudo_referenced_group_cns(sudo_rows: list[dict]) -> set[str]:
    names: set[str] = set()
    for row in sudo_rows:
        for su in row.get("sudo_users") or []:
            g = sudo_subject_group_cn(su)
            if g:
                names.add(g)
    return names


def lookup_posix_wrapper_cn(group_cn: str, crosswalk: dict[str, dict[str, str]]) -> str:
    row = crosswalk.get(group_cn) or {}
    return (row.get("idm_posix_wrapper_cn") or group_cn).strip()


def trust_sudorule_name(row: dict) -> str:
    groups = [
        g
        for g in (
            sudo_subject_group_cn(u) for u in (row.get("sudo_users") or [])
        )
        if g
    ]
    if len(groups) == 1:
        return sanitize_rule_name(f"sudo_{groups[0]}")
    cn = (row.get("openldap_cn") or "rule").lstrip("%")
    return sanitize_rule_name(f"sudo_{cn}")


def sudorule_cmds_for_catalog_row(
    row: dict,
    crosswalk: dict[str, dict[str, str]],
    domain: str,
) -> tuple[list[list[str]], set[str], list[list[str]]]:
    """
    Build ``ipa sudorule-*`` commands for AD Trust (``%group`` → POSIX wrapper).

    Returns ``(cmds, bundle_keys, hosts_cmds)``.
    """
    rule_name = trust_sudorule_name(row)
    add_cmd = ["ipa", "sudorule-add", rule_name]
    desc = (row.get("description") or "").strip()
    if desc:
        add_cmd.append(f"--desc={desc}")
    cmds: list[list[str]] = [add_cmd]
    hosts_cmds: list[list[str]] = []
    registered_cmds: set[str] = set()
    bundle_keys: set[str] = set()

    for user in row.get("sudo_users") or []:
        if user.upper() == "ALL":
            cmds.append(["ipa", "sudorule-mod", rule_name, "--usercat=all"])
        elif user.startswith("%"):
            posix = lookup_posix_wrapper_cn(user[1:].strip(), crosswalk)
            cmds.append(["ipa", "sudorule-add-user", rule_name, f"--groups={posix}"])
        else:
            logger.warning(
                "sudoRole %r: sudoUser %r is not %%group — skipped on trust path",
                row.get("openldap_cn"),
                user,
            )

    sudo_hosts = row.get("sudo_hosts") or ["ALL"]
    hostcat_all = any(h.upper() == "ALL" for h in sudo_hosts)
    if hostcat_all:
        cmds.append(["ipa", "sudorule-mod", rule_name, "--hostcat=all"])
        bundle_keys.add(ALL_HOSTS_BUNDLE)
    else:
        hgs: set[str] = set()
        for host in sudo_hosts:
            fqdn = to_fqdn(host, domain)
            if fqdn == "ALL":
                hostcat_all = True
                hgs.clear()
                cmds.append(["ipa", "sudorule-mod", rule_name, "--hostcat=all"])
                bundle_keys.add(ALL_HOSTS_BUNDLE)
                break
            hg = derive_hostgroup_name(fqdn)
            hgs.add(hg)
            bundle_keys.add(hg)
            hosts_cmds.extend(hosts_cmds_for_hg(hg, {fqdn}))
        if not hostcat_all:
            for hg in sorted(hgs):
                cmds.append(
                    ["ipa", "sudorule-add-host", rule_name, f"--hostgroups={hg}"]
                )

    sudo_commands = row.get("sudo_commands") or ["ALL"]
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

    for ru in row.get("sudo_runas") or []:
        if ru.upper() == "ALL":
            cmds.append(["ipa", "sudorule-mod", rule_name, "--runasusercat=all"])
        else:
            cmds.append(
                ["ipa", "sudorule-add-runasuser", rule_name, f"--users={ru}"]
            )

    for opt in row.get("sudo_options") or []:
        cmds.append(["ipa", "sudorule-add-option", rule_name, f"--sudooption={opt}"])

    sudo_order = row.get("sudo_order") or []
    if sudo_order:
        order_val = str(sudo_order[0]).strip()
        if order_val.isdigit():
            cmds.append(["ipa", "sudorule-mod", rule_name, f"--order={order_val}"])

    not_before = row.get("sudo_not_before") or []
    not_after = row.get("sudo_not_after") or []
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
    if not bundle_keys:
        bundle_keys.add(ALL_HOSTS_BUNDLE)
    return cmds, bundle_keys, hosts_cmds


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")


def prepare_ipa_cmd(cmd: list[str]) -> list[str]:
    """
    Non-interactive ``ipa`` invocation.

    Uses ``-n`` / ``--no-prompt`` (not ``--noask``). Also close stdin when
    running via :func:`run_ipa_commands` or generated shell scripts.
    """
    if not cmd or cmd[0] != "ipa":
        return list(cmd)
    rest = cmd[1:]
    if rest and rest[0] in ("-n", "--no-prompt", "--noask"):
        return list(cmd)
    return ["ipa", "-n", *rest]


def write_shell_script(path: Path, cmds: list[list[str]], header: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "#!/bin/bash",
        f"# {header}",
        "# Generated by openldap-to-idm-mig-lab mapping scripts",
        "# ipa -n (--no-prompt) + stdin from /dev/null avoids member prompts",
        "set -euo pipefail",
        "",
    ]
    for cmd in cmds:
        ipa_cmd = prepare_ipa_cmd(cmd)
        quoted = " ".join(shlex.quote(c) for c in ipa_cmd)
        lines.append(f"{quoted} < /dev/null || true")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    path.chmod(0o755)


def dedupe_cmds(cmds: list[list[str]]) -> list[list[str]]:
    out: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()
    for cmd in cmds:
        key = tuple(cmd)
        if key in seen:
            continue
        seen.add(key)
        out.append(cmd)
    return out


def run_ipa_commands(cmds: list[list[str]], *, quiet: bool = False) -> int:
    failures = 0
    for cmd in cmds:
        ipa_cmd = prepare_ipa_cmd(cmd)
        if not quiet:
            logger.info("Running: %s", " ".join(shlex.quote(c) for c in ipa_cmd))
        proc = subprocess.run(
            ipa_cmd,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
        )
        combined = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode == 0 or any(s in combined.lower() for s in SKIP_STDERR):
            continue
        failures += 1
        logger.error("Command failed (%s): %s", proc.returncode, " ".join(cmd))
        if proc.stderr:
            logger.error(proc.stderr.strip())
    return failures


def hostgroup_add_cmd(hg: str) -> list[str]:
    return ["ipa", "hostgroup-add", hg]


def hosts_cmds_for_hg(
    hg: str, members: set[str], *, precreate_hosts: bool = False
) -> list[list[str]]:
    cmds: list[list[str]] = []
    for fqdn in sorted(members):
        if precreate_hosts:
            cmds.append(["ipa", "host-add", fqdn, "--force"])
        cmds.append(["ipa", "hostgroup-add-member", hg, f"--hosts={fqdn}"])
    return cmds
