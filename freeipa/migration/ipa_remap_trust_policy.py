#!/usr/bin/env python3
# Copyright (C) 2026 BCN Consulting Lab
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Plan / apply AD Trust policy: External Groups + POSIX wrappers + HBAC + sudo.

Reads policy-catalog.json + group-crosswalk.csv (from ipa_bootstrap_trust_catalog.py
or hand-edited). Does NOT create native IdM users.

  python3 ipa_remap_trust_policy.py --list-bundles \\
    --catalog trust_catalog.d/policy-catalog.json \\
    --crosswalk trust_catalog.d/group-crosswalk.csv

  kinit admin
  python3 ipa_remap_trust_policy.py ... --bundle hg_web --execute
"""

from __future__ import annotations

import argparse
import csv
import logging
import sys
from collections import defaultdict
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from ipa_lib import (
        ALL_HOSTS_BUNDLE,
        dedupe_cmds,
        derive_hostgroup_name,
        host_access_to_hostgroups,
        hostgroup_add_cmd,
        hosts_cmds_for_hg,
        load_json,
        lookup_posix_wrapper_cn,
        run_ipa_commands,
        sanitize_rule_name,
        sudorule_cmds_for_catalog_row,
        sudo_subject_group_cn,
        to_fqdn,
        write_shell_script,
    )
except ModuleNotFoundError:
    sys.exit(
        "ERROR: ipa_lib.py not found. Copy the whole freeipa/migration/ directory "
        "(see freeipa/migration/README.md)."
    )

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("TrustPolicy")

OUTPUT_DIR_DEFAULT = Path("ipa_trust_policy.d")
OUTPUT_PREFIX = "ipa_trust_"


def load_crosswalk(path: Path) -> dict[str, dict[str, str]]:
    """Map openldap_group_cn → crosswalk row."""
    by_cn: dict[str, dict[str, str]] = {}
    with path.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            cn = (row.get("openldap_group_cn") or "").strip()
            if cn:
                by_cn[cn] = row
    return by_cn


def external_member_spec(row: dict[str, str], ad_domain: str, ol_cn: str = "") -> str:
    """Build --external=DOMAIN\\group from crosswalk."""
    ad_group = (row.get("ad_group") or "").strip()
    if not ad_group:
        label = ol_cn or (row.get("openldap_group_cn") or "").strip() or "?"
        raise ValueError(f"crosswalk missing ad_group for openldap_group_cn={label!r}")
    if "\\" in ad_group:
        return ad_group
    domain = ad_domain.upper()
    return f"{domain}\\{ad_group}"


def external_group_cmds(external_cn: str, ad_member: str, desc: str) -> list[list[str]]:
    return [
        ["ipa", "group-add", external_cn, "--external", f"--desc={desc}"],
        ["ipa", "group-add-member", external_cn, f"--external={ad_member}"],
    ]


def posix_wrapper_cmds(
    posix_cn: str,
    external_cn: str,
    desc: str,
    *,
    gid_number: str = "",
) -> list[list[str]]:
    add_cmd = ["ipa", "group-add", posix_cn, f"--desc={desc}"]
    gid = (gid_number or "").strip()
    if gid:
        add_cmd.append(f"--gid={gid}")
    return [
        add_cmd,
        ["ipa", "group-add-member", posix_cn, f"--groups={external_cn}"],
    ]


def resolve_group_cns(
    row: dict[str, str],
    ol_cn: str,
) -> tuple[str, str]:
    """Return (external_cn, posix_cn); external and POSIX names must differ."""
    external_cn = (row.get("idm_external_cn") or ol_cn).strip()
    posix_cn = (row.get("idm_posix_wrapper_cn") or ol_cn).strip()
    if external_cn == posix_cn:
        external_cn = f"{posix_cn}_ext"
        logger.warning(
            "openldap_group_cn=%r: idm_external_cn equals idm_posix_wrapper_cn; "
            "using external group %r",
            ol_cn,
            external_cn,
        )
    return external_cn, posix_cn


def hbac_cmds_for_posix_wrapper(
    posix_cn: str,
    hgroups: set[str],
    services: list[str],
) -> list[list[str]]:
    rule = sanitize_rule_name(f"hbac_{posix_cn}")
    cmds: list[list[str]] = [
        ["ipa", "hbacrule-add", rule, "--servicecat=all"],
        ["ipa", "hbacrule-add-user", rule, f"--groups={posix_cn}"],
    ]
    if "ALL" in hgroups:
        cmds.append(["ipa", "hbacrule-mod", rule, "--hostcat=all"])
    else:
        for hg in sorted(h for h in hgroups if h != ALL_HOSTS_BUNDLE and h != "ALL"):
            cmds.append(["ipa", "hbacrule-add-host", rule, f"--hostgroups={hg}"])
    # servicecat=all and explicit --hbacsvcs= are mutually exclusive in ipa CLI.
    cmds.append(["ipa", "hbacrule-enable", rule])
    return cmds


def collect_hosts(host_access: list[str], domain: str) -> set[str]:
    hosts: set[str] = set()
    for host in host_access:
        cleaned = host.strip().lower()
        if cleaned in ("*", "all"):
            continue
        hosts.add(to_fqdn(cleaned, domain))
    return hosts


def group_policy_cmds(
    ol_cn: str,
    row: dict[str, str],
    *,
    ad_domain: str,
    host_access: list[str],
    domain: str,
    gid_number: str = "",
) -> tuple[list[list[str]], set[str], set[str], str] | None:
    """Return (cmds, hostgroups, host_fqdns, posix_cn) or None if skipped."""
    try:
        ad_member = external_member_spec(row, ad_domain, ol_cn)
    except ValueError as exc:
        logger.warning("%s", exc)
        return None

    external_cn, posix_cn = resolve_group_cns(row, ol_cn)
    hgroups = host_access_to_hostgroups(host_access, domain)
    host_fqdns = collect_hosts(host_access, domain)

    group_cmds = external_group_cmds(
        external_cn,
        ad_member,
        f"External mirror of AD group for {ol_cn}",
    )
    group_cmds.extend(
        posix_wrapper_cmds(
            posix_cn,
            external_cn,
            f"POSIX wrapper for HBAC/sudo — {ol_cn}",
            gid_number=gid_number,
        )
    )
    return group_cmds, hgroups, host_fqdns, posix_cn


def attach_group_bundle_slices(
    bundles: dict[str, dict],
    *,
    posix_cn: str,
    group_cmds: list[list[str]],
    hbac_cmds: list[list[str]],
    hgroups: set[str],
    host_fqdns: set[str],
    domain: str,
) -> None:
    bundle_keys = sorted(h for h in hgroups if h not in ("ALL", ALL_HOSTS_BUNDLE))
    if "ALL" in hgroups:
        bundle_keys = [ALL_HOSTS_BUNDLE]

    full_cmds = group_cmds + hbac_cmds
    for bk in bundle_keys or ["hg_general"]:
        b = bundles[bk]
        b["setup"].extend(full_cmds)
        b["groups"].add(posix_cn)
        if bk == ALL_HOSTS_BUNDLE:
            continue
        for fqdn in host_fqdns:
            if derive_hostgroup_name(fqdn) == bk:
                b["hosts"].add(fqdn)
        b["setup"].append(hostgroup_add_cmd(bk))
        b["hosts_cmds"].extend(hosts_cmds_for_hg(bk, b["hosts"]))


def build_bundles(
    catalog: dict,
    crosswalk: dict[str, dict[str, str]],
    *,
    ad_domain: str,
    domain: str,
) -> dict[str, dict]:
    bundles: dict[str, dict] = defaultdict(
        lambda: {
            "setup": [],
            "hosts_cmds": [],
            "hosts": set(),
            "groups": set(),
        }
    )
    processed_posix: set[str] = set()

    for group in catalog.get("groups") or []:
        ol_cn = group.get("openldap_cn") or ""
        if not ol_cn or ol_cn not in crosswalk:
            logger.warning("No crosswalk for openldap_cn=%r — skip", ol_cn)
            continue

        row = crosswalk[ol_cn]
        host_access = group.get("host_access") or []
        built = group_policy_cmds(
            ol_cn,
            row,
            ad_domain=ad_domain,
            host_access=host_access,
            domain=domain,
            gid_number=(row.get("gid_number") or group.get("gid_number") or ""),
        )
        if not built:
            continue
        group_cmds, hgroups, host_fqdns, posix_cn = built
        services = group.get("hbac_services") or ["sshd"]
        hbac_cmds = hbac_cmds_for_posix_wrapper(posix_cn, hgroups, services)
        attach_group_bundle_slices(
            bundles,
            posix_cn=posix_cn,
            group_cmds=group_cmds,
            hbac_cmds=hbac_cmds,
            hgroups=hgroups,
            host_fqdns=host_fqdns,
            domain=domain,
        )
        processed_posix.add(posix_cn)

    for sudo_row in catalog.get("sudo_rules") or []:
        sudo_cmds, bundle_keys, sudo_hosts_cmds = sudorule_cmds_for_catalog_row(
            sudo_row,
            crosswalk,
            domain,
        )
        if not sudo_cmds:
            continue

        group_cmds_to_prepend: list[list[str]] = []
        for su in sudo_row.get("sudo_users") or []:
            gcn = sudo_subject_group_cn(su)
            if not gcn:
                continue
            if gcn not in crosswalk:
                logger.warning(
                    "sudoRole %r: no crosswalk for group %r — skip group setup",
                    sudo_row.get("openldap_cn"),
                    gcn,
                )
                continue
            posix_cn = lookup_posix_wrapper_cn(gcn, crosswalk)
            if posix_cn in processed_posix:
                continue
            built = group_policy_cmds(
                gcn,
                crosswalk[gcn],
                ad_domain=ad_domain,
                host_access=[],
                domain=domain,
                gid_number=(crosswalk[gcn].get("gid_number") or ""),
            )
            if not built:
                continue
            g_cmds, _, _, wrapper_cn = built
            group_cmds_to_prepend.extend(g_cmds)
            processed_posix.add(wrapper_cn)

        ordered_keys = sorted(
            bundle_keys,
            key=lambda k: (k == ALL_HOSTS_BUNDLE, k),
        )
        first_key = ordered_keys[0]
        for bk in ordered_keys:
            b = bundles[bk]
            if bk == first_key and group_cmds_to_prepend:
                b["setup"].extend(group_cmds_to_prepend)
            b["setup"].extend(sudo_cmds)
            if bk == first_key:
                b["hosts_cmds"].extend(sudo_hosts_cmds)
            for su in sudo_row.get("sudo_users") or []:
                gcn = sudo_subject_group_cn(su)
                if gcn:
                    b["groups"].add(lookup_posix_wrapper_cn(gcn, crosswalk))

    return dict(bundles)


def print_bundle_summary(bundles: dict[str, dict]) -> None:
    print("\nBundles (apply one pilot slice at a time):\n")
    print(f"{'BUNDLE':<20} {'groups':>6} {'hosts':>5}  cmds")
    print("-" * 45)
    for key in sorted(bundles, key=lambda k: (k == ALL_HOSTS_BUNDLE, k)):
        b = bundles[key]
        setup_n = len(dedupe_cmds(b["setup"]))
        print(f"{key:<20} {len(b['groups']):>6} {len(b['hosts']):>5}  {setup_n}")
    print()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="AD Trust policy remapper")
    p.add_argument("--catalog", type=Path, required=True, help="policy-catalog.json")
    p.add_argument("--crosswalk", type=Path, required=True, help="group-crosswalk.csv")
    p.add_argument(
        "--ad-domain",
        required=True,
        help="AD NetBIOS/domain prefix for --external=DOMAIN\\\\group (e.g. WIN.IAM.LAB)",
    )
    p.add_argument(
        "--domain",
        default=None,
        help="DNS domain for short hostnames (default: catalog domain)",
    )
    p.add_argument("--list-bundles", action="store_true")
    p.add_argument("--bundle", help="Generate/run one bundle (e.g. hg_web, all_hosts)")
    p.add_argument("--output-dir", type=Path, default=OUTPUT_DIR_DEFAULT)
    p.add_argument("--execute", action="store_true")
    args = p.parse_args(argv)

    catalog = load_json(args.catalog)
    crosswalk = load_crosswalk(args.crosswalk)
    domain = args.domain or catalog.get("domain") or "bcnconsulting.com"

    bundles = build_bundles(
        catalog,
        crosswalk,
        ad_domain=args.ad_domain,
        domain=domain,
    )

    if args.list_bundles:
        print_bundle_summary(bundles)
        return 0

    if not bundles:
        logger.error("No bundles generated — check catalog and crosswalk ad_group column")
        return 2

    keys = [args.bundle] if args.bundle else sorted(
        bundles, key=lambda k: (k == ALL_HOSTS_BUNDLE, k)
    )
    if args.bundle and args.bundle not in bundles:
        logger.error("Unknown bundle %r. Known: %s", args.bundle, ", ".join(sorted(bundles)))
        return 2

    args.output_dir.mkdir(parents=True, exist_ok=True)
    all_failures = 0

    for key in keys:
        b = bundles[key]
        setup = dedupe_cmds(b["setup"])
        hosts_cmds = dedupe_cmds(b.get("hosts_cmds") or [])
        setup_path = args.output_dir / f"{OUTPUT_PREFIX}{key}.sh"
        hosts_path = args.output_dir / f"{OUTPUT_PREFIX}{key}_hosts.sh"
        write_shell_script(setup_path, setup, f"Trust policy bundle {key}")
        write_shell_script(hosts_path, hosts_cmds, f"Hostgroup members for {key}")
        print(f"Wrote {setup_path} ({len(setup)} cmd(s))")
        print(f"Wrote {hosts_path} ({len(hosts_cmds)} cmd(s))")
        if args.execute:
            all_failures += run_ipa_commands(setup)
            all_failures += run_ipa_commands(hosts_cmds)

    return 1 if all_failures else 0


if __name__ == "__main__":
    sys.exit(main())
