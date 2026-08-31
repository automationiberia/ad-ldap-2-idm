#!/usr/bin/env python3
# Copyright (C) 2026 BCN Consulting Lab
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Bootstrap AD Trust policy catalog + group crosswalk from OpenLDAP exports.

Reads the **last OpenLDAP LDIF** (groups with hostAccess, optional sudo) and
writes JSON/CSV inputs for ipa_remap_trust_policy.py. Does not talk to IdM.

  python3 ipa_bootstrap_trust_catalog.py \\
    --groups ldap-groups.ldif \\
    --users ldap-users.ldif \\
    --sudo ldap-sudo.ldif \\
    --output-dir trust_catalog.d
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from ipa_lib import (
        LDIFParser,
        build_ad_group_lookup,
        collect_sudo_catalog_rows,
        host_access_to_hostgroups,
        load_ad_groups_from_ldif,
        match_openldap_cn_to_ad_group,
        principal_from_ldap_user,
        sudo_referenced_group_cns,
        write_json,
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
logger = logging.getLogger("TrustCatalog")

CROSSWALK_FIELDS = [
    "openldap_group_cn",
    "ad_group",
    "idm_external_cn",
    "idm_posix_wrapper_cn",
    "gid_number",
]

USER_CROSSWALK_FIELDS = [
    "openldap_uid",
    "ad_user_principal",
    "login",
    "uid_number",
    "gid_number",
    "home_directory",
    "login_shell",
    "gecos",
]


def collect_group_policy(
    group_entries: list[dict[str, list[str]]],
    domain: str,
) -> list[dict]:
    rows: list[dict] = []
    for group in group_entries:
        cn = (group.get("cn") or [None])[0]
        if not cn:
            continue
        host_access = group.get("hostAccess") or []
        if not host_access:
            continue
        gidn = (group.get("gidNumber") or [""])[0]
        hgroups = sorted(host_access_to_hostgroups(host_access, domain))
        rows.append(
            {
                "openldap_cn": cn,
                "gid_number": gidn,
                "host_access": host_access,
                "hostgroups": hgroups,
                "hbac_services": ["sshd"],
            }
        )
    return sorted(rows, key=lambda r: r["openldap_cn"])


def collect_user_host_access(
    user_entries: list[dict[str, list[str]]],
    domain: str,
) -> list[dict]:
    """Per-user hostAccess — record as catalog exceptions (prefer AD groups later)."""
    rows: list[dict] = []
    for user in user_entries:
        uid = (user.get("uid") or [None])[0]
        ha = user.get("hostAccess") or []
        if not uid or not ha:
            continue
        rows.append(
            {
                "openldap_uid": uid,
                "host_access": ha,
                "hostgroups": sorted(host_access_to_hostgroups(ha, domain)),
                "note": "Review: map to AD group or explicit HBAC exception",
            }
        )
    return sorted(rows, key=lambda r: r["openldap_uid"])


def collect_user_overrides(user_entries: list[dict[str, list[str]]]) -> list[dict]:
    rows: list[dict] = []
    for user in user_entries:
        uid = (user.get("uid") or [None])[0]
        if not uid:
            continue
        uidn = (user.get("uidNumber") or [""])[0]
        gidn = (user.get("gidNumber") or [""])[0]
        home = (user.get("homeDirectory") or [f"/home/{uid}"])[0]
        shell = (user.get("loginShell") or ["/bin/bash"])[0]
        gecos = (user.get("gecos") or [""])[0]
        ad_principal = principal_from_ldap_user(user) or ""
        rows.append(
            {
                "openldap_uid": uid,
                "ad_user_principal": ad_principal,
                "login": uid,
                "uid_number": uidn,
                "gid_number": gidn,
                "home_directory": home,
                "login_shell": shell,
                "gecos": gecos,
            }
        )
    return sorted(rows, key=lambda r: r["openldap_uid"])


def write_csv(path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Bootstrap trust policy catalog from OpenLDAP LDIF")
    p.add_argument("--groups", type=Path, required=True, help="ldap-groups.ldif")
    p.add_argument("--users", type=Path, help="ldap-users.ldif (overrides + user hostAccess)")
    p.add_argument("--sudo", type=Path, help="sudo-rules.ldif (ou=SUDOers sudoRole)")
    p.add_argument(
        "--ad-groups-ldif",
        type=Path,
        help="AD groups ldapsearch export — auto-fill ad_group when names match",
    )
    p.add_argument(
        "--ad-group-prefix",
        default="",
        help="With --ad-groups-ldif: strip/match AD sAMAccountName prefix (e.g. Linux-)",
    )
    p.add_argument("--domain", default="bcnconsulting.com", help="DNS domain for short hostnames")
    p.add_argument(
        "--output-dir",
        type=Path,
        default=Path("trust_catalog.d"),
        help="Output directory (default: trust_catalog.d)",
    )
    args = p.parse_args(argv)

    groups = LDIFParser.parse_file(args.groups)
    users = LDIFParser.parse_file(args.users) if args.users else []
    sudo_entries = LDIFParser.parse_file(args.sudo) if args.sudo else []

    group_rows = collect_group_policy(groups, args.domain)
    sudo_rows = collect_sudo_catalog_rows(sudo_entries, args.domain) if sudo_entries else []
    user_ha_rows = collect_user_host_access(users, args.domain) if users else []
    override_rows = collect_user_overrides(users) if users else []

    out = args.output_dir
    catalog = {
        "domain": args.domain,
        "description": "Policy catalog — edit ad_group in crosswalk CSV; hostgroups derived from hostAccess",
        "groups": group_rows,
        "sudo_rules": sudo_rows,
        "user_host_access_exceptions": user_ha_rows,
    }
    write_json(out / "policy-catalog.json", catalog)

    crosswalk_rows = [
        {
            "openldap_group_cn": r["openldap_cn"],
            "ad_group": "",
            # External and POSIX wrapper must differ (same cn → group-add collision).
            "idm_external_cn": f"{r['openldap_cn']}_ext",
            "idm_posix_wrapper_cn": r["openldap_cn"],
            "gid_number": r.get("gid_number") or "",
        }
        for r in group_rows
    ]
    existing_cns = {r["openldap_group_cn"] for r in crosswalk_rows}
    for gcn in sorted(sudo_referenced_group_cns(sudo_rows)):
        if gcn in existing_cns:
            continue
        crosswalk_rows.append(
            {
                "openldap_group_cn": gcn,
                "ad_group": "",
                "idm_external_cn": f"{gcn}_ext",
                "idm_posix_wrapper_cn": gcn,
                "gid_number": "",
            }
        )
    crosswalk_rows.sort(key=lambda r: r["openldap_group_cn"])
    ad_group_lookup: dict[str, str] = {}
    if args.ad_groups_ldif:
        ad_entries = load_ad_groups_from_ldif(args.ad_groups_ldif)
        ad_group_lookup = build_ad_group_lookup(ad_entries)
        matched = 0
        for row in crosswalk_rows:
            ad_group = match_openldap_cn_to_ad_group(
                row["openldap_group_cn"],
                ad_group_lookup,
                ad_prefix=args.ad_group_prefix,
            )
            if ad_group:
                row["ad_group"] = ad_group
                matched += 1
        logger.info(
            "Matched %d/%d ad_group from %s",
            matched,
            len(crosswalk_rows),
            args.ad_groups_ldif,
        )
    write_csv(out / "group-crosswalk.csv", CROSSWALK_FIELDS, crosswalk_rows)
    if override_rows:
        write_csv(out / "user-overrides.csv", USER_CROSSWALK_FIELDS, override_rows)

    print(f"\nWrote {out}/policy-catalog.json ({len(group_rows)} group policy rows)")
    if sudo_rows:
        print(f"  sudo_rules: {len(sudo_rows)} (from --sudo LDIF)")
    if ad_group_lookup:
        matched_n = sum(1 for r in crosswalk_rows if r.get("ad_group"))
        missing_n = len(crosswalk_rows) - matched_n
        print(
            f"Wrote {out}/group-crosswalk.csv — {matched_n} ad_group from AD LDIF"
            + (f" ({missing_n} unmatched — ipa_match_ad_groups.py or manual)" if missing_n else "")
        )
    else:
        print(
            f"Wrote {out}/group-crosswalk.csv — run ipa_match_ad_groups.py "
            "or fill ad_group from AD export"
        )
    if override_rows:
        principal_n = sum(1 for r in override_rows if r.get("ad_user_principal"))
        missing_n = len(override_rows) - principal_n
        print(
            f"Wrote {out}/user-overrides.csv ({len(override_rows)} rows) — "
            f"{principal_n} ad_user_principal from LDAP "
            f"({{SASL}} userPassword / krbPrincipalName / userPrincipalName)"
        )
        if missing_n:
            print(f"  {missing_n} row(s) still need ad_user_principal (AD export or manual)")

    if user_ha_rows:
        print(
            f"\nWARNING: {len(user_ha_rows)} user-level hostAccess entries — "
            "review user_host_access_exceptions in policy-catalog.json"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
