#!/usr/bin/env python3
# Copyright (C) 2026 BCN Consulting Lab
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Fill ad_user_principal in user-overrides.csv from an AD export.

POSIX columns still come from OpenLDAP bootstrap; this script resolves the
trust anchor from AD **offline** (ldapsearch LDIF or PowerShell CSV).

  python3 ipa_match_ad_users.py \\
    --csv trust_catalog.d/user-overrides.csv \\
    --ad-export ad-users.csv \\
    --ad-realm WIN.IAM.LAB \\
    --output trust_catalog.d/user-overrides.csv

``--ad-export`` accepts ldapsearch **LDIF** or PowerShell **CSV** (auto-detect).
"""

from __future__ import annotations

import argparse
import csv
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from ipa_lib import (
        _entry_attr,
        ad_principal_from_entry,
        load_ad_users_from_export,
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
logger = logging.getLogger("MatchADUsers")


def load_csv_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        fieldnames = list(reader.fieldnames or [])
        return fieldnames, list(reader)


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def resolve_ad_export_path(
    ad_export: Path | None,
    ad_ldif: Path | None,
    ad_csv: Path | None,
) -> Path | None:
    paths = [p for p in (ad_export, ad_ldif, ad_csv) if p is not None]
    if len(paths) > 1:
        logger.error("Use only one of --ad-export, --ad-ldif, --ad-csv")
        return None
    return paths[0] if paths else None


def build_ad_indexes(
    ad_users: list[dict[str, list[str]]],
    realm: str,
) -> tuple[dict[str, str], dict[str, str]]:
    """Maps sAMAccountName (lower) and uidNumber → ad_user_principal."""
    by_sam: dict[str, str] = {}
    by_uidn: dict[str, str] = {}
    for entry in ad_users:
        principal = ad_principal_from_entry(entry, realm)
        if not principal:
            continue
        sam = _entry_attr(entry, "sAMAccountName").lower()
        uidn = _entry_attr(entry, "uidNumber")
        if sam:
            by_sam[sam] = principal
        if uidn:
            by_uidn[uidn] = principal
    return by_sam, by_uidn


def match_rows(
    rows: list[dict[str, str]],
    *,
    by_sam: dict[str, str],
    by_uidn: dict[str, str],
    match_by: str,
    overwrite: bool,
) -> tuple[int, int, int]:
    """Returns (filled, skipped_existing, unmatched)."""
    filled = 0
    skipped_existing = 0
    unmatched = 0
    for row in rows:
        if (row.get("ad_user_principal") or "").strip() and not overwrite:
            skipped_existing += 1
            continue
        uid = (row.get("openldap_uid") or "").strip()
        uidn = (row.get("uid_number") or "").strip()
        principal: str | None = None
        if match_by in ("samaccountname", "both") and uid:
            principal = by_sam.get(uid.lower())
        if not principal and match_by in ("uidnumber", "both") and uidn:
            principal = by_uidn.get(uidn)
        if principal:
            row["ad_user_principal"] = principal
            filled += 1
        else:
            unmatched += 1
            logger.warning(
                "No AD match for openldap_uid=%r uid_number=%r",
                uid,
                uidn,
            )
    return filled, skipped_existing, unmatched


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Fill ad_user_principal from AD LDIF or CSV export",
    )
    p.add_argument("--csv", type=Path, required=True, help="user-overrides.csv")
    p.add_argument(
        "--ad-export",
        type=Path,
        help="AD users: ldapsearch LDIF or PowerShell CSV (format auto-detected)",
    )
    p.add_argument("--ad-ldif", type=Path, help="(alias for --ad-export)")
    p.add_argument("--ad-csv", type=Path, help="(alias for --ad-export)")
    p.add_argument(
        "--ad-realm",
        required=True,
        help="Kerberos realm when building principal from sAMAccountName",
    )
    p.add_argument(
        "--match-by",
        choices=("samaccountname", "uidnumber", "both"),
        default="both",
        help="Join key: openldap_uid↔sAMAccountName and/or uid_number↔uidNumber",
    )
    p.add_argument(
        "--output",
        type=Path,
        help="Write merged CSV (default: overwrite --csv)",
    )
    p.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace existing ad_user_principal values",
    )
    args = p.parse_args(argv)

    ad_path = resolve_ad_export_path(args.ad_export, args.ad_ldif, args.ad_csv)
    if ad_path is None:
        if args.ad_export or args.ad_ldif or args.ad_csv:
            return 2
        logger.error("Provide --ad-export (LDIF or CSV from AD)")
        return 2

    fieldnames, rows = load_csv_rows(args.csv)
    if "ad_user_principal" not in fieldnames:
        fieldnames.append("ad_user_principal")

    ad_users = load_ad_users_from_export(ad_path)
    if not ad_users:
        logger.error("No AD user entries found in %s", ad_path)
        return 2

    by_sam, by_uidn = build_ad_indexes(ad_users, args.ad_realm)
    logger.info(
        "AD index: %d by sAMAccountName, %d by uidNumber (%d user entries)",
        len(by_sam),
        len(by_uidn),
        len(ad_users),
    )

    filled, skipped, unmatched = match_rows(
        rows,
        by_sam=by_sam,
        by_uidn=by_uidn,
        match_by=args.match_by,
        overwrite=args.overwrite,
    )

    out = args.output or args.csv
    write_csv(out, fieldnames, rows)

    print(f"\nWrote {out}")
    print(f"  filled ad_user_principal: {filled}")
    print(f"  kept existing principal:  {skipped}")
    print(f"  unmatched rows:           {unmatched}")
    return 1 if unmatched else 0


if __name__ == "__main__":
    sys.exit(main())
