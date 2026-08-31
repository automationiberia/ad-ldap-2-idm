#!/usr/bin/env python3
# Copyright (C) 2026 BCN Consulting Lab
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Fill ad_group in group-crosswalk.csv from an AD export.

  python3 ipa_match_ad_groups.py \\
    --crosswalk trust_catalog.d/group-crosswalk.csv \\
    --ad-export ad-groups.csv \\
    --ad-prefix Linux- \\
    --output trust_catalog.d/group-crosswalk.csv

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
        build_ad_group_lookup,
        load_ad_groups_from_export,
        match_openldap_cn_to_ad_group,
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
logger = logging.getLogger("MatchADGroups")

CROSSWALK_FIELDS = [
    "openldap_group_cn",
    "ad_group",
    "idm_external_cn",
    "idm_posix_wrapper_cn",
    "gid_number",
]


def load_crosswalk(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        fieldnames = list(reader.fieldnames or CROSSWALK_FIELDS)
        return fieldnames, list(reader)


def write_crosswalk(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
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


def fill_ad_groups(
    rows: list[dict[str, str]],
    lookup: dict[str, str],
    *,
    ad_prefix: str,
    overwrite: bool,
) -> tuple[int, int, int]:
    filled = 0
    kept = 0
    unmatched = 0
    for row in rows:
        if (row.get("ad_group") or "").strip() and not overwrite:
            kept += 1
            continue
        ol_cn = (row.get("openldap_group_cn") or "").strip()
        if not ol_cn:
            unmatched += 1
            continue
        ad_group = match_openldap_cn_to_ad_group(ol_cn, lookup, ad_prefix=ad_prefix)
        if ad_group:
            row["ad_group"] = ad_group
            filled += 1
        else:
            unmatched += 1
            logger.warning("No AD group match for openldap_group_cn=%r", ol_cn)
    return filled, kept, unmatched


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Fill ad_group in group-crosswalk.csv from AD export")
    p.add_argument("--crosswalk", type=Path, required=True, help="group-crosswalk.csv")
    p.add_argument(
        "--ad-export",
        type=Path,
        help="AD groups: ldapsearch LDIF or PowerShell CSV (format auto-detected)",
    )
    p.add_argument(
        "--ad-ldif",
        type=Path,
        help="(alias for --ad-export)",
    )
    p.add_argument(
        "--ad-csv",
        type=Path,
        help="(alias for --ad-export)",
    )
    p.add_argument(
        "--ad-prefix",
        default="",
        help="Optional AD name prefix to strip when matching (e.g. Linux-)",
    )
    p.add_argument(
        "--output",
        type=Path,
        help="Write merged CSV (default: overwrite --crosswalk)",
    )
    p.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace existing ad_group values",
    )
    args = p.parse_args(argv)

    ad_path = resolve_ad_export_path(args.ad_export, args.ad_ldif, args.ad_csv)
    if ad_path is None:
        if args.ad_export or args.ad_ldif or args.ad_csv:
            return 2
        logger.error("Provide --ad-export (LDIF or CSV from AD)")
        return 2

    fieldnames, rows = load_crosswalk(args.crosswalk)
    if "ad_group" not in fieldnames:
        fieldnames.append("ad_group")

    ad_groups = load_ad_groups_from_export(ad_path)
    if not ad_groups:
        logger.error("No AD group entries found in %s", ad_path)
        return 2

    lookup = build_ad_group_lookup(ad_groups)
    logger.info("AD group index: %d name(s) from %d entries", len(lookup), len(ad_groups))

    filled, kept, unmatched = fill_ad_groups(
        rows,
        lookup,
        ad_prefix=args.ad_prefix,
        overwrite=args.overwrite,
    )

    out = args.output or args.crosswalk
    write_crosswalk(out, fieldnames, rows)

    print(f"\nWrote {out}")
    print(f"  filled ad_group:        {filled}")
    print(f"  kept existing ad_group: {kept}")
    print(f"  unmatched rows:         {unmatched}")
    if unmatched:
        print("  Fix unmatched openldap_group_cn → ad_group manually, then re-run ipa_remap_trust_policy.py")
    return 1 if unmatched else 0


if __name__ == "__main__":
    sys.exit(main())
