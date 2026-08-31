#!/usr/bin/env python3
# Copyright (C) 2026 BCN Consulting Lab
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Plan / apply ID Overrides for trusted AD users (Model C).

Offline equivalent of ipa-winsync-migrate for AD→LSC→OpenLDAP: POSIX from the
last OpenLDAP export → Default Trust View overrides for trusted AD principals.

  python3 ipa_trust_overrides.py \\
    --csv trust_catalog.d/user-overrides.csv \\
    --ad-realm WIN.IAM.LAB

  kinit admin
  python3 ipa_trust_overrides.py --csv … --execute
"""

from __future__ import annotations

import argparse
import csv
import logging
import sys
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from ipa_lib import (
        DEFAULT_TRUST_VIEW,
        dedupe_cmds,
        idoverrideuser_option_args,
        run_ipa_commands,
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
logger = logging.getLogger("TrustOverrides")

OUTPUT_DIR_DEFAULT = Path("ipa_trust_overrides.d")


def load_override_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def principal_for_row(row: dict[str, str], ad_realm: str) -> str | None:
    principal = (row.get("ad_user_principal") or "").strip()
    if principal:
        return principal
    uid = (row.get("openldap_uid") or "").strip()
    if uid and ad_realm:
        logger.warning(
            "Row openldap_uid=%s: ad_user_principal empty — fill CSV or pass mapping",
            uid,
        )
    return None


def override_cmds(
    view: str,
    principal: str,
    row: dict[str, str],
    *,
    cli_style: str,
) -> list[list[str]]:
    """Build idoverrideuser-add (same attrs as ipa-winsync-migrate)."""
    cmd = [
        "ipa",
        "idoverrideuser-add",
        view,
        principal,
    ]
    cmd.extend(idoverrideuser_option_args(row, cli_style=cli_style))
    return [cmd]


def build_cmds(
    rows: list[dict[str, str]],
    *,
    view: str,
    ad_realm: str,
    cli_style: str,
) -> list[list[str]]:
    cmds: list[list[str]] = []
    skipped = 0
    for row in rows:
        principal = principal_for_row(row, ad_realm)
        if not principal:
            skipped += 1
            continue
        cmds.extend(override_cmds(view, principal, row, cli_style=cli_style))
    if skipped:
        logger.warning("Skipped %d row(s) without ad_user_principal", skipped)
    return dedupe_cmds(cmds)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="ID Overrides for trusted AD users")
    p.add_argument("--csv", type=Path, required=True, help="user-overrides.csv")
    p.add_argument(
        "--view",
        default=DEFAULT_TRUST_VIEW,
        help=f"ID view name (default: {DEFAULT_TRUST_VIEW})",
    )
    p.add_argument(
        "--ad-realm",
        required=True,
        help="AD Kerberos realm (for validation messages; principals come from CSV)",
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        default=OUTPUT_DIR_DEFAULT,
    )
    p.add_argument(
        "--ipa-cli-style",
        choices=("legacy", "modern"),
        default="legacy",
        help="ipa idoverrideuser-add flag names (default: legacy — RHEL 8 / older IdM)",
    )
    p.add_argument(
        "--execute",
        action="store_true",
        help="Run ipa commands on this IdM host (requires kinit admin)",
    )
    args = p.parse_args(argv)

    rows = load_override_rows(args.csv)
    cmds = build_cmds(
        rows,
        view=args.view,
        ad_realm=args.ad_realm,
        cli_style=args.ipa_cli_style,
    )
    script = args.output_dir / "ipa_trust_overrides.sh"
    write_shell_script(
        script,
        cmds,
        f"ID overrides for trusted users — view={args.view}",
    )
    print(f"Wrote {script} ({len(cmds)} command(s))")

    if args.execute:
        failures = run_ipa_commands(cmds)
        return 1 if failures else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
