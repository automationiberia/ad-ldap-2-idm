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
Bulk-delete IdM users/groups listed in OpenLDAP export LDIFs.

Extracts `uid` from a users LDIF and/or `cn` from a posixGroup LDIF, then
prints (default) or executes batched `ipa user-del` / `ipa group-del` commands.

Usage:
  python3 freeipa/migration/ipa_delete_from_ldif.py --users ldap-users.ldif
  python3 freeipa/migration/ipa_delete_from_ldif.py --users u.ldif --groups g.ldif --batch-size 100
  python3 freeipa/migration/ipa_delete_from_ldif.py --users u.ldif --execute
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_source_ldif import (  # noqa: E402
    LDIFParser,
    first,
    is_group,
    is_user,
)


def extract_uids(entries: list[dict]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for e in entries:
        if not is_user(e):
            continue
        uid = first(e, "uid")
        if uid and uid not in seen:
            seen.add(uid)
            out.append(uid)
    return out


def extract_group_cns(entries: list[dict]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for e in entries:
        if not is_group(e):
            continue
        cn = first(e, "cn")
        if cn and cn not in seen:
            seen.add(cn)
            out.append(cn)
    return out


def chunks(items: list[str], size: int) -> list[list[str]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def run_or_print(cmd: list[str], execute: bool) -> int:
    line = " ".join(cmd)
    if not execute:
        print(line)
        return 0
    print("+", line)
    return subprocess.run(cmd, check=False).returncode


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--users", type=Path, help="ldap-users.ldif (extract uid)")
    p.add_argument("--groups", type=Path, help="ldap-groups.ldif (extract cn)")
    p.add_argument("--batch-size", type=int, default=100)
    p.add_argument(
        "--execute",
        action="store_true",
        help="Run ipa commands (default: print only)",
    )
    args = p.parse_args(argv)

    if not args.users and not args.groups:
        p.error("Provide --users and/or --groups LDIF path(s)")

    uids: list[str] = []
    cns: list[str] = []
    if args.users:
        if not args.users.is_file():
            p.error(f"File not found: {args.users}")
        uids = extract_uids(LDIFParser.parse_file(args.users))
    if args.groups:
        if not args.groups.is_file():
            p.error(f"File not found: {args.groups}")
        cns = extract_group_cns(LDIFParser.parse_file(args.groups))

    print(f"# users to delete: {len(uids)}")
    print(f"# groups to delete: {len(cns)}")
    if not args.execute:
        print("# dry-run — pass --execute to run on IdM (requires kinit admin)")
    print()

    rc = 0
    for batch in chunks(uids, max(1, args.batch_size)):
        cmd = ["ipa", "user-del", "--continue", *batch]
        if run_or_print(cmd, args.execute) != 0:
            rc = 1
    for batch in chunks(cns, max(1, args.batch_size)):
        cmd = ["ipa", "group-del", "--continue", *batch]
        if run_or_print(cmd, args.execute) != 0:
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
