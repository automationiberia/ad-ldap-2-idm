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
Suggest FreeIPA / IdM ID range parameters for migrated POSIX IDs.

Reads uidNumber / gidNumber from LDIF exports and prints recommended values for:

  ipa idrange-add … --base-id=… --range-size=… --rid-base=… --secondary-rid-base=…

Does not modify IdM. Review RID bases against: ipa idrange-find --all

Usage:
  python3 freeipa/migration/ipa_suggest_idrange.py --users ldap-users.ldif --groups ldap-groups.ldif
  python3 freeipa/migration/ipa_suggest_idrange.py --tree ldap-tree.ldif
  python3 freeipa/migration/ipa_suggest_idrange.py --collection-dir /path/to/collection
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Reuse LDIF helpers from the validator
sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_source_ldif import (  # noqa: E402
    LDIFParser,
    first,
    is_group,
    is_user,
)


def collect_ids(
    users: list[dict], groups: list[dict]
) -> tuple[list[int], list[int]]:
    uids: list[int] = []
    gids: list[int] = []
    for e in users:
        if not is_user(e):
            continue
        v = first(e, "uidNumber")
        if v.isdigit():
            uids.append(int(v))
    for e in groups:
        if not is_group(e):
            continue
        v = first(e, "gidNumber")
        if v.isdigit():
            gids.append(int(v))
    return uids, gids


def suggest(
    uids: list[int],
    gids: list[int],
    *,
    range_name: str,
    rid_base: int,
    secondary_rid_base: int,
) -> dict:
    if not uids and not gids:
        raise SystemExit("No uidNumber/gidNumber values found in input LDIFs")

    lo = min(uids + gids)
    hi = max(uids + gids)
    base_id = max(1000, (lo // 1000) * 1000)
    span = hi - base_id + 1
    range_size = max(10000, ((span // 1000) + 2) * 1000)
    return {
        "posix_min": lo,
        "posix_max": hi,
        "uid_min": min(uids) if uids else None,
        "uid_max": max(uids) if uids else None,
        "gid_min": min(gids) if gids else None,
        "gid_max": max(gids) if gids else None,
        "range_name": range_name,
        "base_id": base_id,
        "range_size": range_size,
        "rid_base": rid_base,
        "secondary_rid_base": secondary_rid_base,
        "covers_end": base_id + range_size - 1,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--users", type=Path, help="ldap-users.ldif")
    p.add_argument("--groups", type=Path, help="ldap-groups.ldif")
    p.add_argument("--tree", type=Path, help="ldap-tree.ldif")
    p.add_argument("--collection-dir", type=Path, help="Collection directory")
    p.add_argument("--range-name", default="migrated-posix-range")
    p.add_argument(
        "--rid-base",
        type=int,
        default=500000,
        help="Must not overlap existing IPA RID bases (check idrange-find --all)",
    )
    p.add_argument("--secondary-rid-base", type=int, default=500000000)
    args = p.parse_args(argv)

    users_p, groups_p, tree_p = args.users, args.groups, args.tree
    if args.collection_dir:
        d = args.collection_dir
        users_p = users_p or (d / "ldap-users.ldif")
        groups_p = groups_p or (d / "ldap-groups.ldif")
        tree_p = tree_p or (d / "ldap-tree.ldif")

    users = LDIFParser.parse_file(users_p) if users_p and users_p.is_file() else []
    groups = LDIFParser.parse_file(groups_p) if groups_p and groups_p.is_file() else []
    tree = LDIFParser.parse_file(tree_p) if tree_p and tree_p.is_file() else []
    if tree and not users:
        users = [e for e in tree if is_user(e)]
    if tree and not groups:
        groups = [e for e in tree if is_group(e)]
    if not users and not groups:
        p.error("Provide --users/--groups/--tree and/or --collection-dir with LDIFs")

    uids, gids = collect_ids(users, groups)
    s = suggest(
        uids,
        gids,
        range_name=args.range_name,
        rid_base=args.rid_base,
        secondary_rid_base=args.secondary_rid_base,
    )

    print("===== POSIX ID COVERAGE =====")
    print(f"uidNumber min/max: {s['uid_min']} / {s['uid_max']}  (n={len(uids)})")
    print(f"gidNumber min/max: {s['gid_min']} / {s['gid_max']}  (n={len(gids)})")
    print(f"Combined min/max:  {s['posix_min']} / {s['posix_max']}")
    print()
    print("===== SUGGESTED idrange PARAMETERS =====")
    print(f"range name:           {s['range_name']}")
    print(f"--base-id:            {s['base_id']}")
    print(f"--range-size:         {s['range_size']}")
    print(f"--rid-base:           {s['rid_base']}")
    print(f"--secondary-rid-base: {s['secondary_rid_base']}")
    print(f"covers POSIX IDs:     {s['base_id']} .. {s['covers_end']}")
    print()
    print("===== COMMANDS TO RUN ON IdM =====")
    print("# 1) Confirm RID bases do not overlap existing ranges:")
    print("ipa idrange-find --all")
    print()
    print(
        f"ipa idrange-add {s['range_name']} \\\n"
        f"  --base-id={s['base_id']} \\\n"
        f"  --range-size={s['range_size']} \\\n"
        f"  --rid-base={s['rid_base']} \\\n"
        f"  --secondary-rid-base={s['secondary_rid_base']}"
    )
    print()
    print("# 2) Restart Directory Server (realm → instance with dashes):")
    print("# systemctl restart dirsrv@BCNCONSULTING-COM.service")
    print()
    print("# 3) Generate SIDs (both flags together):")
    print("ipa config-mod --enable-sid --add-sids")
    print()
    print("# 4) Verify a migrated user:")
    print("ipa user-show <login> --all | grep -i ipantsecurityidentifier")
    return 0


if __name__ == "__main__":
    sys.exit(main())
