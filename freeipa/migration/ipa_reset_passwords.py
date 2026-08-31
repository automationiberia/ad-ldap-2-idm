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
Reset lab user passwords in FreeIPA after migrate-ds.

Why: ipa migrate-ds may copy LDAP userPassword hashes, but Kerberos keys
(kinit) are not usable until the password is set through IPA.

Usage (on IdM, after kinit admin):
  python3 ipa_reset_passwords.py
  python3 ipa_reset_passwords.py --password redhat00 --prefix user
"""

from __future__ import annotations

import argparse
import subprocess
import sys


def run(cmd: list[str], input_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def list_users(prefix: str) -> list[str]:
    result = run(
        [
            "ipa",
            "user-find",
            f"--login={prefix}*",
            "--sizelimit=0",
            "--raw",
        ]
    )
    users: list[str] = []
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        # raw: uid: user0001
        if line.startswith("uid:"):
            uid = line.split(":", 1)[1].strip()
            if uid.startswith(prefix):
                users.append(uid)
    # fallback parse non-raw
    if not users:
        result = run(["ipa", "user-find", f"--login={prefix}*", "--sizelimit=0"])
        for line in (result.stdout or "").splitlines():
            if "User login:" in line:
                users.append(line.split(":", 1)[1].strip())
    return sorted(set(users))


def set_password(login: str, password: str) -> bool:
    # Prefer non-interactive stdin; avoid shell history expansion on '!'
    for cmd in (
        ["ipa", "passwd", login],
        ["ipa", "user-mod", login, "--password"],
    ):
        result = run(cmd, input_text=f"{password}\n{password}\n")
        if result.returncode == 0:
            # Lab: avoid forced immediate password change on kinit
            run(
                [
                    "ipa",
                    "user-mod",
                    login,
                    "--setattr=krbPasswordExpiration=20301231235959Z",
                ]
            )
            run(["ipa", "user-unlock", login])
            return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--password", default="redhat00", help="Lab password")
    parser.add_argument("--prefix", default="user", help="Login prefix (default: user)")
    parser.add_argument("--limit", type=int, default=0, help="Max users (0=all)")
    args = parser.parse_args()

    users = list_users(args.prefix)
    if args.limit:
        users = users[: args.limit]

    if not users:
        print("No users found. Did migrate-ds succeed? Try: ipa user-find user0001")
        return 1

    print(f"Resetting password for {len(users)} users to '{args.password}'")
    ok = 0
    fail = 0
    for login in users:
        if set_password(login, args.password):
            print(f"  OK  {login}")
            ok += 1
        else:
            print(f"  FAIL {login}")
            fail += 1

    print()
    print(f"Done. ok={ok} fail={fail}")
    print("Test: kinit user0001   # password: redhat00")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
