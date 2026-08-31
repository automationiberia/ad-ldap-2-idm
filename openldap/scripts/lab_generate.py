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
BCN Consulting enterprise OpenLDAP lab generator (customer-realistic).

Mirrors patterns seen in real OpenLDAP estates migrating to IdM:

  User:
    objectClass: top, person, organizationalPerson, inetOrgPerson,
                 posixAccount, shadowAccount, specialAttributes
    uid, cn, sn, givenName, gecos, mail, uidNumber, gidNumber,
    homeDirectory, loginShell, userPassword {SASL} (base64 userPassword::), shadow*,
    hostAccess* (privileged / scoped accounts)

  Group:
    objectClass: top, specialAttributes, posixGroup
    cn, gidNumber, memberUid*, hostAccess* (team login scope)

  Host:
    Mix of jump*/app* / mw*/app* / db* / web* / server* (HBAC hostgroup patterns)

  Sudo:
    sudoRole with %group, specific sudoHost, options, and on a subset
    sudoNotBefore / sudoNotAfter (GeneralizedTime) for remapper setattr tests

Also injects:
  - One intentional uidNumber collision (user-dup vs another account) so
    ipa_remap_access.py --uid-report-only has realistic input
  - cn=defaults sudoRole (ignored by remappers)

Creates: 600 users, 60 groups, 100 hosts, 100+ sudo rules
"""

from __future__ import annotations

import argparse
import base64
import random
import sys
from collections import defaultdict
from pathlib import Path

BASE_DN = "dc=bcnconsulting,dc=com"
DEFAULT_OUTPUT = "bcnconsulting-enterprise-600users-60groups-100sudo.ldif"

USERS = 600
GROUPS = 60
HOSTS = 100
SUDO_RULES = 100

# Customer-like POSIX ranges (not IPA DNA defaults)
UID_BASE = 9000
GID_BASE = 8000

RNG_SEED = 42

FIRST_NAMES = [
    "Pepito", "Ana", "Carlos", "Maria", "Luis", "Elena", "Jorge", "Lucia",
    "Miguel", "Laura", "Pablo", "Sofia", "Diego", "Carmen", "Andres", "Paula",
]
LAST_NAMES = [
    "Perez", "Garcia", "Lopez", "Martinez", "Sanchez", "Fernandez",
    "Gonzalez", "Rodriguez", "Ruiz", "Diaz", "Torres", "Ramirez",
]

# Generic lab group names (structure like enterprise; names are NOT customer-like)
NAMED_GROUPS = [
    "grp-linux",       # primary for user0001
    "grp-network",
    "grp-database",
    "grp-middleware",
    "grp-web",
    "grp-storage",
    "grp-security",
    "grp-devops",
    "grp-batch",
    "grp-helpdesk",
    "grp-monitoring",
    "grp-backup",
    "grp-cloud",
    "grp-virtualization",
    "grp-cicd",
    "grp-db-oracle",
    "grp-db-postgres",
    "grp-app-finance",
    "grp-app-hr",
    "grp-app-crm",
]

DEPT_BY_GROUP = {
    "grp-linux": "ops",
    "grp-network": "net",
    "grp-database": "db",
    "grp-middleware": "mw",
    "grp-web": "web",
    "grp-storage": "sto",
    "grp-security": "sec",
    "grp-devops": "dev",
    "grp-batch": "bat",
    "grp-helpdesk": "hdk",
    "grp-monitoring": "mon",
}

# Group → hostAccess host-class prefixes (generic lab inventory)
GROUP_HOST_PREFIX = {
    "grp-linux": ["jump", "app"],
    "grp-network": ["jump"],
    "grp-database": ["db"],
    "grp-middleware": ["app", "mw"],
    "grp-web": ["web", "app"],
    "grp-storage": ["jump", "db"],
    "grp-security": ["jump", "web", "db"],
    "grp-devops": ["web", "app", "ci"],
    "grp-batch": ["batch", "app"],
    "grp-helpdesk": ["web"],
    "grp-monitoring": ["jump", "web", "db", "app", "mw"],
}

SUDO_COMMAND_SETS = [
    ["/usr/bin/mount", "/usr/bin/umount", "/usr/bin/lsblk"],
    ["/usr/bin/ip", "/usr/bin/nmcli", "/usr/sbin/iptables"],
    ["/usr/bin/systemctl restart mysqld", "/usr/bin/systemctl restart postgresql"],
    ["/usr/bin/rsync", "/usr/bin/tar"],
    ["/usr/bin/passwd", "/usr/sbin/useradd", "/usr/sbin/usermod"],
    ["/usr/bin/dnf", "/usr/bin/podman"],
    ["ALL"],
    ["/usr/bin/systemctl", "/usr/bin/journalctl"],
    ["/usr/local/bin/kubectl", "/usr/bin/crictl"],
    ["/usr/bin/systemctl restart httpd", "/usr/sbin/nginx"],
]


def group_cn(n: int) -> str:
    if 1 <= n <= len(NAMED_GROUPS):
        return NAMED_GROUPS[n - 1]
    return f"team{n:03d}"


def group_gid(n: int) -> int:
    return GID_BASE + n


def dept_for_group(cn: str) -> str:
    return DEPT_BY_GROUP.get(cn, "ops")


def domain_from_dn(base_dn: str) -> str:
    """Turn ``dc=foo,dc=bar`` into ``foo.bar``."""
    parts: list[str] = []
    for piece in base_dn.split(","):
        piece = piece.strip()
        if piece.lower().startswith("dc="):
            parts.append(piece.split("=", 1)[1])
    return ".".join(parts) if parts else "bcnconsulting.com"


def sasl_user_password_b64(uid: str, domain: str) -> str:
    """
    LSC-style trust anchor: ``userPassword::`` holds base64 of
    ``{SASL}uid@domain`` (decoded by migration LDIF parsers).
    """
    payload = f"{{SASL}}{uid}@{domain}"
    return base64.b64encode(payload.encode("utf-8")).decode("ascii")


def build_hosts() -> list[dict]:
    """100 hosts with generic class prefixes for HBAC pattern mapping."""
    plan = [
        ("jump", 10),
        ("app", 20),
        ("mw", 10),
        ("db", 20),
        ("web", 15),
        ("batch", 10),
        ("ci", 15),
    ]
    hosts: list[dict] = []
    ip_octet = 10
    for prefix, count in plan:
        for i in range(1, count + 1):
            short = f"{prefix}{i:02d}"
            hosts.append(
                {
                    "cn": short,
                    "ip": f"192.168.100.{ip_octet}",
                    "prefix": prefix,
                    "description": f"Lab {prefix} host {short}",
                }
            )
            ip_octet += 1
    assert len(hosts) == HOSTS, len(hosts)
    return hosts


def hosts_by_prefix(hosts: list[dict]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for h in hosts:
        out[h["prefix"]].append(h["cn"])
    return out


def pick_host_access(cn: str, by_prefix: dict[str, list[str]], privileged: bool) -> list[str]:
    """
    Realistic structure: short hostname + FQDN (same pattern as many LDAP ACLs).
    Names themselves are generic lab inventory only.
    """
    prefixes = GROUP_HOST_PREFIX.get(cn)
    if not prefixes:
        pool = by_prefix.get("jump", [])[:5]
        shorts = pool[:2] if pool else []
    else:
        selected: list[str] = []
        for p in prefixes:
            pool = by_prefix.get(p, [])
            if not pool:
                continue
            take = 3 if privileged else 2
            selected.extend(pool[:take])
        shorts = list(dict.fromkeys(selected))

    values: list[str] = []
    for short in shorts:
        values.append(short)
        values.append(f"{short}.bcnconsulting.com")
    return values


def build_memberships(
    hosts: list[dict],
    *,
    principal_domain: str,
) -> tuple[list[dict], dict[str, list[str]], dict[str, list[str]]]:
    """Return users, membership, group_hostaccess."""
    by_prefix = hosts_by_prefix(hosts)
    membership: dict[str, list[str]] = defaultdict(list)
    group_ha: dict[str, list[str]] = {}
    users: list[dict] = []

    for n in range(1, GROUPS + 1):
        cn = group_cn(n)
        group_ha[cn] = pick_host_access(cn, by_prefix, privileged=(n <= 5))

    for i in range(1, USERS + 1):
        uid = f"user{i:04d}"
        primary_n = ((i - 1) % GROUPS) + 1
        primary = group_cn(primary_n)
        membership[primary].append(uid)

        if random.random() < 0.25:
            other_n = random.randint(1, GROUPS)
            while other_n == primary_n:
                other_n = random.randint(1, GROUPS)
            membership[group_cn(other_n)].append(uid)

        first = FIRST_NAMES[(i - 1) % len(FIRST_NAMES)]
        last = LAST_NAMES[(i - 1) % len(LAST_NAMES)]
        dept = dept_for_group(primary)
        cn = f"{uid}-{dept}"
        sn = f"{first} {last}"
        privileged = primary_n <= 5
        gecos = "Privileged User" if privileged else f"{first} {last}"

        # Per-user hostAccess for privileged accounts (specialAttributes payload)
        user_ha: list[str] = []
        if privileged:
            user_ha = pick_host_access(primary, by_prefix, privileged=True)
        elif random.random() < 0.08:
            user_ha = pick_host_access(primary, by_prefix, privileged=False)[:2]

        users.append(
            {
                "uid": uid,
                "cn": cn,
                "sn": sn,
                "given": first,
                "gecos": gecos,
                "index": i,
                "uidnumber": UID_BASE + i,
                "primary": primary,
                "gid": group_gid(primary_n),
                "password_b64": sasl_user_password_b64(uid, principal_domain),
                "host_access": user_ha,
                "privileged": privileged,
            }
        )

    for n in range(1, GROUPS + 1):
        cn = group_cn(n)
        if not membership[cn]:
            membership[cn].append(users[(n - 1) % len(users)]["uid"])

    # Generic service accounts (structure only — not customer login patterns)
    service_accounts = [
        ("svc-linux", "grp-linux", "Privileged User"),
        ("svc-db", "grp-database", "Privileged User"),
        ("svc-web", "grp-web", "Privileged User"),
    ]
    extra_uid = UID_BASE + USERS + 10
    for login, primary, gecos in service_accounts:
        gid = group_gid(NAMED_GROUPS.index(primary) + 1)
        membership[primary].append(login)
        ha = pick_host_access(primary, by_prefix, privileged=True)
        users.append(
            {
                "uid": login,
                "cn": login,
                "sn": login.replace("-", " ").title(),
                "given": login.split("-")[0].title(),
                "gecos": gecos,
                "index": extra_uid,
                "uidnumber": extra_uid,
                "primary": primary,
                "gid": gid,
                "password_b64": sasl_user_password_b64(login, principal_domain),
                "host_access": ha,
                "privileged": True,
            }
        )
        extra_uid += 1

    # Intentional uidNumber collision for pre-migrate reporting
    victim = next(u for u in users if u["uid"] == "user0500")
    users.append(
        {
            "uid": "user-dup",
            "cn": "user-dup-conflict",
            "sn": "Duplicate Uid",
            "given": "Dup",
            "gecos": "UID CONFLICT LAB ACCOUNT",
            "index": 99999,
            "uidnumber": victim["uidnumber"],
            "primary": "grp-helpdesk",
            "gid": group_gid(NAMED_GROUPS.index("grp-helpdesk") + 1),
            "password_b64": sasl_user_password_b64("user-dup", principal_domain),
            "host_access": [],
            "privileged": False,
            "uid_conflict": True,
        }
    )
    membership["grp-helpdesk"].append("user-dup")

    return users, membership, group_ha


def write_ldif(
    path: Path,
    users: list[dict],
    membership: dict[str, list[str]],
    group_ha: dict[str, list[str]],
    hosts: list[dict],
) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for ou in ("People", "Groups", "Hosts", "SUDOers"):
            fh.write(
                f"""dn: ou={ou},{BASE_DN}
objectClass: organizationalUnit
ou: {ou}

"""
            )

        for n in range(1, GROUPS + 1):
            cn = group_cn(n)
            members = list(dict.fromkeys(membership[cn]))
            fh.write(
                f"""dn: cn={cn},ou=Groups,{BASE_DN}
gidNumber: {group_gid(n)}
objectClass: top
objectClass: specialAttributes
objectClass: posixGroup
cn: {cn}
description: Enterprise lab group {cn}
"""
            )
            for ha in group_ha.get(cn, []):
                fh.write(f"hostAccess: {ha}\n")
            for member in members:
                fh.write(f"memberUid: {member}\n")
            fh.write("\n")

        for user in users:
            fh.write(
                f"""dn: uid={user['uid']},ou=People,{BASE_DN}
loginShell: /bin/bash
sn: {user['sn']}
gidNumber: {user['gid']}
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
objectClass: specialAttributes
uid: {user['uid']}
gecos: {user['gecos']}
uidNumber: {user['uidnumber']}
cn: {user['cn']}
givenName: {user['given']}
homeDirectory: /home/{user['uid']}
mail: {user['uid']}@bcnconsulting.com
userPassword:: {user['password_b64']}
shadowLastChange: 19700
shadowMax: 99999
shadowWarning: 7
"""
            )
            for ha in user.get("host_access") or []:
                fh.write(f"hostAccess: {ha}\n")
            fh.write("\n")

        for h in hosts:
            fh.write(
                f"""dn: cn={h['cn']},ou=Hosts,{BASE_DN}
objectClass: top
objectClass: device
objectClass: ipHost
cn: {h['cn']}
ipHostNumber: {h['ip']}
description: {h['description']}

"""
            )

        # Global defaults (remappers must skip)
        fh.write(
            f"""dn: cn=defaults,ou=SUDOers,{BASE_DN}
objectClass: top
objectClass: sudoRole
cn: defaults
description: OpenLDAP sudo defaults
sudoOption: !authenticate
sudoOption: env_reset

"""
        )

        for counter in range(1, SUDO_RULES + 1):
            g_n = ((counter - 1) % GROUPS) + 1
            g_cn = group_cn(g_n)
            cmds = SUDO_COMMAND_SETS[(counter - 1) % len(SUDO_COMMAND_SETS)]
            rule = f"sudo-{g_cn}-{counter:03d}"

            # Most rules: ALL hosts; some scoped to group hostAccess
            if counter % 7 == 0 and group_ha.get(g_cn):
                sudo_hosts = group_ha[g_cn][:2]
            else:
                sudo_hosts = ["ALL"]

            fh.write(
                f"""dn: cn={rule},ou=SUDOers,{BASE_DN}
objectClass: top
objectClass: sudoRole
cn: {rule}
description: Lab sudo for %{g_cn}
sudoUser: %{g_cn}
sudoRunAsUser: ALL
sudoOption: !authenticate
sudoOrder: {counter}
"""
            )
            for shost in sudo_hosts:
                fh.write(f"sudoHost: {shost}\n")
            for cmd in cmds:
                fh.write(f"sudoCommand: {cmd}\n")

            # Temporal windows on ~15% of rules (remapper setattr path)
            if counter % 7 == 1:
                fh.write("sudoNotBefore: 20240101000000Z\n")
                fh.write("sudoNotAfter: 20261231235959Z\n")
            fh.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"Output LDIF path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--domain",
        default=domain_from_dn(BASE_DN),
        help="Domain in {SASL}uid@domain userPassword (default: from BASE_DN)",
    )
    args = parser.parse_args()

    random.seed(RNG_SEED)
    print("Generating realistic BCN enterprise LDAP laboratory")

    hosts = build_hosts()
    users, membership, group_ha = build_memberships(
        hosts,
        principal_domain=args.domain,
    )
    out = Path(args.output).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    write_ldif(out, users, membership, group_ha, hosts)

    text = out.read_text(encoding="utf-8")
    member_attrs = text.count("memberUid:")
    host_access_attrs = text.count("hostAccess:")
    if member_attrs < USERS:
        print(f"ERROR: memberUid count too low: {member_attrs}", file=sys.stderr)
        return 1

    u1 = next(u for u in users if u["uid"] == "user0001")
    conflicts = [u for u in users if u.get("uid_conflict")]
    print()
    print("Generated:")
    print(f"  {out}")
    print()
    print(f"Users : {len(users)} (incl. service accts + uid-conflict demo)")
    print(f"Groups: {GROUPS} (named: {', '.join(NAMED_GROUPS[:5])}…)")
    print(f"Hosts : {HOSTS} (jump/app/mw/db/web/batch/ci)")
    print(f"Sudo  : {SUDO_RULES} + cn=defaults")
    print(f"memberUid attributes : {member_attrs}")
    print(f"hostAccess attributes: {host_access_attrs}")
    print()
    print("Sample shapes:")
    print(f"  group: cn={u1['primary']}  hostAccess={group_ha.get(u1['primary'], [])[:3]}…")
    sasl_plain = f"{{SASL}}{u1['uid']}@{args.domain}"
    print(
        f"  user:  uid={u1['uid']} cn={u1['cn']} sn={u1['sn']} "
        f"gecos={u1['gecos']} hostAccess={u1['host_access']}"
    )
    print(f"  userPassword: {sasl_plain} (written as userPassword:: base64)")
    print(f"  host:  cn={hosts[0]['cn']} / cn={hosts[15]['cn']} / cn={hosts[30]['cn']}")
    if conflicts:
        c = conflicts[0]
        print(
            f"  UID CONFLICT (fix before migrate-ds): "
            f"uid={c['uid']} shares uidNumber={c['uidnumber']} with user0500"
        )
    print()
    print("Requires schema: openldap/schema/specialAttributes.ldif (with hostAccess)")
    print("Post-migrate: freeipa/migration/ipa_remap_access.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
