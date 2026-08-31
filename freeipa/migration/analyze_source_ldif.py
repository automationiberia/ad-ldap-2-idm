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
Pre-migration LDIF validation for OpenLDAP → IdM (engagement).

Analyzes collection LDIFs and writes an action-oriented report.
Stdlib only (RHEL-friendly). Useful before the AD trust mapping path
(docs/05-mapping.md); it does not talk to IdM.

Exit codes:
  0 — no critical blockers
  1 — critical issues that would block import or mapping

Usage:
  python3 freeipa/migration/analyze_source_ldif.py \\
    --users ldap-users.ldif --groups ldap-groups.ldif \\
    --tree ldap-tree.ldif --sudo sudo-rules.ldif
  # → analyze_source.d/analyze_source_YYYYMMDD_HHMMSS.txt


  # Full DIT from slapcat (openldap-export.ldif):
  python3 freeipa/migration/analyze_source_ldif.py \\
    --slapcat openldap-export.ldif

  python3 freeipa/migration/analyze_source_ldif.py \\
    --collection-dir /tmp/openldap_migration_20260804
"""

from __future__ import annotations

import argparse
import base64
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# ObjectClasses migrate-ds / IPA commonly accept (RFC2307 path).
MIGRATABLE_OCS = {
    "top",
    "person",
    "organizationalPerson",
    "inetOrgPerson",
    "posixAccount",
    "shadowAccount",
    "posixGroup",
    "sudoRole",
    "organizationalUnit",
    "domain",
    "dcObject",
    "organization",
    "groupOfNames",
    "groupOfUniqueNames",
    "ipHost",
    "device",
    "ieee802Device",
    "account",
    "ldapPublicKey",
}

# Present in source; need review (not stock IPA user/group identity path).
REVIEW_OCS = {
    "organizationalRole",
    "simpleSecurityObject",
}

# Attributes typically not part of stock IPA user/group schema (non-sudo).
CUSTOM_ATTR_HINTS = {
    "hostaccess",
}

# Common structural OUs (anything else → "unknown OU" hint).
COMMON_OUS = {
    "people",
    "groups",
    "sudoers",
    "hosts",
    "services",
    "config",
    "users",
    "computers",
}

STANDARD_ATTRS = {
    "dn",
    "objectclass",
    "cn",
    "sn",
    "givenname",
    "uid",
    "uidnumber",
    "gidnumber",
    "homedirectory",
    "loginshell",
    "gecos",
    "userpassword",
    "mail",
    "description",
    "memberuid",
    "member",
    "uniquemember",
    "ou",
    "dc",
    "o",
    "l",
    "st",
    "street",
    "postalcode",
    "telephonenumber",
    "mobile",
    "title",
    "displayname",
    "initials",
    "shadowlastchange",
    "shadowmin",
    "shadowmax",
    "shadowwarning",
    "shadowinactive",
    "shadowexpire",
    "shadowflag",
    "createtimestamp",
    "modifytimestamp",
    "creatorsname",
    "modifiersname",
    "entryuuid",
    "entrycsn",
    "structuralobjectclass",
    "hassubordinates",
    "subschemasubentry",
    "iphostnumber",
    "macaddress",
    # sudo schema attrs (expected with sudoRole; migrate separately)
    "sudouser",
    "sudohost",
    "sudocommand",
    "sudooption",
    "sudorunas",
    "sudorunasuser",
    "sudorunasgroup",
    "sudonotbefore",
    "sudonotafter",
    "sudoorder",
    "sudorunasuid",
}


class LDIFParser:
    """RFC 2849 LDIF parser (folding + base64) — no external deps."""

    @staticmethod
    def parse_file(filepath: str | Path) -> list[dict[str, list[str]]]:
        path = Path(filepath)
        if not path.is_file():
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
                        value = base64.b64decode(payload).decode(
                            "utf-8", errors="replace"
                        )
                    except Exception:
                        value = payload
                else:
                    value = rest[1:].strip() if rest.startswith(" ") else rest.strip()

                current[attr].append(value)
                current_attr = attr

        if current:
            entries.append(dict(current))
        return entries


def first(entry: dict[str, list[str]], *names: str) -> str:
    for name in names:
        for key, vals in entry.items():
            if key.lower() == name.lower() and vals:
                return vals[0]
    return ""


def all_vals(entry: dict[str, list[str]], name: str) -> list[str]:
    out: list[str] = []
    for key, vals in entry.items():
        if key.lower() == name.lower():
            out.extend(vals)
    return out


def has_oc(entry: dict[str, list[str]], needle: str) -> bool:
    return any(v.lower() == needle.lower() for v in all_vals(entry, "objectClass"))


def oc_set(entry: dict[str, list[str]]) -> set[str]:
    return {v.lower() for v in all_vals(entry, "objectClass")}


def is_posix_user(entry: dict[str, list[str]]) -> bool:
    return has_oc(entry, "posixAccount")


def is_user(entry: dict[str, list[str]]) -> bool:
    """Broad user-like entry (posix or inetOrgPerson)."""
    if has_oc(entry, "posixAccount") or has_oc(entry, "inetOrgPerson"):
        return True
    dn = first(entry, "dn").lower()
    return dn.startswith("uid=")


def is_group(entry: dict[str, list[str]]) -> bool:
    if has_oc(entry, "posixGroup"):
        return True
    dn = first(entry, "dn").lower()
    return ",ou=groups," in dn and dn.startswith("cn=")


def is_sudo(entry: dict[str, list[str]]) -> bool:
    return has_oc(entry, "sudoRole")


SERVICE_NAME_HINTS = (
    "ldap",
    "svc",
    "service",
    "app",
    "bind",
    "proxy",
    "ro_",
    "rw_",
    "jenkins",
    "orchestrat",
    "monitor",
)


def is_ou(entry: dict[str, list[str]]) -> bool:
    return has_oc(entry, "organizationalUnit") or first(entry, "dn").lower().startswith(
        "ou="
    )


def _name_hint_hit(entry: dict[str, list[str]]) -> str | None:
    uid = first(entry, "uid").lower()
    cn = first(entry, "cn").lower()
    for hint in SERVICE_NAME_HINTS:
        if hint in uid or hint in cn:
            return hint
    return None


def _under_ou_services(entry: dict[str, list[str]]) -> bool:
    dn = first(entry, "dn").lower()
    return ",ou=services," in dn or dn.startswith("ou=services,")


def service_account_reasons(entry: dict[str, list[str]]) -> list[str]:
    """Why this entry is a service/bind candidate (empty = not a candidate)."""
    reasons: list[str] = []
    if has_oc(entry, "simpleSecurityObject"):
        reasons.append("simpleSecurityObject")
    if has_oc(entry, "organizationalRole"):
        reasons.append("organizationalRole")
    if _under_ou_services(entry) and (is_user(entry) or is_posix_user(entry)):
        reasons.append("ou=Services")
    hint = _name_hint_hit(entry)
    if hint and (is_user(entry) or is_posix_user(entry) or has_oc(entry, "account")):
        reasons.append(f"name-hint:{hint}")
    if is_user(entry) and not is_posix_user(entry) and reasons:
        reasons.append("non-POSIX")
    seen: set[str] = set()
    out: list[str] = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def recommend_sysaccount(entry: dict[str, list[str]], reasons: list[str]) -> tuple[str, str]:
    """
    Return (OK|REVIEW, short guidance).

    OK     — recreate as IdM system account; exclude from migrate-ds as user
    REVIEW — human decision (POSIX login vs bind-only)
    """
    posix = is_posix_user(entry)
    bindish = (
        "simpleSecurityObject" in reasons
        or "organizationalRole" in reasons
        or "non-POSIX" in reasons
    )
    if bindish and not posix:
        return (
            "OK",
            "IdM sysaccount (ipa sysaccount-add); do not migrate as POSIX user",
        )
    if "ou=Services" in reasons or any(r.startswith("name-hint:") for r in reasons):
        if posix:
            return (
                "REVIEW",
                "POSIX under Services/svc*: sysaccount if bind-only; "
                "keep as IdM user if SSH/sudo/HBAC still required",
            )
        return (
            "OK",
            "Likely bind account → IdM sysaccount; confirm app still needs it",
        )
    if bindish and posix:
        return (
            "REVIEW",
            "Has bind OC but is POSIX — decide sysaccount vs user",
        )
    return ("REVIEW", "Candidate — confirm with application owners")


def is_service_account(entry: dict[str, list[str]]) -> bool:
    return bool(service_account_reasons(entry))


def classify_service_accounts(
    entries: list[dict[str, list[str]]],
) -> list[dict[str, str]]:
    """List of {name, dn, objectClass, reasons, status, action}."""
    rows: list[dict[str, str]] = []
    for e in entries:
        reasons = service_account_reasons(e)
        if not reasons:
            continue
        status, action = recommend_sysaccount(e, reasons)
        rows.append(
            {
                "name": first(e, "cn") or first(e, "uid") or first(e, "dn"),
                "dn": first(e, "dn"),
                "objectClass": ", ".join(all_vals(e, "objectClass")),
                "posix": "yes" if is_posix_user(e) else "no",
                "reasons": ", ".join(reasons),
                "status": status,
                "action": action,
            }
        )
    rows.sort(key=lambda r: (r["status"] != "OK", r["name"].lower()))
    return rows


def classify_no_password(entry: dict[str, list[str]]) -> str:
    if is_service_account(entry):
        return "technical"
    uid = first(entry, "uid").lower()
    dn = first(entry, "dn").lower()
    if any(x in uid or x in dn for x in ("app", "service", "counter", "config")):
        return "application"
    if is_posix_user(entry):
        return "user"
    return "technical"


def duplicates(index: dict[str, list[dict]]) -> dict[str, list[dict]]:
    return {k: v for k, v in index.items() if k and len(v) > 1}


def ou_rdn(dn: str) -> str:
    return dn.split(",", 1)[0].strip()


def parent_dn(dn: str) -> str:
    parts = dn.split(",", 1)
    return parts[1].strip() if len(parts) == 2 else ""


def detect_base_dn(source: list[dict]) -> str:
    dc_only = sorted(
        {
            first(e, "dn")
            for e in source
            if re.match(r"^dc=[^,]+(,dc=[^,]+)*$", first(e, "dn"), flags=re.I)
        },
        key=len,
    )
    if dc_only:
        return dc_only[0]
    for e in source:
        dn = first(e, "dn")
        m = re.search(r"(dc=[^,]+(?:,dc=[^,]+)*)$", dn, flags=re.I)
        if m:
            return m.group(1)
    return ""


def rdn_value(rdn: str) -> str:
    if "=" in rdn:
        return rdn.split("=", 1)[1]
    return rdn


def analyze(
    users: list[dict],
    groups: list[dict],
    tree: list[dict],
    sudo: list[dict],
) -> tuple[str, bool]:
    """Return (report_text, has_critical)."""
    critical: list[str] = []
    source = tree if tree else (users + groups + sudo)

    # Prefer dedicated lists; fill from tree if needed
    posix_users = [e for e in (users or source) if is_posix_user(e)]
    person_users = [e for e in (users or source) if is_user(e)]
    posix_groups = [e for e in (groups or source) if is_group(e)]
    sudo_entries = [e for e in (sudo or source) if is_sudo(e)]
    # Drop cn=defaults from "rules" count display but keep in list note
    sudo_rules = [
        e
        for e in sudo_entries
        if first(e, "cn").lower() != "defaults"
    ]
    ou_entries = [e for e in source if is_ou(e)]
    service_rows = classify_service_accounts(source)
    service_accts = service_rows  # keep name for summary counts


    base_dn = detect_base_dn(source)

    # --- indexes ---
    by_uid: dict[str, list[dict]] = defaultdict(list)
    by_uidn: dict[str, list[dict]] = defaultdict(list)
    missing_user: dict[str, list[str]] = defaultdict(list)
    uid_nums: list[int] = []
    no_password: list[tuple[str, str, str]] = []  # label, class, dn
    password_notes: list[str] = []

    for e in posix_users:
        uid = first(e, "uid")
        uidn = first(e, "uidNumber")
        dn = first(e, "dn")
        label = uid or dn or "(unknown)"
        if uid:
            by_uid[uid].append(e)
        else:
            missing_user["uid"].append(dn or "(no dn)")
        if uidn:
            by_uidn[uidn].append(e)
            try:
                uid_nums.append(int(uidn))
            except ValueError:
                critical.append(f"Non-numeric uidNumber={uidn} ({label})")
        else:
            missing_user["uidNumber"].append(label)
        for req in ("gidNumber", "homeDirectory", "loginShell"):
            if not first(e, req):
                missing_user[req].append(label)

        pw = first(e, "userPassword")
        if not pw:
            no_password.append((label, classify_no_password(e), dn))
        elif pw.upper().startswith("{SASL}"):
            password_notes.append(f"{label}: SASL proxy — not an IPA Kerberos key")
        elif pw.startswith(("{CRYPT}", "{MD5}", "{SMD5}", "{SHA}")):
            password_notes.append(f"{label}: legacy hash — plan password reset after migrate")

    # Also scan non-posix person entries for missing password / service
    for e in person_users:
        if is_posix_user(e):
            continue
        uid = first(e, "uid") or first(e, "cn")
        dn = first(e, "dn")
        if not first(e, "userPassword"):
            no_password.append((uid or dn, classify_no_password(e), dn))

    dup_uid = duplicates(by_uid)
    dup_uidn = duplicates(by_uidn)
    if dup_uid:
        critical.append(f"Duplicate uid: {len(dup_uid)} value(s)")
    if dup_uidn:
        critical.append(f"Duplicate uidNumber: {len(dup_uidn)} value(s)")
    for req, labels in missing_user.items():
        if labels:
            critical.append(f"POSIX users missing {req}: {len(labels)}")

    by_cn: dict[str, list[dict]] = defaultdict(list)
    by_gidn: dict[str, list[dict]] = defaultdict(list)
    missing_group: dict[str, list[str]] = defaultdict(list)
    gid_nums: list[int] = []
    users_by_primary_gid: dict[str, list[str]] = defaultdict(list)

    for e in posix_users:
        gidn = first(e, "gidNumber")
        if gidn:
            users_by_primary_gid[gidn].append(first(e, "uid") or first(e, "dn"))

    for e in posix_groups:
        cn = first(e, "cn")
        gidn = first(e, "gidNumber")
        dn = first(e, "dn")
        label = cn or dn or "(unknown)"
        if cn:
            by_cn[cn].append(e)
        else:
            missing_group["cn"].append(dn or "(no dn)")
        if gidn:
            by_gidn[gidn].append(e)
            try:
                gid_nums.append(int(gidn))
            except ValueError:
                critical.append(f"Non-numeric gidNumber={gidn} ({label})")
        else:
            missing_group["gidNumber"].append(label)

    dup_cn = duplicates(by_cn)
    dup_gidn_groups = duplicates(by_gidn)  # same gidNumber on 2+ groups = error
    if dup_cn:
        critical.append(f"Duplicate group cn: {len(dup_cn)} value(s)")
    if dup_gidn_groups:
        critical.append(
            f"Duplicate gidNumber across groups: {len(dup_gidn_groups)} value(s)"
        )
    for req, labels in missing_group.items():
        if labels:
            critical.append(f"Groups missing {req}: {len(labels)}")

    # --- structure ---
    all_dns = [first(e, "dn") for e in source if first(e, "dn")]
    ou_dns = sorted({first(e, "dn") for e in ou_entries if first(e, "dn")})
    if not ou_dns:
        ou_dns = sorted(
            {dn for dn in all_dns if dn.lower().startswith("ou=")},
            key=str.lower,
        )

    def children_of(parent: str) -> list[str]:
        pl = parent.lower()
        kids = []
        for dn in all_dns:
            if parent_dn(dn).lower() == pl:
                kids.append(dn)
        return kids

    empty_ous: list[str] = []
    unknown_ous: list[str] = []
    for ou in ou_dns:
        if not children_of(ou):
            empty_ous.append(ou)
        name = rdn_value(ou_rdn(ou)).lower()
        if name not in COMMON_OUS:
            unknown_ous.append(ou)

    # Application-ish containers / entries
    app_ous = [
        ou
        for ou in ou_dns
        if rdn_value(ou_rdn(ou)).lower() in ("config", "services", "apps", "application")
    ]
    app_entries = []
    for e in source:
        dn = first(e, "dn").lower()
        uid = first(e, "uid").lower()
        if any(x in dn for x in (",ou=config,", ",ou=services,", ",ou=apps,")):
            app_entries.append(first(e, "dn"))
        elif uid in ("counters", "counter") or uid.endswith("app"):
            app_entries.append(first(e, "dn"))

    # --- objectClass / attrs ---
    all_ocs: dict[str, int] = defaultdict(int)
    all_attrs: dict[str, int] = defaultdict(int)
    attr_user_hits: dict[str, int] = defaultdict(int)
    for e in source:
        for oc in all_vals(e, "objectClass"):
            all_ocs[oc] += 1
        for attr in e:
            all_attrs[attr] += 1
            if is_user(e):
                attr_user_hits[attr.lower()] += 1

    migratable_found = sorted(
        oc for oc in all_ocs if oc.lower() in {x.lower() for x in MIGRATABLE_OCS}
    )
    review_found = sorted(
        oc for oc in all_ocs if oc.lower() in {x.lower() for x in REVIEW_OCS}
    )
    custom_ocs = sorted(
        oc
        for oc in all_ocs
        if oc.lower()
        not in {x.lower() for x in MIGRATABLE_OCS | REVIEW_OCS | {"top"}}
    )

    custom_attrs = sorted(
        a
        for a in all_attrs
        if a.lower() not in STANDARD_ATTRS and a.lower() != "dn"
    )

    # Objects migrate-ds will not bring over as-is
    not_migrated = []
    for oc in sorted(set(review_found) | set(custom_ocs)):
        not_migrated.append(f"objectClass {oc} ({all_ocs[oc]} entries)")
    for a in custom_attrs:
        if a.lower() in CUSTOM_ATTR_HINTS or a.lower() == "hostaccess":
            not_migrated.append(f"attribute {a} ({all_attrs[a]} occurrences)")
    if sudo_rules:
        not_migrated.append(
            f"sudoRole rules ({len(sudo_rules)}) — migrate with ipa_remap_access.py"
        )

    uid_min = min(uid_nums) if uid_nums else None
    uid_max = max(uid_nums) if uid_nums else None
    gid_min = min(gid_nums) if gid_nums else None
    gid_max = max(gid_nums) if gid_nums else None

    # --- traffic light ---
    ok_items: list[str] = []
    warn_items: list[str] = []
    err_items: list[str] = []

    for oc in ("inetOrgPerson", "posixAccount", "posixGroup"):
        if any(k.lower() == oc.lower() for k in all_ocs):
            ok_items.append(oc)
    if sudo_rules:
        warn_items.append(f"sudoRole ({len(sudo_rules)} rules — migrate separately)")
    for oc in review_found:
        warn_items.append(oc)
    for oc in custom_ocs:
        warn_items.append(oc)
    for a in custom_attrs:
        warn_items.append(a)
    if dup_uid:
        err_items.append(f"uid duplicates ({len(dup_uid)})")
    if dup_uidn:
        err_items.append(f"uidNumber duplicates ({len(dup_uidn)})")
    if dup_gidn_groups:
        err_items.append(f"gidNumber duplicates across groups ({len(dup_gidn_groups)})")
    for req, labels in missing_user.items():
        if labels:
            err_items.append(f"POSIX users missing {req} ({len(labels)})")
    for req, labels in missing_group.items():
        if labels:
            err_items.append(f"Groups missing {req} ({len(labels)})")

    # --- action plan ---
    def status_ok() -> str:
        return "OK"

    def status_warn() -> str:
        return "REVIEW"

    def status_err() -> str:
        return "ERROR"

    actions: list[tuple[str, str, str]] = []
    actions.append(
        (
            "POSIX users",
            status_err() if (dup_uid or dup_uidn or missing_user) else status_ok(),
            "Migrate with ipa migrate-ds"
            if not (dup_uid or dup_uidn or missing_user)
            else "Resolve blockers, then migrate with ipa migrate-ds",
        )
    )
    actions.append(
        (
            "POSIX groups",
            status_err() if (dup_gidn_groups or dup_cn or missing_group) else status_ok(),
            "Migrate with ipa migrate-ds"
            if not (dup_gidn_groups or dup_cn or missing_group)
            else "Resolve group blockers, then migrate with ipa migrate-ds",
        )
    )
    actions.append(
        (
            "SUDO rules",
            status_warn() if sudo_rules else status_ok(),
            "Migrate separately via ipa_remap_access.py --sudo"
            if sudo_rules
            else "None detected",
        )
    )
    if review_found or service_rows:
        n_ok = sum(1 for r in service_rows if r["status"] == "OK")
        n_rev = sum(1 for r in service_rows if r["status"] == "REVIEW")
        actions.append(
            (
                "LDAP service / bind accounts",
                status_warn() if service_rows else status_ok(),
                (
                    f"{n_ok} OK → sysaccount; {n_rev} REVIEW "
                    "(see §8). Exclude OK from migrate-ds user path; "
                    "create after migrate-ds (ipa sysaccount-add)."
                    if service_rows
                    else "None"
                ),
            )
        )
    if any(o.lower() == "specialattributes" for o in custom_ocs):
        actions.append(
            (
                "specialAttributes",
                status_warn(),
                "Ignore on migrate-ds (--*-ignore-objectclass); remap hostAccess → HBAC",
            )
        )
    if any(a.lower() == "hostaccess" for a in custom_attrs):
        actions.append(
            (
                "hostAccess",
                status_warn(),
                "Not in stock FreeIPA; ignore on migrate-ds; remap with ipa_remap_access.py",
            )
        )
    if dup_uidn:
        actions.append(
            (
                "uidNumber duplicates",
                status_err(),
                "Resolve before migration (each uidNumber must be unique)",
            )
        )
    if dup_uid:
        actions.append(
            (
                "uid duplicates",
                status_err(),
                "Resolve before migration (each uid must be unique)",
            )
        )
    if dup_gidn_groups:
        actions.append(
            (
                "gidNumber duplicates between groups",
                status_err(),
                "Resolve before migration (two groups must not share gidNumber)",
            )
        )
    if no_password:
        actions.append(
            (
                "Entries without userPassword",
                status_warn(),
                "Classify (user / technical / application); plan bind secrets or IPA passwords",
            )
        )
    if app_ous or app_entries:
        actions.append(
            (
                "Application objects (ou=Config/Services, …)",
                status_warn(),
                "Usually stay outside IdM or are recreated per application — do not expect migrate-ds",
            )
        )

    has_critical = bool(critical)

    # ========== REPORT ==========
    lines: list[str] = []
    lines.append("===== 1. GENERAL SUMMARY =====")
    lines.append(f"BASE DN: {base_dn or '(not detected — check namingContexts.ldif)'}")
    lines.append("")
    lines.append(f"Entries.............{len(source)}")
    lines.append(f"POSIX users.........{len(posix_users)}")
    lines.append(f"POSIX groups........{len(posix_groups)}")
    lines.append(f"SUDO roles..........{len(sudo_rules)}")
    lines.append(f"OUs.................{len(ou_dns)}")
    lines.append(f"Service accounts....{len(service_rows)}")

    lines.append(
        f"Overall status......{'FAIL (exit 1)' if has_critical else 'OK (exit 0)'}"
    )
    if uid_min is not None:
        lines.append(f"uidNumber range.....{uid_min} .. {uid_max}")
    if gid_min is not None:
        lines.append(f"gidNumber range.....{gid_min} .. {gid_max}")
    lines.append("")

    lines.append("===== 2. LDAP STRUCTURE =====")
    if base_dn:
        lines.append(base_dn)
        # Direct OU children of base
        direct = [
            ou
            for ou in ou_dns
            if parent_dn(ou).lower() == base_dn.lower()
        ]
        if not direct:
            direct = ou_dns
        for i, ou in enumerate(sorted(direct, key=str.lower)):
            branch = "└──" if i == len(direct) - 1 else "├──"
            lines.append(f" {branch} {ou_rdn(ou)}")
    else:
        for ou in ou_dns:
            lines.append(f"  {ou}")
    lines.append("")
    lines.append("Empty OUs:")
    if empty_ous:
        for ou in empty_ous:
            lines.append(f"  {ou}")
    else:
        lines.append("  (none)")
    lines.append("Unknown / uncommon OUs:")
    if unknown_ous:
        for ou in unknown_ous:
            lines.append(f"  {ou}")
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append("===== 3. OBJECTCLASS =====")
    lines.append("--- Migratable ---")
    if migratable_found:
        for oc in migratable_found:
            lines.append(f"  {all_ocs[oc]:5d}  {oc}")
    else:
        lines.append("  (none)")
    lines.append("--- Review ---")
    if review_found:
        for oc in review_found:
            lines.append(f"  {all_ocs[oc]:5d}  {oc}")
    else:
        lines.append("  (none)")
    lines.append("--- Custom / other ---")
    if custom_ocs:
        for oc in custom_ocs:
            lines.append(f"  {all_ocs[oc]:5d}  {oc}")
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append("===== 4. CUSTOM ATTRIBUTES =====")
    if not custom_attrs:
        lines.append("(none beyond standard POSIX / inetOrgPerson / sudo set)")
    else:
        for a in custom_attrs:
            lines.append(f"CUSTOM ATTRIBUTE: {a}")
            lines.append(f"  Occurrences........{all_attrs[a]}")
            if a.lower() in attr_user_hits:
                lines.append(f"  Appears on users...{attr_user_hits[a.lower()]}")
            lines.append("  Must be reviewed before migrate-ds")
            lines.append("")
    lines.append("")

    lines.append("===== 5. DUPLICATE uid / uidNumber =====")
    lines.append("--- Duplicate uid ---")
    if not dup_uid:
        lines.append("(none)")
    else:
        for uid, ents in sorted(dup_uid.items()):
            lines.append(f"DUPLICATE UID: {uid}")
            for e in ents:
                lines.append(
                    f"    {first(e, 'uid') or '(missing)'}  "
                    f"uidNumber={first(e, 'uidNumber') or '(missing)'}  "
                    f"dn={first(e, 'dn')}"
                )
            lines.append("")
    lines.append("--- Duplicate uidNumber ---")
    if not dup_uidn:
        lines.append("(none)")
    else:
        for num, ents in sorted(
            dup_uidn.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0
        ):
            lines.append(f"DUPLICATE UIDNUMBER: {num}")
            for e in ents:
                lines.append(
                    f"    {first(e, 'uid') or '(missing)'}  dn={first(e, 'dn')}"
                )
            lines.append("")
    lines.append("")

    lines.append("===== 6. GID ANALYSIS =====")
    lines.append(
        "Note: many users sharing a primary gidNumber with one group is normal."
    )
    lines.append(
        "ERROR only when two different groups share the same gidNumber."
    )
    lines.append("")
    lines.append("--- Group gidNumber → primary-gid user count (sample) ---")
    shown = 0
    for gidn, gents in sorted(
        by_gidn.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0
    ):
        if shown >= 30:
            lines.append(f"  … {len(by_gidn) - shown} more groups omitted")
            break
        cn = first(gents[0], "cn")
        nusers = len(users_by_primary_gid.get(gidn, []))
        lines.append(f"gidNumber {gidn}")
        lines.append(f"  Group: {cn}")
        lines.append(f"  Users with this primary gidNumber: {nusers}")
        shown += 1
    lines.append("")
    lines.append("--- Duplicate gidNumber across GROUPS (ERROR) ---")
    if not dup_gidn_groups:
        lines.append("(none)")
    else:
        for num, ents in sorted(
            dup_gidn_groups.items(),
            key=lambda x: int(x[0]) if x[0].isdigit() else 0,
        ):
            lines.append(f"DUPLICATE GIDNUMBER BETWEEN GROUPS: {num}")
            for e in ents:
                lines.append(f"    cn={first(e, 'cn')}  dn={first(e, 'dn')}")
            lines.append("")
    lines.append("")

    lines.append("===== 7. USERS WITHOUT PASSWORD =====")
    if not no_password:
        lines.append("(none)")
    else:
        by_class: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for label, klass, dn in no_password:
            by_class[klass].append((label, dn))
        for klass in ("user", "technical", "application"):
            items = by_class.get(klass, [])
            lines.append(f"--- {klass} ({len(items)}) ---")
            if not items:
                lines.append("(none)")
            else:
                for label, dn in items[:40]:
                    lines.append(f"  {label}  NO userPassword  dn={dn}")
                if len(items) > 40:
                    lines.append(f"  … and {len(items) - 40} more")
        lines.append("")
    if password_notes:
        lines.append("Password / Kerberos notes:")
        for p in password_notes[:40]:
            lines.append(f"  {p}")
        if len(password_notes) > 40:
            lines.append(f"  … and {len(password_notes) - 40} more")
    lines.append("")

    lines.append("===== 8. LDAP SERVICE ACCOUNTS =====")
    lines.append(
        "Candidates for IdM System Accounts (ipa sysaccount-add)."
    )
    lines.append(
        "OK = recreate as sysaccount / exclude from migrate-ds as user. "
        "REVIEW = confirm with owners."
    )
    lines.append("")
    if not service_rows:
        lines.append("(none detected)")
    else:
        for r in service_rows:
            lines.append(f"  [{r['status']}] {r['name']}")
            lines.append(f"    dn: {r['dn']}")
            lines.append(f"    objectClass: {r['objectClass']}")
            lines.append(f"    posix: {r['posix']}")
            lines.append(f"    reasons: {r['reasons']}")
            lines.append(f"    action: {r['action']}")
        lines.append("")
        lines.append(
            "Next: after migrate-ds, create OK accounts with ipa sysaccount-add; "
            "update app bind DNs to uid=<name>,cn=sysaccounts,cn=etc,<basedn>."
        )
        lines.append(
            "Plan/apply tooling for sysaccounts is a separate post-migrate step "
            "(parallel to HBAC remap)."
        )
    lines.append("")

    lines.append("===== 9. NOT MIGRATED BY ipa migrate-ds =====")
    if not not_migrated:
        lines.append("(nothing obvious beyond standard users/groups)")
    else:
        for item in not_migrated:
            lines.append(f"  - {item}")
    lines.append("")

    lines.append("===== 10. APPLICATION OBJECTS =====")
    if not app_ous and not app_entries:
        lines.append("(none detected)")
    else:
        if app_ous:
            lines.append("Containers:")
            for ou in app_ous:
                lines.append(f"  {ou}")
        if app_entries:
            lines.append("Entries (sample):")
            for dn in sorted(set(app_entries))[:40]:
                lines.append(f"  {dn}")
            if len(set(app_entries)) > 40:
                lines.append(f"  … and {len(set(app_entries)) - 40} more")
    lines.append("")

    lines.append("===== 11. POSIX USERS (required attrs) =====")
    if not missing_user:
        lines.append("All analyzed posixAccount entries have uid, uidNumber,")
        lines.append("gidNumber, homeDirectory, loginShell.")
    else:
        for req, labels in sorted(missing_user.items()):
            lines.append(f"Missing {req} ({len(labels)}):")
            for d in labels[:25]:
                lines.append(f"  {d}")
            if len(labels) > 25:
                lines.append(f"  … and {len(labels) - 25} more")
    lines.append("")

    lines.append("===== 12. GROUPS =====")
    if not missing_group and not dup_gidn_groups and not dup_cn:
        lines.append(
            f"OK — {len(posix_groups)} posixGroup entries with cn + gidNumber; "
            "no gidNumber clashes between groups."
        )
    else:
        for req, labels in sorted(missing_group.items()):
            lines.append(f"Missing {req} ({len(labels)}):")
            for d in labels[:25]:
                lines.append(f"  {d}")
        if dup_cn:
            lines.append(f"Duplicate cn: {len(dup_cn)}")
        if dup_gidn_groups:
            lines.append(f"Duplicate gidNumber between groups: {len(dup_gidn_groups)}")
    lines.append("")

    lines.append("===== 13. SUDO =====")
    lines.append(f"sudoRole rules: {len(sudo_rules)}")
    if any(first(e, "cn").lower() == "defaults" for e in sudo_entries):
        lines.append("(cn=defaults present — review separately)")
    lines.append("")

    lines.append("===== 14. FREEIPA COMPATIBILITY =====")
    lines.append("OK")
    if ok_items:
        for i in ok_items:
            lines.append(f"  ✔ {i}")
    else:
        lines.append("  (no core migratable OCs found)")
    lines.append("REVIEW")
    if warn_items:
        for i in warn_items:
            lines.append(f"  ⚠ {i}")
    else:
        lines.append("  (none)")
    lines.append("ERROR")
    if err_items:
        for i in err_items:
            lines.append(f"  ✘ {i}")
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append("===== 15. ACTION PLAN =====")
    col_w = max(len(a[0]) for a in actions) if actions else 10
    lines.append(f"{'Element':<{col_w}}  {'Status':<8}  Action")
    lines.append(f"{'-' * col_w}  {'-' * 8}  {'-' * 40}")
    for elem, st, act in actions:
        lines.append(f"{elem:<{col_w}}  {st:<8}  {act}")
    lines.append("")
    lines.append("Engagement order (AD trust lab — see repo README):")
    lines.append("  1. Collect OpenLDAP export (docs/01-openldap-lab.md §5)")
    lines.append("  2. Run this validator; fix ERROR items; decide §8 REVIEW accounts")
    lines.append("  3. Import people into AD, install IdM, establish trust")
    lines.append("     (docs/02-ad-lab.md, 03-idm-lab.md, 04-ad-trust.md)")
    lines.append("  4. Map POSIX/HBAC/sudo (docs/05-mapping.md) — do not ipa migrate-ds")
    lines.append("")

    return "\n".join(lines) + "\n", has_critical


OUTPUT_DIR_DEFAULT = Path("analyze_source.d")
OUTPUT_PREFIX = "analyze_source_"


def default_report_path() -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return OUTPUT_DIR_DEFAULT / f"{OUTPUT_PREFIX}{stamp}.txt"


def resolve_collection(
    dirpath: Path,
) -> tuple[Path | None, Path | None, Path | None, Path | None, Path | None]:
    """Return (users, groups, tree, sudo, slapcat) paths that exist."""
    users = dirpath / "ldap-users.ldif"
    groups = dirpath / "ldap-groups.ldif"
    tree = dirpath / "ldap-tree.ldif"
    sudo = dirpath / "sudo-rules.ldif"
    slapcat = dirpath / "openldap-export.ldif"
    return (
        users if users.is_file() else None,
        groups if groups.is_file() else None,
        tree if tree.is_file() else None,
        sudo if sudo.is_file() else None,
        slapcat if slapcat.is_file() else None,
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--users", type=Path, help="ldap-users.ldif")
    p.add_argument("--groups", type=Path, help="ldap-groups.ldif")
    p.add_argument(
        "--tree",
        type=Path,
        help="ldap-tree.ldif from ldapsearch (optional; overridden by --slapcat)",
    )
    p.add_argument(
        "--slapcat",
        type=Path,
        metavar="LDIF",
        help=(
            "Full DIT from slapcat (typically openldap-export.ldif). "
            "Preferred over --tree when both are set."
        ),
    )
    p.add_argument("--sudo", type=Path, help="sudo-rules.ldif (optional)")
    p.add_argument(
        "--collection-dir",
        type=Path,
        help=(
            "Directory with ldap-users/groups/tree/sudo-rules.ldif "
            "and/or openldap-export.ldif"
        ),
    )
    p.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help=(
            f"Report path (default: {OUTPUT_DIR_DEFAULT}/"
            f"{OUTPUT_PREFIX}YYYYMMDD_HHMMSS.txt)"
        ),
    )
    args = p.parse_args(argv)

    users_path, groups_path, tree_path, sudo_path, slapcat_path = (
        args.users,
        args.groups,
        args.tree,
        args.sudo,
        args.slapcat,
    )
    if args.collection_dir:
        cu, cg, ct, cs, cx = resolve_collection(args.collection_dir)
        users_path = users_path or cu
        groups_path = groups_path or cg
        tree_path = tree_path or ct
        sudo_path = sudo_path or cs
        slapcat_path = slapcat_path or cx

    # slapcat dump is the richest full-DIT source when available
    dit_path = slapcat_path or tree_path
    dit_label = None
    if slapcat_path:
        dit_label = f"slapcat:{slapcat_path}"
    elif tree_path:
        dit_label = f"tree:{tree_path}"

    if not users_path and not groups_path and not dit_path:
        p.error(
            "Provide --users/--groups/--tree/--slapcat and/or --collection-dir"
        )

    users = LDIFParser.parse_file(users_path) if users_path else []
    groups = LDIFParser.parse_file(groups_path) if groups_path else []
    tree = LDIFParser.parse_file(dit_path) if dit_path else []
    sudo = LDIFParser.parse_file(sudo_path) if sudo_path else []

    if dit_label:
        print(f"DIT source: {dit_label}", file=sys.stderr)

    if tree and not users:
        users = [e for e in tree if is_user(e)]
    if tree and not groups:
        groups = [e for e in tree if is_group(e)]
    if tree and not sudo:
        sudo = [e for e in tree if is_sudo(e)]

    report, critical = analyze(users, groups, tree, sudo)
    out_path = args.output if args.output is not None else default_report_path()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")
    print(report)
    print(f"Wrote: {out_path.resolve()}", file=sys.stderr)
    return 1 if critical else 0


if __name__ == "__main__":
    sys.exit(main())
