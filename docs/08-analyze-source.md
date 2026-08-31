# Analyze source LDIF (`analyze_source_ldif.py`)

Inventory the **OpenLDAP export** before you import it into AD or map it onto
IdM. The script only reads LDIF. It does **not** talk to IdM, AD, or OpenLDAP.

**Why this step:** duplicate `uid` / `uidNumber`, missing POSIX attributes, and
custom `hostAccess` will break AD import or ID Overrides. Find that on paper
before `ipa trust-add` or `--execute`.

Run it **after** [01-openldap-lab.md](01-openldap-lab.md) §5 (or an engagement
collection package) and **before** [05-mapping.md](05-mapping.md).

Script: `freeipa/migration/analyze_source_ldif.py`  
Stdlib only — no `ipa_lib.py`. Copy is still easiest as the whole
`freeipa/migration/` folder.

---

## What it answers

| Question | Report section |
|----------|----------------|
| How many users, groups, sudo rules, OUs? | §1 General summary |
| What does the DIT look like? | §2 LDAP structure |
| Which objectClasses are stock vs custom (`specialAttributes`)? | §3 |
| Custom attributes (`hostAccess`, …)? | §4 |
| Duplicate `uid` / `uidNumber`? | §5 — **ERROR**, exit 1 |
| Two groups sharing a `gidNumber`? | §6 — **ERROR** |
| Users without `userPassword` / `{SASL}` notes? | §7 |
| Bind / service accounts? | §8 |
| What `ipa migrate-ds` would drop | §9 — **ignore migrate-ds**; on this lab use mapping |
| Missing POSIX fields | §11–12 |
| Traffic light + action table | §14–15 |

Exit code **0** = no critical blockers. Exit **1** = duplicates or missing
required POSIX attributes. Warnings (`hostAccess`, sudo, service accounts) do
**not** fail the run.

On the **AD trust** path, treat ERROR the same (fix the LDIF). Treat “migrate
with `ipa migrate-ds`” in §15 as **do not** — identity stays in AD; policy is
[05-mapping.md](05-mapping.md). `hostAccess` → `ipa_remap_trust_policy.py`, not
`ipa_remap_access.py`.

---

## Inputs

Provide **at least one** of: users, groups, a full tree, or a slapcat dump.

| Flag | File | Typical source |
|------|------|----------------|
| `--users` | `ldap-users.ldif` | `ldapsearch` `ou=People` ([01](01-openldap-lab.md) §5) |
| `--groups` | `ldap-groups.ldif` | `ou=Groups` |
| `--sudo` | `sudo-rules.ldif` | `ou=SUDOers` (optional but recommended) |
| `--tree` | `ldap-tree.ldif` | `ldapsearch` of the whole DIT (optional) |
| `--slapcat` | `openldap-export.ldif` | Full DIT from `slapcat` — preferred over `--tree` |
| `--collection-dir DIR` | files named as above inside `DIR` | Engagement drop folder |
| `-o` / `--output` | report path | default `analyze_source.d/analyze_source_YYYYMMDD_HHMMSS.txt` |

`--collection-dir` looks for:

```text
ldap-users.ldif
ldap-groups.ldif
ldap-tree.ldif
sudo-rules.ldif
openldap-export.ldif
```

If a full DIT is given and `--users` / `--groups` / `--sudo` are omitted, the
script classifies entries from that dump (`posixAccount`, `posixGroup`,
`sudoRole`).

---

## Lab (after OpenLDAP export)

From the repo, with the three files from [01](01-openldap-lab.md) §5:

```bash
cd freeipa/migration

python3 analyze_source_ldif.py \
  --users /path/to/ldap-users.ldif \
  --groups /path/to/ldap-groups.ldif \
  --sudo /path/to/sudo-rules.ldif
```

The report prints to stdout and is saved under `analyze_source.d/`.

Collection directory:

```bash
python3 analyze_source_ldif.py --collection-dir /path/to/openldap_export/
```

Single slapcat file (engagement):

```bash
python3 analyze_source_ldif.py --slapcat openldap-export.ldif
```

Optional whole-tree search (if you did not split OUs):

```bash
podman exec openldap ldapsearch -x -LLL \
  -H ldap://127.0.0.1:389 \
  -D "cn=admin,dc=bcnconsulting,dc=com" -w redhat00 \
  -b "dc=bcnconsulting,dc=com" \
  > ldap-tree.ldif

python3 analyze_source_ldif.py --tree ldap-tree.ldif --sudo sudo-rules.ldif
```

---

## How to read the report (trust path)

1. Check **Overall status** in §1. `FAIL (exit 1)` → fix ERROR items before
   AD import or mapping.
2. §5 / §6: duplicate `uid`, `uidNumber`, or group `gidNumber` — the AD
   importer and ID Overrides assume uniqueness.
3. §4 / `hostAccess`: expected in this lab. Mapping turns it into HBAC
   ([05-mapping.md](05-mapping.md)); do not extend IdM schema.
4. §7 `{SASL}`: those principals can fill `ad_user_principal` at bootstrap.
   Empty `userPassword` on POSIX users: AD import still creates the account
   with the lab password; engagement accounts need a password plan in **AD**.
5. §8 service accounts: apps that bound to OpenLDAP will not bind to IdM the
   same way after cutover. Decide per account (keep on a leftover LDAP, move
   to AD, or IdM `sysaccount` only if you still use native IdM bind).
6. Skip §9/§15 lines that say `ipa migrate-ds` or `ipa_remap_access.py`.

---

## What success looks like (lab enterprise LDIF)

- Exit **0**, or only WARNINGs (`specialAttributes`, `hostAccess`, sudo).
- POSIX user/group counts close to the live `ldapsearch` counts in
  [01](01-openldap-lab.md) §4.
- No duplicate `uid` / `uidNumber` / group `gidNumber`.
- `uidNumber` / `gidNumber` ranges recorded — you will reuse those in ID
  Overrides and POSIX wrappers.

Then continue: [02-ad-lab.md](02-ad-lab.md) (import into AD) and
[05-mapping.md](05-mapping.md) (catalog + apply).

Flags also listed in [freeipa/migration/README.md](../freeipa/migration/README.md).
