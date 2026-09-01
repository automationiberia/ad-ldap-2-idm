# 09 — OpenLDAP export attribute mapping

**Phase 4 — Mapping reference.** How attributes found in a typical **last OpenLDAP LDIF export** map to **AD (identity)** and **IdM (Linux policy + POSIX overrides)** under the **AD trust** path.

This document is **customer-agnostic**: counts and attribute presence vary per estate. Use `analyze_source_ldif.py` on the engagement export to confirm what your source actually contains.

Related:


| Doc / tool                       | Role                                 |
| -------------------------------- | ------------------------------------ |
| `analyze_source_ldif.py`         | Pre-migration inventory and blockers |
| `ipa_bootstrap_trust_catalog.py` | LDIF → `trust_catalog.d/`            |
| `ipa_trust_overrides.py`         | POSIX ID overrides                   |
| `ipa_remap_trust_policy.py`      | External groups, HBAC, sudo          |


---



## Legend

**In AD**


| Value   | Meaning                                                                 |
| ------- | ----------------------------------------------------------------------- |
| Yes     | Native or RFC2307 attribute on AD user/group                            |
| Carrier | Stored on a different AD attribute (e.g. `labeledURI` for access hints) |
| No      | Not in AD                                                               |


**IdM mechanism**


| Mechanism              | Meaning                                           |
| ---------------------- | ------------------------------------------------- |
| ID Override            | `ipa idoverrideuser-*` in Default Trust View      |
| External + POSIX group | `ipa group-add --external` + nested POSIX wrapper |
| HBAC + hostgroup       | `ipa hbacrule-*`, `ipa hostgroup-*`               |
| sudorule               | `ipa sudorule-*`, `ipa sudocmd-*`                 |
| AD trust (inherited)   | From trusted AD object; no IdM LDAP copy          |
| Not migrated           | Retired with OpenLDAP; no IdM equivalent required |


---



## Quick reference

```text
OpenLDAP export                    AD (identity)              IdM (Linux)
─────────────────────────────────  ─────────────────────────  ─────────────────────────────
uid, cn, sn                        sAMAccountName, cn, sn     ID Override: login (--login)
uidNumber, gidNumber, home, shell  RFC2307 (optional)         ID Override: uidnumber, gidnumber,
                                                              homedirectory, loginshell, gecos
userPassword {SASL}user@realm       Kerberos                   ad_user_principal (bootstrap only)
memberUid / posixGroup cn          group + member             External group + POSIX wrapper
hostAccess (custom)                labeledURI (optional)      HBAC + hostgroups
sudoRole / sudo*                   —                          sudorule + sudocmd
ou, dc, entryUUID, CSN, …          —                          (not migrated)
```

---



## Identity and POSIX (users)

Source: `posixAccount` (and person object classes) in `ou=People` (or equivalent).


| Attribute       | On users | In AD                          | IdM                                 | Script / artifact                                           | Notes                                              |
| --------------- | -------- | ------------------------------ | ----------------------------------- | ----------------------------------------------------------- | -------------------------------------------------- |
| `uid`           | ✓        | Yes (`sAMAccountName`)         | ID Override `--login`               | `user-overrides.csv` → `ipa_trust_overrides.py`             | Linux login name                                   |
| `uidNumber`     | ✓        | Optional RFC2307               | ID Override `--uid` / `--uidnumber` | same                                                        | Must stay stable for NFS/files                     |
| `gidNumber`     | ✓        | Optional RFC2307               | ID Override `--gid` / `--gidnumber` | same                                                        | Primary GID                                        |
| `homeDirectory` | ✓        | Optional (`unixHomeDirectory`) | ID Override `--homedir`             | same                                                        |                                                    |
| `loginShell`    | ✓        | Optional RFC2307               | ID Override `--shell`               | same                                                        | Bootstrap defaults missing values to `/bin/bash`   |
| `gecos`         | ✓        | No                             | ID Override `--gecos`               | same                                                        | Optional; may be empty in source                   |
| `cn`            | ✓        | Yes                            | AD trust                            | —                                                           | Override uses `login` from `uid` unless CSV edited |
| `sn`            | ✓        | Yes                            | AD trust                            | —                                                           | Not copied to IdM                                  |
| `userPassword`  | ✓        | Yes (Kerberos)                 | **Not migrated**                    | Bootstrap extracts `{SASL}user@realm` → `ad_user_principal` | Auth via AD trust                                  |


**Bootstrap columns** (`user-overrides.csv`): `openldap_uid`, `ad_user_principal`,
`login`, `uid_number`, `gid_number`, `home_directory`, `login_shell`, `gecos`.

**Validation:** `getent passwd user@REALM` shows override values; `ipa idoverrideuser-show`.

---



## Groups

Source: `posixGroup` in `ou=Groups`.


| Attribute    | On groups | In AD                  | IdM                               | Script / artifact                                   | Notes                                                   |
| ------------ | --------- | ---------------------- | --------------------------------- | --------------------------------------------------- | ------------------------------------------------------- |
| `cn`         | ✓         | Yes                    | External + POSIX wrapper names    | `group-crosswalk.csv`                               | `openldap_group_cn`                                     |
| `gidNumber`  | ✓         | Optional               | POSIX wrapper `--gid=`            | crosswalk `gid_number`                              | Legacy GID for NFS                                      |
| `memberUid`  | ✓         | Yes (`member`)         | **Not copied** — membership in AD | Crosswalk + trust                                   | Validate AD group members vs OpenLDAP in pre-transition |
| `hostAccess` | ✓         | Carrier (`labeledURI`) | HBAC + hostgroups                 | `policy-catalog.json` → `ipa_remap_trust_policy.py` | Custom attr; not stored in IdM LDAP                     |


**Crosswalk columns:** `openldap_group_cn`, `ad_group`, `idm_external_cn`, `idm_posix_wrapper_cn`, `gid_number`.

External group: `--external=DOMAIN\ad_group`. POSIX wrapper nests external group; HBAC/sudo target the **wrapper**, not `_ext`.

---



## Per-user `hostAccess` (exceptions)

Some estates attach `hostAccess` directly to **user** entries (not only groups).


| Stage              | Behavior                                                        |
| ------------------ | --------------------------------------------------------------- |
| Bootstrap          | Rows in `policy-catalog.json` → `user_host_access_exceptions[]` |
| Review output      | `user-host-access-review.csv` + stdout table from bootstrap     |
| Apply (trust path) | **Not automated** — review each row in engagement               |
| Recommended        | Map user to AD group + wrapper, or explicit HBAC exception      |


Document decisions in the transition runbook ([15](15-transition-runbook.md)).

---

## Sudo (`ou=SUDOers`)

Source: `sudoRole` entries (`sudo-rules.ldif` or subtree export).


| Attribute                     | On sudo | In AD         | IdM                                                  | Script                          | Notes                                                                                   |
| ----------------------------- | ------- | ------------- | ---------------------------------------------------- | ------------------------------- | --------------------------------------------------------------------------------------- |
| `cn`                          | ✓       | No            | sudorule name derived from `%group` or `openldap_cn` | catalog `openldap_cn`           | IdM name: `sudo_<group>` when single `%group` subject                                   |
| `description`                 | ✓       | Yes (general) | `--desc=` on `sudorule-add`                          | catalog                         |                                                                                         |
| `sudoUser`                    | ✓       | No            | `--usercat=all` / `--groups=`                        | `sudorule_cmds_for_catalog_row` | Trust path: `%group` **only** (POSIX wrapper); `ALL` and named users logged and skipped |
| `sudoHost`                    | ✓       | No            | hostgroup / `--hostcat=all`                          | same                            | `ALL` → `all_hosts` bundle                                                              |
| `sudoCommand`                 | ✓       | No            | `ipasudocmd` + allow / `--cmdcat=all`                | same                            | Empty in LDIF → treated as `ALL`                                                        |
| `sudoRunAsUser` / `sudoRunAs` | ✓       | No            | `--runasusercat` / `--users=`                        | same                            |                                                                                         |
| `sudoOption`                  | ✓       | No            | `--sudooption=`                                      | same                            | e.g. `!authenticate`                                                                    |
| `sudoNotBefore`               | ✓       | No            | `--setattr=sudonotbefore=`                           | same                            | GeneralizedTime normalized                                                              |
| `sudoNotAfter`                | ✓       | No            | `--setattr=sudonotafter=`                            | same                            |                                                                                         |
| `sudoOrder`                   | ✓       | No            | `--order=` on sudorule                               | catalog `sudo_order`            | Rule evaluation priority                                                                |


`cn=defaults` is skipped (OpenLDAP sudo defaults — not a migratable rule).

---

## Directory structure and operational metadata


| Attribute               | In AD               | IdM                        | Action                               |
| ----------------------- | ------------------- | -------------------------- | ------------------------------------ |
| `ou`                    | Yes                 | Not migrated               | IdM has its own tree                 |
| `dc`                    | Yes                 | Not migrated               | IdM realm/DNS is separate            |
| `objectClass`           | Yes (different set) | Per entry type — see below | Mapping is by semantics, not OC copy |
| `structuralObjectClass` | Yes                 | Not migrated as attr       | Used in analysis only                |
| `creatorsName`          | No                  | Not migrated               | LDAP audit                           |
| `createTimestamp`       | Yes (`whenCreated`) | Not migrated               | AD has own timestamps                |
| `modifiersName`         | No                  | Not migrated               | LDAP audit                           |
| `modifyTimestamp`       | Yes (`whenChanged`) | Not migrated               | AD has own timestamps                |




### slapd operational metadata (not identity, not Linux policy)

OpenLDAP generates these for **internal directory operation** (replication,
stable entry IDs). They do not describe people, groups, or access. Drop them at
cutover; AD and IdM already have their own IDs and change tracking.


| Attribute    | What                       | OpenLDAP use                                    | Why not migrated                        |
| ------------ | -------------------------- | ----------------------------------------------- | --------------------------------------- |
| `entryUUID`  | Stable per-entry UUID      | Identify an entry if the DN changes; sync tools | AD GUID / IdM `ipaUniqueID` replace it  |
| `entryCSN`   | Per-entry change sequence  | Multi-master / replica conflict order           | Only valid inside that OpenLDAP cluster |
| `contextCSN` | Suffix / DB CSN (DIT root) | How far the `dc=…` replica is in sync           | Same as `entryCSN`, directory-wide      |


Trust cutover uses overrides + HBAC + sudorule — copying CSNs or UUIDs adds nothing.

### Object classes (typical export)


| objectClass                                   | IdM handling                                             |
| --------------------------------------------- | -------------------------------------------------------- |
| `posixAccount`                                | POSIX via ID Overrides (Model C) or AD RFC2307 (Model B) |
| `inetOrgPerson` / `person`                    | AD trust                                                 |
| `shadowAccount`                               | Ignored if no `shadow*` values                           |
| `specialAttributes` (custom)                  | Ignore OC — remap `hostAccess` to HBAC                   |
| `posixGroup`                                  | External + POSIX wrapper                                 |
| `sudoRole`                                    | sudorule                                                 |
| `organizationalUnit`                          | Not migrated                                             |
| `organizationalRole` / `simpleSecurityObject` | Review — often bind/service; usually not Linux users     |
| `domain`                                      | Not migrated                                             |


---

## AD `labeledURI` (optional carrier)

When access metadata lives on **AD** as `labeledURI` instead of (or in addition
to) OpenLDAP `hostAccess`:


| Phase          | Approach                                                                                 |
| -------------- | ---------------------------------------------------------------------------------------- |
| Pre-transition | Inventory in [04](04-pre-migration.md)                                                   |
| Transition     | Convert to **catalog rows** (same shape as `hostAccess` bootstrap)                       |
| Steady state   | Prefer IdM catalog in git ([12 §5](12-ad-trust-migration.md#5-labeleduri--groups--hbac)) |


Scripts read the **JSON catalog + CSV crosswalk**, not LSC at runtime.

---

## Coverage matrix (scripts)


| Attribute group        | Bootstrap                        | Apply                       |
| ---------------------- | -------------------------------- | --------------------------- |
| POSIX user attrs       | `ipa_bootstrap_trust_catalog.py` | `ipa_trust_overrides.py`    |
| `{SASL}` principal     | bootstrap                        | match scripts if gap        |
| Group `hostAccess`     | bootstrap                        | `ipa_remap_trust_policy.py` |
| User `hostAccess`      | bootstrap (exceptions list)      | manual / engagement         |
| `memberUid`            | crosswalk groups only            | trust (AD membership)       |
| `sudo*` (incl. order)  | bootstrap                        | `ipa_remap_trust_policy.py` |
| Operational LDAP attrs | `analyze_source_ldif.py`         | —                           |


---



## Known trust-path limitations

Document and resolve in the engagement workbook:

1. `sudoUser` **not** `%group` — named users and `ALL` are not auto-mapped; design AD group or manual sudorule.
2. **Per-user** `hostAccess` — inventoried but not applied by `ipa_remap_trust_policy.py`.
3. `cn` **vs** `uid` — override login defaults to `uid`; edit CSV if they differ.
4. **Hostgroup derivation** — hostnames map to bundles by prefix (`db`* → `hg_database`, …); customize `derive_hostgroup_name()` in `ipa_lib.py` if naming differs.

---



## Pre-migration inventory command

```bash
python3 freeipa/migration/analyze_source_ldif.py \
  --users /path/to/ldap-users.ldif \
  --groups /path/to/ldap-groups.ldif \
  --sudo /path/to/sudo-rules.ldif \
  --report /tmp/pre-migration-report.txt
```

Confirm every attribute class you need appears in the report before bootstrap.