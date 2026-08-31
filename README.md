# OpenLDAP + AD → IdM lab

Lab: one-way AD → IdM trust. OpenLDAP POSIX, hostAccess and sudo mapped as ID Overrides, HBAC and sudorule. Copyleft GPL-3.0-or-later.

Lab for the **target operating model**: Active Directory holds users, passwords, and group membership; Red Hat IdM holds Linux policy (HBAC, sudo, hostgroups) and POSIX via **ID Overrides**. A **one-way AD trust** replaces the current OpenLDAP + LSC path: IdM trusts AD, so AD users can log in to Linux. IdM users cannot access AD.

```text
TODAY                              TARGET
AD ──LSC──► OpenLDAP               AD ──── Trust ────► IdM
              │                                         ├─ ID Overrides (uid/gid/home/shell)
              ├─ POSIX                                  ├─ External groups + POSIX wrappers
              ├─ hostAccess                             ├─ HBAC
              └─ sudoRole                               └─ sudorule
```
---

## Why each phase exists

| Phase | What you stand up | Why |
|-------|-------------------|-----|
| **1. Lab** | OpenLDAP, AD, IdM | Reproduce today’s directory, the future identity store, and the Linux policy engine as three separate systems |
| **2. Trust** | `ipa-adtrust-install` + `ipa trust-add` | Kerberos and group membership must flow from AD **before** any mapping. Mapping without trust has nowhere to attach |
| **3. Mapping** | ID Overrides + External groups + HBAC/sudo | OpenLDAP still owns POSIX and `hostAccess`/sudo. Scripts copy that **policy** onto trusted AD users — they do not copy users |
| **4. Legacy enrollment** | RHEL 6.10 `ipa-client-install` | Prove a legacy client can resolve AD users through IdM SSSD and obey HBAC |

Work the phases in order. Trust before mapping. Mapping before expecting POSIX uids from OpenLDAP. Enrollment before SSH/HBAC tests.

---

## Lab names

| Role | Value |
|------|--------|
| OpenLDAP domain / bind | `dc=bcnconsulting,dc=com` · `cn=admin,dc=bcnconsulting,dc=com` / `redhat00` |
| OpenLDAP host URI | `ldap://127.0.0.1:1389` (container `ldap://127.0.0.1:389`) |
| AD forest | `win.iam.lab` · NetBIOS `WIN` · realm `WIN.IAM.LAB` |
| AD lab password (imported users) | `redhat00!` |
| IdM host / realm | `idm.bcnconsulting.com` · `BCNCONSULTING.COM` · `admin` / `redhat00` |

---

## Read this in order

### 1. Install the lab

1. **[OpenLDAP](docs/01-openldap-lab.md)** — start the container, load schemas, import the enterprise LDIF, export users/groups/sudo for the later steps.
2. **[Active Directory](docs/02-ad-lab.md)** — promote the DC, then import the same users and groups with [`AD/scripts/01-import-ldap-to-ad.ps1`](AD/scripts/01-import-ldap-to-ad.ps1).
3. **[IdM](docs/03-idm-lab.md)** — install the IdM server (packages, `ipa-server-install`, `kinit admin`). Stop here; do not migrate LDAP into IdM.

### 2. Trust with IdM

4. **[AD trust](docs/04-ad-trust.md)** — DNS and time, `ipa-adtrust-install`, `ipa trust-add`, then test Kerberos, `getent`, and group resolution.

### 3. Mapping

5. **[Analyze source LDIF](docs/08-analyze-source.md)** — inventory users/groups/sudo, catch duplicate POSIX ids, then **[map](docs/05-mapping.md)** (catalog, ID Overrides, HBAC, sudo).

### 4. Legacy enrollment

6. **[RHEL 6.10 client](docs/06-legacy-enrollment.md)** — enroll a legacy host and validate login as a **trusted AD user**.

**When something fails:** [Troubleshooting](docs/07-troubleshooting.md).

**Script flags and CSV columns:** [freeipa/migration/README.md](freeipa/migration/README.md).

---

## Scripts that belong on this path

| Script | Phase | What it does |
|--------|-------|----------------|
| _(none — Podman + ldapadd)_ | 1 OpenLDAP | Container, schemas, LDIF import |
| `AD/scripts/01-import-ldap-to-ad.ps1` | 1 AD | Create AD users/groups/membership from OpenLDAP LDIFs |
| `analyze_source_ldif.py` | 3 (before bootstrap) | Inventory / blockers from OpenLDAP LDIF |
| `ipa_bootstrap_trust_catalog.py` | 3 | OpenLDAP LDIF → `trust_catalog.d/` |
| `ipa_match_ad_groups.py` / `ipa_match_ad_users.py` | 3 | Fill `ad_group` / `ad_user_principal` from an AD export |
| `ipa_trust_overrides.py` | 3 | POSIX → Default Trust View ID Overrides |
| `ipa_remap_trust_policy.py` | 3 | External group + POSIX wrapper + HBAC + sudorule |

Copy the **whole** `freeipa/migration/` directory (including `ipa_lib.py`). Do not copy a single `.py` file.

---

## License

**Copyleft** — GNU General Public License v3.0 or later
([GPL-3.0-or-later](https://spdx.org/licenses/GPL-3.0-or-later.html)).

Copyright (C) 2026 BCN Consulting Lab

You may run, study, share, and change this work. If you distribute it or a
modified version, you must do so under the same GPL terms (source included).
You may not relicense it as proprietary. Full text: [LICENSE](LICENSE).

Python helpers already carry `SPDX-License-Identifier: GPL-3.0-or-later`.

---

## What this repo is not

- There is **no Makefile** and **no** `openldap/scripts/lab_generate.py`. The enterprise LDIF is already in `openldap/bootstrap/`.
- `ipa_remap_access.py`, `ipa_suggest_idrange.py`, `ipa_delete_from_ldif.py`, and `ipa_reset_passwords.py` are **legacy `migrate-ds` tools**. They are not used after trust is the identity path. See [docs/07-troubleshooting.md](docs/07-troubleshooting.md) appendix.
