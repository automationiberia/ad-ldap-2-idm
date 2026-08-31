# 1b — Active Directory lab (Windows Server 2022)

AD is the **identity authority** in the target model: users, passwords, and group membership. IdM will connect with a trust. Users are **not** copied into IdM LDAP.

**Why this step:** trust can only resolve principals that exist in AD. The PowerShell importer clones the OpenLDAP people and groups into the AD forest so Kerberos tests and External Groups have real objects.

```text
  AD                                            IdM
  users / passwords / groups  ──── Trust ──►  policy only
  (one-way: IdM trusts AD; AD users log in to Linux)
```

Do this **after** OpenLDAP is populated and **exported** ([01-openldap-lab.md](01-openldap-lab.md) §5).

---

## Sequence

1. Install Windows Server 2022 and promote a new forest
2. DNS and time (required for trust later)
3. Copy OpenLDAP LDIFs next to the importer
4. Dry-run, then import with `01-import-ldap-to-ad.ps1`
5. Confirm users, groups, and membership in AD

---

## 1. Install and promote

| Item | Lab value |
|------|-----------|
| OS | Windows Server 2022 |
| DNS name / forest | `win.iam.lab` |
| NetBIOS | `WIN` |
| Kerberos realm | `WIN.IAM.LAB` |
| Example DC hostname | `win-01rnsf8ulv3.win.iam.lab` (set `$DC` in the script) |

1. Install Windows Server 2022 (Desktop or Server Core).
2. Promote to **Domain Controller** — new forest `win.iam.lab`.
3. Enable **Active Directory module for Windows PowerShell** (RSAT / AD DS tools
   on the DC).
4. NTP: AD and IdM must stay within a few minutes of each other (Kerberos).

Optional: Identity Management for UNIX / RFC2307 attributes (`uidNumber`, `gidNumber`, `unixHomeDirectory`, `loginShell`) are in the AD schema on modern Windows. The importer writes them for Model B experiments. Mapping phase **3** still takes POSIX from OpenLDAP LDIF into IdM ID Overrides (Model C).

---

## 2. DNS (needed before trust)

| Record | Points to |
|--------|-----------|
| `idm.bcnconsulting.com` | IdM server |
| DC hostname / `win.iam.lab` | AD server |
| SRV `_ldap._tcp.win.iam.lab`, `_kerberos._tcp.win.iam.lab` | AD DC (created by promotion) |

On the AD DNS server, add a **conditional forwarder** for `bcnconsulting.com` to the IdM DNS IP. IdM will forward `win.iam.lab` the other way
([04-ad-trust.md](04-ad-trust.md)). 

Both sides must resolve each other **before** `ipa trust-add`.

---

## 3. Files for the importer

`AD/scripts/01-import-ldap-to-ad.ps1` reads **only** these two files, from the same directory as the script:

| File | Source |
|------|--------|
| `ldap-users.ldif` | Export `ou=People` ([01](01-openldap-lab.md) §5) |
| `ldap-groups.ldif` | Export `ou=Groups` |

It keeps users whose DN is `cn=…,ou=People,…` and groups whose DN is
`cn=…,ou=Groups,…` (OpenLDAP `dc=bcnconsulting,dc=com` is fine).

Edit the script header before the first run:

| Variable | Why |
|----------|-----|
| `$DC` | FQDN of your DC |
| `$UpnSuffix` | UPN suffix (`win.iam.lab`) |
| `$UsersOU` / `$GroupsOU` | Where objects are created (lab default: `CN=Users,DC=win,DC=iam,DC=lab`) |
| `$Password` | Lab password for every imported user (`redhat00!`) — used later for `kinit` |
| `$DryRun` | `$true` = report only; `$false` = write to AD |

---

## 4. Import users and groups

On the DC (or a jump host with RSAT + network to the DC), as a Domain Admin:

```powershell
cd C:\path\to\ad-ldap-2-idm\AD\scripts

# 1) Confirm LDIFs are present
Get-Item ldap-users.ldif, ldap-groups.ldif

# 2) Dry-run (default). Expect parsed user/group counts, no AD writes.
.\01-import-ldap-to-ad.ps1
```

If counts are zero, the LDIFs are empty or DNs are not `ou=People` /
`ou=Groups`. Fix the export and retry.

Then set `$DryRun = $false` in the script and run again:

```powershell
.\01-import-ldap-to-ad.ps1
```

What the script creates:

| OpenLDAP | AD |
|----------|-----|
| `uid` | `sAMAccountName` |
| `uid@win.iam.lab` | `userPrincipalName` |
| `uidNumber`, `gidNumber`, `loginShell` | same RFC2307 attributes |
| `homeDirectory` | `unixHomeDirectory` (not Windows `homeDirectory`) |
| `hostAccess` | `labeledURI` (informational; HBAC still comes from OpenLDAP at mapping) |
| `posixGroup` `cn` | Global security group, same `sAMAccountName` |
| `memberUid` | `Add-ADGroupMember` |

Existing `sAMAccountName` values are skipped (logged), not overwritten.
Duplicates in the LDIF do **not** abort the run.

Report: `AD/scripts/ldap-to-ad-report.csv`.

---

## 5. Verify in AD

```powershell
Get-ADUser user0001 -Properties uidNumber, gidNumber, unixHomeDirectory, UserPrincipalName
Get-ADGroup grp-web
Get-ADGroupMember grp-linux | Select-Object -First 10 SamAccountName
```

Expect `user0001` enabled, UPN `user0001@win.iam.lab`, and group membership
matching `memberUid` in OpenLDAP.

You do **not** need to create extra groups such as `Linux-Web` for this lab:
the importer keeps OpenLDAP CNs (`grp-web`, `grp-linux`, …). Mapping will set
`ad_group` to those same names.

---

## After cutover (steady state)

New Linux people are created **in AD only**. Do not recreate an OpenLDAP + LSC
path. POSIX for those new users is either:

- **Model C:** append a row to `user-overrides.csv` and run `ipa_trust_overrides.py`
  ([05-mapping.md](05-mapping.md)), or
- **Model B:** set `uidNumber` / `gidNumber` / `unixHomeDirectory` / `loginShell`
  on the AD user at create time.

**Next:** [03-idm-lab.md](03-idm-lab.md).
