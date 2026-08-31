# 3 — Mapping (ID Overrides, HBAC, sudo)

Map the **last OpenLDAP export** onto the AD trust: POSIX as ID Overrides, groups as External + POSIX wrapper, `hostAccess` as HBAC, `sudoRole` as sudorule.

**Why this step:** trust only proves AD identity. Linux still needs the same uids, gids, homes, and host/sudo policy that live in OpenLDAP today. These scripts write **IdM policy objects**. They never create `ipa user` entries.

Prerequisites:
trust works ([04-ad-trust.md](04-ad-trust.md)) and you have `ldap-users.ldif`, `ldap-groups.ldif`, `sudo-rules.ldif`
([01-openldap-lab.md](01-openldap-lab.md) §5). Inventory those files first:
[08-analyze-source.md](08-analyze-source.md).

---



## What is mapped


| Today (OpenLDAP)                             | Target (IdM + trust)                                                           |
| -------------------------------------------- | ------------------------------------------------------------------------------ |
| `uidNumber`, `gidNumber`, home, shell, gecos | **ID Override** in Default Trust View                                          |
| `posixGroup` + `memberUid`                   | Membership stays in **AD**. IdM gets an **External group** + **POSIX wrapper** |
| `hostAccess`                                 | **HBAC** on the POSIX wrapper + hostgroups                                     |
| `ou=SUDOers`                                 | **sudorule** on the same POSIX wrapper                                         |


```text
AD group (e.g. grp-web)          membership stays in AD
        │
        ▼
IdM External Group grp-web_ext   ipa group-add --external
        │                        --external='WIN.IAM.LAB\grp-web'
        ▼
IdM POSIX wrapper grp-web        nested group; --gid= from OpenLDAP
        ▼
HBAC / sudorule                  --groups=grp-web  (wrapper, not _ext)
```

Users get access because they are in the **AD group**. Scripts do not add users to External Groups one by one.

---

## Step 1 — Bootstrap catalog from OpenLDAP LDIF

**Why:** turn the export into three files the apply scripts understand. No IdM changes yet.

```bash
cd freeipa/migration
rm -rf trust_catalog.d ipa_trust_overrides.d ipa_trust_policy.d

python3 ipa_bootstrap_trust_catalog.py \
  --groups /path/to/ldap-groups.ldif \
  --users /path/to/ldap-users.ldif \
  --sudo /path/to/sudo-rules.ldif \
  --domain bcnconsulting.com \
  --output-dir trust_catalog.d
```

| Output                | Purpose                                                                     |
| --------------------- | --------------------------------------------------------------------------- |
| `user-overrides.csv`  | POSIX from LDIF; `ad_user_principal` from `{SASL}userPassword` when present |
| `group-crosswalk.csv` | `idm_external_cn` = `{cn}_ext`, wrapper = `{cn}`, `gid_number` from LDIF    |
| `policy-catalog.json` | `hostAccess` → hostgroups; `sudo_rules` from `--sudo`                       |


`--domain` is the **Linux DNS domain** used to expand short hostnames in `hostAccess` (lab: `bcnconsulting.com`), not the AD forest name.

Inventory first (no IdM writes): [08-analyze-source.md](08-analyze-source.md).

Groups that appear only in sudo (`sudoUser: %lxsapteam`) are added to the crosswalk automatically.

---


## Step 2 — Fill AD names

**Why:** IdM External Groups need `DOMAIN\sAMAccountName`. ID Overrides need the AD UserPrincipalName. Bootstrap may leave those columns empty (if lab OpenLDAP has no `{SASL}` bind in the enterprise LDIF).

After the AD importer, OpenLDAP `uid` / group `cn` match AD `sAMAccountName`. Matching is then automatic.

### Export from AD (optional or After transition, if LDAP doesn't exist)

**PowerShell:**

```powershell
Get-ADUser -Filter * -Properties userPrincipalName, sAMAccountName, uidNumber |
  Select-Object sAMAccountName, userPrincipalName, uidNumber |
  Export-Csv -Path ad-users.csv -NoTypeInformation -Encoding UTF8

Get-ADGroup -Filter {GroupCategory -eq 'Security'} |
  Select-Object Name, sAMAccountName |
  Export-Csv -Path ad-groups.csv -NoTypeInformation -Encoding UTF8
```

**ldapsearch** (from Linux):

```bash
ldapsearch -x -LLL -H ldap://dc.win.iam.lab \
  -D 'CN=Administrator,CN=Users,DC=win,DC=iam,DC=lab' -w 'PASSWORD' \
  -b 'DC=win,DC=iam,DC=lab' \
  '(&(objectClass=user)(objectCategory=person))' \
  sAMAccountName userPrincipalName uidNumber \
  > ad-users.ldif
```

### Merge groups

```bash
python3 ipa_match_ad_groups.py \
  --crosswalk trust_catalog.d/group-crosswalk.csv \
  --ad-export ad-groups.csv \
  --output trust_catalog.d/group-crosswalk.csv
```

`--ad-export` accepts LDIF or CSV. If AD groups used a prefix (e.g. OpenLDAP
`grp-web` → AD `Linux-grp-web`), pass `--ad-prefix Linux-`. This lab’s importer keeps the OpenLDAP CN, so no prefix.

### Merge users

```bash
python3 ipa_match_ad_users.py \
  --csv trust_catalog.d/user-overrides.csv \
  --ad-export ad-users.csv \
  --ad-realm WIN.IAM.LAB \
  --match-by both \
  --output trust_catalog.d/user-overrides.csv
```

`--match-by both` tries `openldap_uid` = `sAMAccountName`, then `uidNumber`.

Principal used: AD `userPrincipalName`, else `sAMAccountName@WIN.IAM.LAB`.

Rows **without** `ad_user_principal` are skipped when applying overrides.

### Crosswalk rules

```csv
openldap_group_cn,ad_group,idm_external_cn,idm_posix_wrapper_cn,gid_number
grp-web,grp-web,grp-web_ext,grp-web,8004
```

- `idm_external_cn` and `idm_posix_wrapper_cn` **must differ** (collision / “member of itself”).
- `gid_number` applies to the **POSIX wrapper** only (`ipa group-add --gid=`).

---



## Step 3 — ID Overrides (users)

**Why:** SSSD on Linux must see the **same** uid/gid/home/shell as OpenLDAP, or NFS and local files break. Default Trust View overrides apply to
`user@WIN.IAM.LAB` without creating an IdM user.

On the **IdM server**:

```bash
kinit admin

# Dry-run → ipa_trust_overrides.d/ipa_trust_overrides.sh
python3 ipa_trust_overrides.py \
  --csv trust_catalog.d/user-overrides.csv \
  --ad-realm WIN.IAM.LAB

# Apply
python3 ipa_trust_overrides.py \
  --csv trust_catalog.d/user-overrides.csv \
  --ad-realm WIN.IAM.LAB \
  --execute
```

Default CLI flags are **legacy** (`--login`, `--uid`, `--gid`). Use `--ipa-cli-style modern` only if `ipa idoverrideuser-add --help` shows `--uidnumber`.

Verify:

```bash
ipa idoverrideuser-find 'Default Trust View'
ipa idoverrideuser-show 'Default Trust View' 'user0001@win.iam.lab'
```

Do **not** run `ipa passwd` for trusted users. Passwords stay in AD (`redhat00!` in this lab).

---

## Step 4 — Groups, HBAC, sudo

**Why:** `hostAccess` is not evaluated by SSSD. HBAC is. Sudo in LDAP becomes IdM sudorule on the POSIX wrapper so `sudo -l` matches the old `sudoRole`.

```bash
python3 ipa_remap_trust_policy.py --list-bundles \
  --catalog trust_catalog.d/policy-catalog.json \
  --crosswalk trust_catalog.d/group-crosswalk.csv \
  --ad-domain WIN.IAM.LAB
```

`--ad-domain` is the prefix for `--external=DOMAIN\group` (lab: `WIN.IAM.LAB`).

Generate one **pilot** bundle (no IdM writes yet):

```bash
python3 ipa_remap_trust_policy.py \
  --catalog trust_catalog.d/policy-catalog.json \
  --crosswalk trust_catalog.d/group-crosswalk.csv \
  --ad-domain WIN.IAM.LAB \
  --bundle hg_web

less ipa_trust_policy.d/ipa_trust_hg_web.sh
```

Each bundle creates:

1. External group `{cn}_ext` + `--external=WIN.IAM.LAB\ad_group`
2. POSIX wrapper `{cn}` with `--gid=` from the crosswalk
3. Wrapper nests the external group
4. HBAC `--groups={cn}` + hostgroups derived from `hostAccess`
5. `ipa sudorule-*` when `sudo_rules` exist (`%group` → wrapper, not `_ext`)

Hostnames map to hostgroups by prefix (`web*` → `hg_web`, `db*` → `hg_database`,
`*` / ALL → bundle `all_hosts`). Apply `all_hosts` **last**.

On IdM:

```bash
kinit admin
bash ipa_trust_policy.d/ipa_trust_hg_web.sh
# After hosts are enrolled (phase 4):
bash ipa_trust_policy.d/ipa_trust_hg_web_hosts.sh

# Sudo with sudoHost: ALL lives in all_hosts
bash ipa_trust_policy.d/ipa_trust_all_hosts.sh
```

Or `--execute` on the IdM server only (not the jump host).

Verify:

```bash
ipa group-find --external
ipa group-show grp-web              # wrapper — gidNumber from OpenLDAP
ipa group-show grp-web_ext
ipa hbacrule-find
ipa sudorule-find
```

---

## Step 5 — Validate (enrolled client)

Enroll a client ([06-legacy-enrollment.md](06-legacy-enrollment.md) or a RHEL 8/9
`ipa-client-install`), then:

```bash
getent passwd 'user0001@win.iam.lab'   # uid/gid must match OpenLDAP, not the auto AD range
getent group grp-web
kinit user0001@WIN.IAM.LAB
sudo -l -U 'user0001@WIN.IAM.LAB'
```

HBAC is hidden while the default `allow_all` rule is on. For a pilot:

```bash
ipa hbacrule-disable allow_all
# SSH as a user in grp-web to a host in hg_web — should work
# SSH as a user not in that group — should fail
ipa hbacrule-enable allow_all
```

---



## Pilot reset (one bundle)

Local files:

```bash
rm -rf trust_catalog.d ipa_trust_overrides.d ipa_trust_policy.d
# re-run steps 1–2
```

IdM objects (example `grp-web`):

```bash
kinit admin
ipa hbacrule-del hbac_grp-web
ipa sudorule-del sudo_grp-web    # if created
ipa group-del grp-web
ipa group-del grp-web_ext
# ipa idoverrideuser-del 'Default Trust View' 'user0001@win.iam.lab'
```

Do **not** delete the AD trust.

---



## Common errors


| Symptom                                   | Cause                               | Fix                                       |
| ----------------------------------------- | ----------------------------------- | ----------------------------------------- |
| `FileNotFoundError: 'ipa'`                | `--execute` on jump host            | Run `.sh` on IdM                          |
| `Parsed 0 entries` / empty AD export      | Wrong file or format                | `--ad-export`; check `head`               |
| `group already exists` / member of itself | External + wrapper same `cn`        | Crosswalk `{cn}_ext` / `{cn}`             |
| `[member user]:` prompts                  | Interactive `ipa`                   | Scripts use `ipa -n` + `< /dev/null`      |
| `no such option: --uidnumber`             | Older CLI                           | Default `legacy` style                    |
| Wrapper GID in the 1171400… range         | Group added without `--gid`         | `gid_number` in crosswalk; recreate group |
| 0 policy bundles                          | Empty `ad_group` or no `hostAccess` | `ipa_match_ad_groups.py`; check LDIF      |
| HBAC has no effect                        | `allow_all` enabled                 | Disable for the test                      |
| Skipped rows without principal            | Empty `ad_user_principal`           | `ipa_match_ad_users.py`                   |


---



## New users after cutover

OpenLDAP is retired. Create the person **in AD**, put them in the right AD group, then:

```text
append user-overrides.csv  →  ipa_trust_overrides.py --execute
```

New Linux **tier** (new HBAC/sudo): create the AD group, add a crosswalk row
and catalog hosts, run `ipa_remap_trust_policy.py`.

Do not stand OpenLDAP + LSC back up for new accounts.

---

## Scripts (copy together)

```text
freeipa/migration/
├── ipa_lib.py
├── ipa_bootstrap_trust_catalog.py
├── ipa_match_ad_users.py
├── ipa_match_ad_groups.py
├── ipa_trust_overrides.py
└── ipa_remap_trust_policy.py
```

Flags and CSV columns: [freeipa/migration/README.md](../freeipa/migration/README.md).

**Next:** [06-legacy-enrollment.md](06-legacy-enrollment.md).