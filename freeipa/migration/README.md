# Migration scripts (AD trust path)

Copy this **entire directory** (including `ipa_lib.py`) to the engagement host.
Do not copy a single file.

**When to run which script:** [docs/08-analyze-source.md](../../docs/08-analyze-source.md) then
[docs/05-mapping.md](../../docs/05-mapping.md).  
Lab order: [README](../../README.md).

---

## Trust-path scripts

All of these import `ipa_lib.py` except `analyze_source_ldif.py`.

| Script | Input | Output / effect |
|--------|--------|-----------------|
| `ipa_bootstrap_trust_catalog.py` | OpenLDAP users/groups/sudo LDIF | `trust_catalog.d/` (JSON + CSVs) |
| `ipa_match_ad_groups.py` | `group-crosswalk.csv` + AD export | Fills `ad_group` |
| `ipa_match_ad_users.py` | `user-overrides.csv` + AD export | Fills `ad_user_principal` |
| `ipa_trust_overrides.py` | `user-overrides.csv` | ID Overrides (dry-run `.sh` or `--execute`) |
| `ipa_remap_trust_policy.py` | catalog + crosswalk | External group, POSIX wrapper, HBAC, sudo |
| `analyze_source_ldif.py` | Any source LDIF | Inventory / blockers — [docs/08-analyze-source.md](../../docs/08-analyze-source.md) |

`--execute` and `bash ipa_trust_*.sh` run **on the IdM server** after
`kinit admin`. Bootstrap, match, and **analyze** run anywhere with Python 3.

---

## `analyze_source_ldif.py`

Does **not** need `ipa_lib.py`. Does not talk to IdM.

Full procedure: [docs/08-analyze-source.md](../../docs/08-analyze-source.md).

```bash
python3 analyze_source_ldif.py \
  --users ldap-users.ldif \
  --groups ldap-groups.ldif \
  --sudo sudo-rules.ldif
```

Also: `--slapcat openldap-export.ldif`, `--tree ldap-tree.ldif`,
`--collection-dir DIR`, `-o report.txt`.

Exit **0** = no critical POSIX blockers. Exit **1** = duplicate uid/uidNumber
or missing required POSIX attributes. Report: stdout +
`analyze_source.d/analyze_source_YYYYMMDD_HHMMSS.txt`.

---

## `ipa_bootstrap_trust_catalog.py`

```bash
python3 ipa_bootstrap_trust_catalog.py \
  --groups ldap-groups.ldif \
  --users ldap-users.ldif \
  --sudo sudo-rules.ldif \
  --domain bcnconsulting.com \
  --output-dir trust_catalog.d
```

`--domain` expands short hostnames in `hostAccess` (Linux DNS domain).  
Optional `--ad-groups-ldif` + `--ad-group-prefix` fill `ad_group` at bootstrap.

`user-overrides.csv` columns: `openldap_uid`, `ad_user_principal`, `login`,
`uid_number`, `gid_number`, `home_directory`, `login_shell`, `gecos`.

`group-crosswalk.csv` columns: `openldap_group_cn`, `ad_group`,
`idm_external_cn`, `idm_posix_wrapper_cn`, `gid_number`.

External and POSIX names **must differ** (bootstrap uses `{cn}_ext` / `{cn}`).

---

## `ipa_match_ad_groups.py` / `ipa_match_ad_users.py`

```bash
python3 ipa_match_ad_groups.py \
  --crosswalk trust_catalog.d/group-crosswalk.csv \
  --ad-export ad-groups.csv

python3 ipa_match_ad_users.py \
  --csv trust_catalog.d/user-overrides.csv \
  --ad-export ad-users.csv \
  --ad-realm WIN.IAM.LAB \
  --match-by both
```

`--ad-export` auto-detects ldapsearch **LDIF** or PowerShell **CSV**.
`--ad-ldif` / `--ad-csv` are aliases.

User `--match-by`: `samaccountname` | `uidnumber` | `both` (default).

How to export AD: [docs/05-mapping.md](../../docs/05-mapping.md) step 2.

---

## `ipa_trust_overrides.py`

Trusted AD users are not `ipa user` objects. POSIX is an ID override in
**Default Trust View**.

```bash
python3 ipa_trust_overrides.py \
  --csv trust_catalog.d/user-overrides.csv \
  --ad-realm WIN.IAM.LAB

kinit admin
python3 ipa_trust_overrides.py \
  --csv trust_catalog.d/user-overrides.csv \
  --ad-realm WIN.IAM.LAB \
  --execute
```

Rows without `ad_user_principal` are skipped. Do not use `ipa passwd` for
trusted users.

| Flag | Purpose |
|------|---------|
| `--csv` | `user-overrides.csv` |
| `--ad-realm` | e.g. `WIN.IAM.LAB` |
| `--view` | default `Default Trust View` |
| `--output-dir` | default `ipa_trust_overrides.d` |
| `--execute` | run `ipa` on this host |
| `--ipa-cli-style` | `legacy` (default: `--uid`/`--gid`) or `modern` (`--uidnumber`) |

---

## `ipa_remap_trust_policy.py`

```bash
python3 ipa_remap_trust_policy.py --list-bundles \
  --catalog trust_catalog.d/policy-catalog.json \
  --crosswalk trust_catalog.d/group-crosswalk.csv \
  --ad-domain WIN.IAM.LAB

python3 ipa_remap_trust_policy.py \
  --catalog trust_catalog.d/policy-catalog.json \
  --crosswalk trust_catalog.d/group-crosswalk.csv \
  --ad-domain WIN.IAM.LAB \
  --bundle hg_web
```

`--ad-domain` is the prefix in `--external=DOMAIN\group`. Apply `all_hosts`
last. Generated scripts use `ipa -n … < /dev/null` so `group-add-member` does
not prompt. `sudoUser: %group` maps to the POSIX wrapper, not `{cn}_ext`.

---

## Common errors

| Symptom | Fix |
|---------|-----|
| `ModuleNotFoundError: ipa_lib` | Copy all of `freeipa/migration/` |
| `FileNotFoundError: 'ipa'` | Run `--execute` / `.sh` on IdM |
| `no such option: --uidnumber` | Keep `--ipa-cli-style legacy` |
| `no such option: --noask` | IPA uses `-n` / `--no-prompt` |
| Skipped rows without principal | `ipa_match_ad_users.py` |
| 0 bundles | Fill `ad_group`; groups need `hostAccess` or sudo |

---

## Legacy migrate-ds scripts (not the lab path)

| Script | Role |
|--------|------|
| `ipa_remap_access.py` | HBAC/sudo for **native** IdM users after `migrate-ds` |
| `ipa_suggest_idrange.py` | SID range for migrated POSIX ids |
| `ipa_delete_from_ldif.py` | Delete native users/groups listed in an LDIF |
| `ipa_reset_passwords.py` | Set passwords on native lab users |

See [docs/07-troubleshooting.md](../../docs/07-troubleshooting.md) appendix.
