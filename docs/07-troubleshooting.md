# Troubleshooting

Symptoms first. The AD **trust** path is the lab default. `ipa migrate-ds` notes are in the [appendix](#appendix--legacy-migrate-ds).

Related: [01-openldap-lab.md](01-openldap-lab.md) · [02-ad-lab.md](02-ad-lab.md) ·
[04-ad-trust.md](04-ad-trust.md) · [08-analyze-source.md](08-analyze-source.md) ·
[05-mapping.md](05-mapping.md).

---

## OpenLDAP container will not start

```bash
podman logs openldap
podman ps -a --filter name=openldap
```

Port conflicts on 1389/1636: change `-p` in the `podman run` command
([01-openldap-lab.md](01-openldap-lab.md) §1).

---

## ldapadd: Invalid credentials

Domain/password must match the container:

- Domain: `bcnconsulting.com` → `dc=bcnconsulting,dc=com`
- Admin: `cn=admin,dc=bcnconsulting,dc=com`
- Password: `redhat00`

---

## ldapadd: hostAccess attribute type undefined

```text
ldap_add: Undefined attribute type (17)
additional info: hostAccess: attribute type undefined
```

**Cause:** `specialAttributes` objectClass loaded without `hostAccess` in
`cn=schema`.

**Fix:** verify both, then patch if needed:

```bash
podman exec openldap ldapsearch -Y EXTERNAL -H ldapi:/// -LLL \
  -b cn=schema,cn=config "(olcObjectClasses=*specialAttributes*)" dn
podman exec openldap ldapsearch -Y EXTERNAL -H ldapi:/// -LLL \
  -b cn=schema,cn=config "(olcAttributeTypes=*hostAccess*)" dn
```

If the OC exists but the attribute does not, set `{N}` in
`openldap/schema/specialAttributes-add-hostAccess.ldif` and:

```bash
podman cp openldap/schema/specialAttributes-add-hostAccess.ldif \
  openldap:/tmp/specialAttributes-add-hostAccess.ldif
podman exec openldap ldapmodify -Y EXTERNAL -H ldapi:/// \
  -f /tmp/specialAttributes-add-hostAccess.ldif
```

Re-import the enterprise LDIF with `ldapadd -c` ([01](01-openldap-lab.md) §3).

---

## ldapadd: Already exists — then user0001 missing

Without `-c`, `ldapadd` stops at the first `Already exists` (often `ou=People`).
Re-run with `-c`, or `podman rm -f openldap` and start clean.

---

## ldapadd: objectClass value #1 invalid per syntax

Missing `specialAttributes` schema. Load schemas **before** the data LDIF
([01-openldap-lab.md](01-openldap-lab.md) §2).

---

## sudo schema load fails

Load against `cn=config` via ldapi:

```bash
podman cp openldap/schema/sudo.ldif openldap:/tmp/sudo.ldif
podman exec openldap ldapadd -Y EXTERNAL -H ldapi:/// -f /tmp/sudo.ldif
```

`Already exists` on reload is fine.

---

## AD import parsed 0 users / 0 groups

`01-import-ldap-to-ad.ps1` only keeps DNs matching `cn=…,ou=People,` and
`cn=…,ou=Groups,`.

- Files must be named `ldap-users.ldif` / `ldap-groups.ldif` **next to the script**.
- Export from OpenLDAP with those OUs ([01](01-openldap-lab.md) §5).
- Run dry-run first (`$DryRun = $true`).

---

## AD import: unix attributes fail on Set-ADUser

`uidNumber` / `unixHomeDirectory` require the RFC2307 / SFU attributes in the
AD schema (present on modern Windows Server). If `Set-ADUser -Replace` fails,
the user object was still created; POSIX for Linux comes from IdM ID Overrides
in any case (Model C).

---

## ipa trust-add: cannot find AD / server not found

Usually DNS. From IdM:

```bash
host -t SRV _ldap._tcp.win.iam.lab
host -t SRV _kerberos._tcp.win.iam.lab
ipa dnsforwardzone-find
```

Add `ipa dnsforwardzone-add win.iam.lab. --forwarder=<AD_IP> --forward-policy=only`
and a conditional forwarder on AD for `bcnconsulting.com`
([04-ad-trust.md](04-ad-trust.md)).

---

## kinit user@WIN.IAM.LAB: Clock skew too great

NTP on AD, IdM, and the client must agree. `timedatectl` / `w32tm /query /status`.

---

## kinit user@WIN.IAM.LAB: Password incorrect

Imported lab password is `redhat00!` (AD), not OpenLDAP `redhat00`. Unlock /
enable the AD account if you tried too many times.

---

## getent passwd shows a huge uid (1.1e9 range)

That is the **automatic AD trust ID range**, not OpenLDAP POSIX. Apply ID
Overrides ([05-mapping.md](05-mapping.md) step 3) and expire the SSSD cache
(`sssctl cache-expire -E` or restart `sssd`).

---

## ipa user-show finds the AD person

You ran `ipa migrate-ds` or `ipa user-add`. Trust users must **not** be native
IdM users. Delete the native user (`ipa user-del`) only if you are sure it is a
lab leftover — do not delete the AD account.

---

## analyze_source_ldif.py exit 1

Duplicate `uid` / `uidNumber`, two groups with the same `gidNumber`, or POSIX
users missing `uid` / `uidNumber` / `gidNumber` / `homeDirectory` / `loginShell`.
Read §5, §6, §11, §14 in the report. Procedure:
[08-analyze-source.md](08-analyze-source.md).

`hostAccess` / `specialAttributes` / sudo are warnings, not exit 1.

---

## FileNotFoundError: 'ipa' during mapping

`--execute` ran off the IdM server. Generate `.sh` on any host; run
`bash ipa_trust_*.sh` on IdM after `kinit admin`.

---

## ModuleNotFoundError: ipa_lib

Copy the **whole** `freeipa/migration/` directory, including `ipa_lib.py`.

---

## Mapping: 0 bundles / empty ad_group

Fill `group-crosswalk.csv` with `ipa_match_ad_groups.py` after an AD export.
Groups without `hostAccess` only appear if they are referenced from sudo.

---

## HBAC has no effect

`allow_all` is enabled by default. `ipa hbacrule-disable allow_all` for a
pilot, then re-enable.

---

## RHEL 6.10 ipa-client-install fails

Local yum repo from ISO; DNS SRV to IdM; `--no-dns` if the client must not
update DNS. TLS errors before enroll are normal until `/etc/ipa/ca.crt` exists.

---

## Re-loading OpenLDAP

```bash
podman rm -f openldap
```

Then the checklist in [01-openldap-lab.md](01-openldap-lab.md).

---

## Appendix — legacy `migrate-ds`

**Do not use** when AD is the identity authority. Kept for lab regression only.

### migrate-ds skips groups

- Missing `--group-objectclass=posixGroup`
- RFC2307bis (`groupOfNames` / `member`) on RFC2307 data (`memberUid`)
- Wrong `--group-container`

### migrate-ds: attribute "hostaccess" not allowed / unknown object class

IdM has no `hostAccess`. Ignore OC + attribute and remap with
`ipa_remap_access.py` (native users — **not** the trust path):

```bash
ipa migrate-ds \
  ldap://127.0.0.1:1389 \
  --bind-dn="cn=admin,dc=bcnconsulting,dc=com" \
  --base-dn="dc=bcnconsulting,dc=com" \
  --user-container="ou=People" \
  --group-container="ou=Groups" \
  --user-objectclass=posixAccount \
  --group-objectclass=posixGroup \
  --schema=RFC2307 \
  --with-compat \
  --exclude-groups=admins \
  --user-ignore-objectclass=specialAttributes \
  --group-ignore-objectclass=specialAttributes \
  --user-ignore-attribute=hostAccess \
  --group-ignore-attribute=hostAccess
```

Then:

```bash
python3 freeipa/migration/ipa_remap_access.py \
  --users ldap-users.ldif --groups ldap-groups.ldif --sudo sudo-rules.ldif \
  --bundle hg_web --execute
```

Do not add `specialAttributes` to `ipaUserObjectClasses` if source entries
already carry the OC (duplicate objectClass → Type or value exists).

Optional schema experiment only: `freeipa/schema/specialAttributes-idm.ldif`.

### Kerberos Generic error after migrate-ds (missing SIDs)

Migrated users need `ipantsecurityidentifier`. Suggest a covering ID range:

```bash
python3 freeipa/migration/ipa_suggest_idrange.py \
  --users ldap-users.ldif --groups ldap-groups.ldif
```

Then `ipa idrange-add`, restart Directory Server, `ipa config-mod --enable-sid --add-sids`.
Lab UIDs (~10001+) do not fall in the default IPA range (~1859200000).

### Clean native users from an LDIF

```bash
python3 freeipa/migration/ipa_delete_from_ldif.py --users ldap-users.ldif --groups ldap-groups.ldif
```

On the trust path, use [05-mapping.md](05-mapping.md) instead of this appendix.
