# 1a — OpenLDAP lab

OpenLDAP is **today’s Linux directory**: POSIX accounts, `posixGroup` + `memberUid`, custom `hostAccess`, and `sudoRole`. LSC would feed this tree from AD in production. The lab loads a snapshot so later phases can import the same people into AD and map policy onto IdM.

**Why this step:** without a populated OpenLDAP you have no POSIX uids, no `hostAccess`, and no sudo rules to preserve at cutover.

Do this **before** AD import and **before** mapping.

---

## Sequence

1. Start the OpenLDAP container
2. Load extra schemas into `cn=config`
3. Import the enterprise LDIF (OUs, users, groups, hosts, sudo)
4. Validate the live tree
5. Export split LDIFs for AD import and IdM mapping

There is no generator script in this repo. Use `openldap/bootstrap/bcnconsulting-enterprise-600users-60groups-100sudo.ldif`.

---

## 1. Start the container

| Item | Value |
|------|--------|
| Image | `docker.io/osixia/openldap:1.5.0` |
| Host URI | `ldap://127.0.0.1:1389` |
| Inside container | `ldap://127.0.0.1:389` |
| Bind DN | `cn=admin,dc=bcnconsulting,dc=com` |
| Password | `redhat00` |

Do **not** bind-mount schema or LDIF directories into osixia 1.5.0 (startup failures or host path deletion). Copy files with `podman cp` and apply with `ldapadd` / `ldapmodify`.

```bash
podman rm -f openldap 2>/dev/null || true

podman run -d \
  --name openldap \
  --hostname ldap.bcnconsulting.com \
  -p 1389:389 \
  -p 1636:636 \
  -e LDAP_ORGANISATION="BCN Consulting" \
  -e LDAP_DOMAIN="bcnconsulting.com" \
  -e LDAP_ADMIN_PASSWORD="redhat00" \
  docker.io/osixia/openldap:1.5.0

# Repeat until slapd answers
podman exec openldap ldapsearch -x -H ldap://127.0.0.1:389 \
  -D "cn=admin,dc=bcnconsulting,dc=com" -w redhat00 \
  -b "dc=bcnconsulting,dc=com" -s base '(objectClass=*)' dn
```

From the host (mapped port):

```bash
ldapsearch -x -H ldap://127.0.0.1:1389 \
  -D "cn=admin,dc=bcnconsulting,dc=com" -w redhat00 \
  -b "dc=bcnconsulting,dc=com" -s base
```

---

## 2. Load schemas

Base OpenLDAP already has `posixAccount` / `posixGroup`. The lab adds two
schemas **before** any data LDIF:

| File | Why |
|------|-----|
| `openldap/schema/sudo.ldif` | `sudoRole` for `ou=SUDOers` |
| `openldap/schema/specialAttributes.ldif` | Custom OC + multivalued `hostAccess` |

If you skip this, import fails (`hostAccess: attribute type undefined` or
invalid `specialAttributes` objectClass).

```bash
podman cp openldap/schema/sudo.ldif openldap:/tmp/sudo.ldif
podman cp openldap/schema/specialAttributes.ldif openldap:/tmp/specialAttributes.ldif

podman exec openldap ldapadd -Y EXTERNAL -H ldapi:/// -f /tmp/sudo.ldif
podman exec openldap ldapadd -Y EXTERNAL -H ldapi:/// -f /tmp/specialAttributes.ldif
```

`Already exists` on a reload is acceptable. Verify **both** the objectClass and
the attribute:

```bash
podman exec openldap ldapsearch -Y EXTERNAL -H ldapi:/// -LLL \
  -b cn=schema,cn=config "(olcObjectClasses=*sudoRole*)" dn

podman exec openldap ldapsearch -Y EXTERNAL -H ldapi:/// -LLL \
  -b cn=schema,cn=config "(olcObjectClasses=*specialAttributes*)" dn

podman exec openldap ldapsearch -Y EXTERNAL -H ldapi:/// -LLL \
  -b cn=schema,cn=config "(olcAttributeTypes=*hostAccess*)" dn
```

If the OC exists but `hostAccess` does not, patch with
`openldap/schema/specialAttributes-add-hostAccess.ldif` (edit `{N}` to the live
schema index). Details: [07-troubleshooting.md](07-troubleshooting.md).

---

## 3. Import the enterprise LDIF

| Object | Approx. count |
|--------|----------------|
| Users | ~604 (`user0001`…, service accounts) |
| Groups | 60 (`grp-linux`, `grp-web`, …) |
| Hosts | 100 |
| Sudo rules | 100+ |

```text
dc=bcnconsulting,dc=com
├── ou=People
├── ou=Groups
├── ou=Hosts
└── ou=SUDOers
```

`openldap/bootstrap/base.ldif` is OUs only. The enterprise file already includes those OUs plus data — import **that** file, not `base.ldif` separately.

`openldap/bootstrap/lab_environment.ldif` is an alternate snapshot. Use the enterprise file unless you have a reason not to.

```bash
podman cp openldap/bootstrap/bcnconsulting-enterprise-600users-60groups-100sudo.ldif \
  openldap:/tmp/lab.ldif

podman exec openldap ldapadd -c \
  -x -H ldap://127.0.0.1:389 \
  -D "cn=admin,dc=bcnconsulting,dc=com" -w redhat00 \
  -f /tmp/lab.ldif
```

`-c` continues past `Already exists` (osixia already created the domain, and a re-import hits existing OUs). Without `-c`, `ldapadd` stops at the first duplicate and later users never load.

### Optional ACLs

```bash
podman cp openldap/bootstrap/acl-lab.ldif openldap:/tmp/acl-lab.ldif
podman exec openldap ldapmodify -Y EXTERNAL -H ldapi:/// -f /tmp/acl-lab.ldif
```

If `olcDatabase={1}mdb` is not the live DN, edit the LDIF first (see comments
in the file).

---

## 4. Validate

```bash
podman exec openldap ldapsearch -x -LLL \
  -H ldap://127.0.0.1:389 \
  -D "cn=admin,dc=bcnconsulting,dc=com" -w redhat00 \
  -b "ou=People,dc=bcnconsulting,dc=com" "(objectClass=posixAccount)" dn \
  | grep -c '^dn:'

podman exec openldap ldapsearch -x -LLL \
  -H ldap://127.0.0.1:389 \
  -D "cn=admin,dc=bcnconsulting,dc=com" -w redhat00 \
  -b "ou=Groups,dc=bcnconsulting,dc=com" "(objectClass=posixGroup)" dn \
  | grep -c '^dn:'

podman exec openldap ldapsearch -x -LLL \
  -H ldap://127.0.0.1:389 \
  -D "cn=admin,dc=bcnconsulting,dc=com" -w redhat00 \
  -b "ou=People,dc=bcnconsulting,dc=com" "(uid=user0001)"

podman exec openldap ldapsearch -x -LLL \
  -H ldap://127.0.0.1:389 \
  -D "cn=admin,dc=bcnconsulting,dc=com" -w redhat00 \
  -b "ou=Groups,dc=bcnconsulting,dc=com" "memberUid=user0001" cn

podman exec openldap ldapsearch -x -LLL \
  -H ldap://127.0.0.1:389 \
  -D "cn=admin,dc=bcnconsulting,dc=com" -w redhat00 \
  -b "ou=SUDOers,dc=bcnconsulting,dc=com" "(objectClass=sudoRole)" dn \
  | grep -c '^dn:'
```

Expect `user0001` to show `specialAttributes` and `hostAccess`.

---

## 5. Export split LDIFs (needed by AD and mapping)

The bootstrap file is one tree. AD import and `ipa_bootstrap_trust_catalog.py` need **separate** user, group, and sudo files.

```bash
BIND='cn=admin,dc=bcnconsulting,dc=com'
PW=redhat00
URI='ldap://127.0.0.1:389'

podman exec openldap ldapsearch -x -LLL -H "$URI" -D "$BIND" -w "$PW" \
  -b "ou=People,dc=bcnconsulting,dc=com" "(objectClass=posixAccount)" \
  > ldap-users.ldif

podman exec openldap ldapsearch -x -LLL -H "$URI" -D "$BIND" -w "$PW" \
  -b "ou=Groups,dc=bcnconsulting,dc=com" "(objectClass=posixGroup)" \
  > ldap-groups.ldif

podman exec openldap ldapsearch -x -LLL -H "$URI" -D "$BIND" -w "$PW" \
  -b "ou=SUDOers,dc=bcnconsulting,dc=com" "(objectClass=sudoRole)" \
  > sudo-rules.ldif
```

Copy `ldap-users.ldif` and `ldap-groups.ldif` next to
`AD/scripts/01-import-ldap-to-ad.ps1` for [02-ad-lab.md](02-ad-lab.md). Keep all
three files for analysis and mapping:
[08-analyze-source.md](08-analyze-source.md), [05-mapping.md](05-mapping.md).

---

## Reset

```bash
podman stop openldap && podman rm -f openldap
```

Then start again from section 1.

**Next:** [08-analyze-source.md](08-analyze-source.md) (inventory the export), then [02-ad-lab.md](02-ad-lab.md).
