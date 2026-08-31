# OpenLDAP (lab source)

Today’s Linux directory for this lab: POSIX users/groups, `hostAccess`, and
`sudoRole`. Full procedure: [docs/01-openldap-lab.md](../docs/01-openldap-lab.md).

**Why it exists:** AD import and IdM mapping both read an export of this tree.
Stand it up first.

```bash
# Start, schemas, import — see docs/01-openldap-lab.md
# There is no Makefile and no generator script in this repo.
```

| Path | Role |
|------|------|
| `schema/sudo.ldif` | `sudoRole` schema (`cn=config`) |
| `schema/specialAttributes.ldif` | OC + `hostAccess` |
| `schema/specialAttributes-add-hostAccess.ldif` | Patch if OC loaded without the attribute |
| `bootstrap/bcnconsulting-enterprise-600users-60groups-100sudo.ldif` | Lab data to import |
| `bootstrap/base.ldif` | OUs only (already inside the enterprise file) |
| `bootstrap/acl-lab.ldif` | Optional `olcAccess` |
| `bootstrap/lab_environment.ldif` | Alternate snapshot — not the default path |

After import, export `ldap-users.ldif` / `ldap-groups.ldif` / `sudo-rules.ldif`
(commands in docs/01). Copy users+groups to `AD/scripts/` for the AD importer.

Next: [docs/02-ad-lab.md](../docs/02-ad-lab.md).
