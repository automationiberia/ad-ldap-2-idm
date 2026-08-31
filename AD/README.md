# Active Directory lab

AD is the **identity store** after cutover: users, passwords, group membership.
IdM never copies those objects; it trusts this forest.

Full procedure: [docs/02-ad-lab.md](../docs/02-ad-lab.md).

## Import OpenLDAP people into AD

| File | Role |
|------|------|
| `scripts/01-import-ldap-to-ad.ps1` | Create users, POSIX attrs, groups, membership |
| `scripts/ldap-users.ldif` | You provide — export from OpenLDAP |
| `scripts/ldap-groups.ldif` | You provide — export from OpenLDAP |
| `scripts/ldap-to-ad-report.csv` | Written by the script |

1. Export LDIFs ([docs/01-openldap-lab.md](../docs/01-openldap-lab.md) §5).
2. Place `ldap-users.ldif` and `ldap-groups.ldif` in `scripts/`.
3. Set `$DC`, `$UpnSuffix`, `$UsersOU` / `$GroupsOU` in the script.
4. Run with `$DryRun = $true`, then `$DryRun = $false`.

The script matches `ou=People` / `ou=Groups` DNs from OpenLDAP
(`dc=bcnconsulting,dc=com` is expected). It does **not** require
`dc=win,dc=iam,dc=lab` in the LDIF.

Lab password for every imported user: `redhat00!` (used for `kinit` after trust).

Next: [docs/03-idm-lab.md](../docs/03-idm-lab.md), then
[docs/04-ad-trust.md](../docs/04-ad-trust.md).
