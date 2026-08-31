# 4 — Legacy client enrollment (RHEL 6.10)

Enroll a **RHEL 6.10** host into IdM and log in as a **trusted AD user**. This proves the cutover path on a legacy OS, not a support-lifecycle promise.

**Why this step:** mapping only exists on the IdM server until a client SSSD talks to IdM (and, through trust, to AD). SSH, `getent`, and HBAC are client behaviours.

Prerequisites: trust ([04-ad-trust.md](04-ad-trust.md)). ID Overrides and HBAC ([05-mapping.md](05-mapping.md)) should be applied if you want OpenLDAP uids and real HBAC; enrollment itself only needs a working IdM server.

Lab used IdM **4.13.x** on RHEL 9/10.

---

## Placeholders

| Placeholder | Meaning | Lab example |
|-------------|---------|-------------|
| `<IDM_SERVER>` | IdM server FQDN | `idm.bcnconsulting.com` |
| `<IPA_DOMAIN>` | IPA DNS domain | `bcnconsulting.com` |
| `<IPA_REALM>` | Kerberos realm | `BCNCONSULTING.COM` |
| `<CLIENT_FQDN>` | RHEL 6.10 host FQDN | `rhel610.bcnconsulting.com` |
| `<AD_USER>` | Trusted AD user | `user0001@WIN.IAM.LAB` |
| `<POSIX_GROUP>` | IdM POSIX wrapper | `grp-web` |

---

## Prerequisites

- RHEL 6.10 **not** on CDN: configure a **local yum repo** from the RHEL 6.10
  ISO, then install `ipa-client` from that repo.
- DNS and firewall: client → IdM (LDAP, LDAPS, Kerberos).
- Time sync with IdM and AD (Kerberos).
- Put the client A/PTR in IdM DNS (integrated DNS) or corporate DNS.

---

## 1. Network / DNS (on the client)

```bash
host <IDM_SERVER>
host -t SRV _ldap._tcp.<IPA_DOMAIN>
host -t SRV _kerberos._udp.<IPA_DOMAIN>
```

---

## 2. TLS (LDAPS)

```bash
openssl s_client -connect <IDM_SERVER>:636
```

Quit with `Ctrl-C`. A self-signed IdM CA often shows verify error 19 until enroll installs `/etc/ipa/ca.crt`.

---

## 3. Enroll

```bash
ipa-client-install \
    --server=<IDM_SERVER> \
    --domain=<IPA_DOMAIN> \
    --realm=<IPA_REALM> \
    --mkhomedir \
    --force-join \
    --no-dns \
    --debug
```

Expect `Client configuration complete.` `--no-dns` avoids relying on the client to update IdM DNS on RHEL 6.

Add the host to the IdM hostgroup that HBAC uses (or run the generated `ipa_trust_*_hosts.sh` from mapping):

```bash
# on IdM
kinit admin
ipa host-show <CLIENT_FQDN>
ipa hostgroup-add-member hg_web --hosts=<CLIENT_FQDN>
```

---

## 4. Login tests (AD user, not `ipa passwd`)

Passwords are in **AD**. Do not run `ipa passwd` for trusted users.

From a workstation:

```bash
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    '<AD_USER>'@<CLIENT_FQDN>
```

Lab password after AD import: `redhat00!`.

On the client session:

```bash
kinit
klist
getent passwd '<AD_USER>'
getent group <POSIX_GROUP>
id
```

After ID Overrides, `getent passwd` must show the **OpenLDAP** uid/gid, not the automatic AD trust range.

Kerberos from the client:

```bash
kinit user0001@WIN.IAM.LAB
klist
```

---

## 5. HBAC / sudo (optional in lab)

Default IdM `allow_all` hides HBAC. For a real deny/allow test:

```bash
# on IdM
ipa hbacrule-disable allow_all
```

SSH as a user in the POSIX wrapper that the hostgroup allows — success.
SSH as a user not in that group — failure. Re-enable when finished:

```bash
ipa hbacrule-enable allow_all
```

Sudo (after mapping sudorules):

```bash
sudo -l
```

---

## Lab result (reference)

Enrollment, `kinit` as an AD user, and SSSD lookup completed in lab. Treat as **technical feasibility** for RHEL 6.10 during migration.

If enrollment fails: [07-troubleshooting.md](07-troubleshooting.md).
