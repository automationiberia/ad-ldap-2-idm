# 2 — AD trust with IdM

Establish a **one-way trust** so IdM can authenticate AD users and see AD group membership. Mapping (phase 3) attaches POSIX and HBAC to those trusted principals. It cannot run first.

```text
AD ──── Trust ────► IdM
IdM trusts AD. AD users log in to Linux.
IdM users do not get access to AD.
```

**Why this step:** after trust, `kinit user@WIN.IAM.LAB` and `getent passwd` work without any `ipa user-add`. Passwords never leave AD. 

Prerequisites: [02-ad-lab.md](02-ad-lab.md) (users exist in AD) and [03-idm-lab.md](03-idm-lab.md) (`ipa ping` works).

For more information read [Red Hat Documentation Trust IdM and AD](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/installing_trust_between_idm_and_ad/setting-up-a-trust_installing-trust-between-idm-and-ad)

[//]: # (**Trusting forest**: The local FreeIPA realm trusts the external Active Directory forest, meaning users from the trusted domain can authenticate to resources in FreeIPA.)
[//]: # (**Trusted forest**: The reverse direction, where the external domain trusts the local FreeIPA environment.)
[//]: # (**Two-way**: Mutual trust where both environments trust each other.)

---

## Sequence

1. DNS both ways + time (required even for a one-way trust)
2. Firewall ports for AD trust (Samba / RPC)
3. `ipa-adtrust-install` (prepare IdM as a trust agent)
4. `ipa trust-add` (one-way: IdM trusts AD)
5. Test Kerberos, passwd, and groups

---

## 1. DNS and time

Kerberos and DC locator fail if either side cannot resolve the other.

**On IdM** (integrated DNS), forward the AD zone to the DC:

```bash
kinit admin
ipa dnsforwardzone-add win.iam.lab. \
  --forwarder=<AD_DC_IP> \
  --forward-policy=only
```

**On the AD DNS server**, add a conditional forwarder:

- Zone: `bcnconsulting.com`
- Target: IdM server IP

Checks from **IdM**:

```bash
getent hosts win.iam.lab
host -t SRV _ldap._tcp.win.iam.lab
host -t SRV _kerberos._tcp.win.iam.lab
host idm.bcnconsulting.com
timedatectl
```

Checks from **AD** (or a Windows host): `nslookup idm.bcnconsulting.com` and time sync with the DC.

Fix DNS **before** `ipa trust-add`. Trust discovery uses those SRV records.

---

## 2. Firewall on the IdM server

`ipa-adtrust-install` needs SMB/RPC in addition to the services opened at IdM install:

```bash
sudo firewall-cmd --permanent --add-port=135/tcp
sudo firewall-cmd --permanent --add-port=138/tcp
sudo firewall-cmd --permanent --add-port=139/tcp
sudo firewall-cmd --permanent --add-port=445/tcp
sudo firewall-cmd --permanent --add-port=1024-1300/tcp
sudo firewall-cmd --reload
```

---

## 3. Prepare IdM (`ipa-adtrust-install`)

This command does **not** create the trust. It enables Samba, SID generation, and the compat tree so SSSD can resolve trusted users.

```bash
kinit admin
sudo ipa-adtrust-install \
  --netbios-name=BCNCONSULTING \
  --add-sids \
  --enable-compat \
  --unattended
```

`--enable-compat` is required for `getent` of AD users on many clients.
`--add-sids` assigns SIDs to existing **native** IdM users (admin, etc.).

---

## 4. Create the trust (`ipa trust-add`)

Use the AD **Administrator** password (or another account that can create trusts). This is **not** the OpenLDAP password.

```bash
kinit admin
ipa trust-add win.iam.lab \
  --type=ad \
  --admin Administrator \
  --password
```

Omit `--two-way`. Default is **one-way**: IdM trusts AD (AD users can use Linux). AD does not trust IdM, so IdM principals cannot log on to Windows.

```bash
ipa trust-find
ipa trust-show win.iam.lab
ipa trustdomain-find
ipa idrange-find
```

`ipa trust-show` must show a **Trust direction: Trusting forest** trust (IdM trusting AD), not a two-way forest trust.

You should see an AD range (`ipa-ad-trust`) covering SIDs from `WIN.IAM.LAB`. Until mapping applies ID Overrides, `getent` uids often come from **that** range, not from OpenLDAP. That is expected.

---

## 5. Tests (Kerberos, users, groups)

Use an account created by the AD importer, for example `user0001` / password `redhat00!`.

### Trust and discovery

```bash
kinit admin
ipa trust-show win.iam.lab
ipa trust-fetch-domains win.iam.lab   # if your version supports it
```

### Kerberos (password lives in AD)

```bash
kdestroy -A
kinit user0001@WIN.IAM.LAB
klist
```

`kinit` must talk to the **AD** KDC. Failure here is DNS, time, or password — not HBAC.

### NSS identity (IdM server or any enrolled client)

```bash
getent passwd 'user0001@win.iam.lab'
id 'user0001@win.iam.lab'
getent group 'grp-linux@win.iam.lab'    # AD group via trust; syntax may vary
```

Trusted users must **not** appear as native IdM users:

```bash
ipa user-show user0001
# expect: user not found
```

### Groups

Membership is still **in AD**. IdM External Groups (phase 3) **reference** those AD groups; they do not copy members.

```powershell
# On AD
Get-ADGroupMember grp-linux | Select-Object SamAccountName
```

```bash
# On IdM — after SSSD cache refresh
sssctl cache-expire -E   # if sssctl is installed
id 'user0001@win.iam.lab'
```

`id` should list AD groups once SSSD has queried the trust. POSIX wrapper groups (`grp-linux` without `@win.iam.lab`) appear only **after** mapping.

---

## What success looks like

| Check | Pass |
|-------|------|
| `ipa trust-show win.iam.lab` | One-way trust; IdM trusts AD |
| `kinit user0001@WIN.IAM.LAB` | Ticket from AD |
| `getent passwd 'user0001@win.iam.lab'` | A passwd line (uid may still be the auto AD range) |
| `ipa user-find user0001` | Empty / not a native user |

POSIX uid/gid from OpenLDAP, HBAC, and sudo are **not** done yet. That is phase 3.

**Next:** [05-mapping.md](05-mapping.md).
