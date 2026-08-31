# 1c — IdM / FreeIPA lab

Install Red Hat IdM (FreeIPA) as the **Linux policy engine**. Identity stays in
AD. This document stops at a working IdM server (`ipa ping`). Trust is the next
phase.

**Why this step:** HBAC, sudo, hostgroups, and ID Overrides live only on IdM.
You cannot map OpenLDAP policy until the server exists and `kinit admin` works.

```text
CURRENT                         TARGET
AD ──LSC──► OpenLDAP            AD ──── Trust ────► IdM
              │                                      ├─ ID Overrides
Lab OpenLDAP ─┘                                      ├─ External + POSIX groups
                                                     └─ HBAC / sudorule
```

Do **not** run `ipa migrate-ds`. That creates native IdM users and fights the
trust model.

---

## Sequence

1. Prepare hostname, `/etc/hosts`, NTP
2. Install packages and open firewall services
3. Run `ipa-server-install`
4. Verify `kinit admin` / `ipa ping`
5. Copy this repository onto the IdM host (scripts run here in phases 3–4)

---

## 1. Prepare the server host

| Item | Lab value |
|------|-----------|
| FQDN | `idm.bcnconsulting.com` |
| Realm | `BCNCONSULTING.COM` |
| Domain | `bcnconsulting.com` |
| Directory Manager / admin password | `redhat00` |

```bash
sudo hostnamectl set-hostname idm.bcnconsulting.com
grep -q 'idm.bcnconsulting.com' /etc/hosts || \
  echo '192.168.122.179 idm.bcnconsulting.com idm' | sudo tee -a /etc/hosts
sudo timedatectl set-ntp true
```

Use the IdM server’s real IP in `/etc/hosts`. NTP must agree with the AD DC.

---

## 2. Install packages and firewall

```bash
sudo dnf install -y ipa-server ipa-server-dns
sudo firewall-cmd --add-service={freeipa-ldap,freeipa-ldaps,dns,ntp,http,https,kerberos,kpasswd} --permanent
sudo firewall-cmd --reload
```

Trust-specific ports are added in [04-ad-trust.md](04-ad-trust.md). `ipa-server-dns`
is only required for **integrated DNS** (lab default).

---

## 3. Run `ipa-server-install`

AD and IdM must resolve each other later. Integrated DNS is simpler in the lab
because you control the `bcnconsulting.com` zone on this host.

### 3a. Integrated DNS (lab default)

```bash
sudo ipa-server-install \
  --domain=bcnconsulting.com \
  --realm=BCNCONSULTING.COM \
  --ds-password=redhat00 \
  --admin-password=redhat00 \
  --hostname=idm.bcnconsulting.com \
  --setup-dns \
  --forwarder=8.8.8.8 \
  --unattended
```

### 3b. External DNS

Create A/PTR for `idm.bcnconsulting.com` in corporate DNS **before** install.
Package `ipa-server-dns` is optional.

```bash
sudo ipa-server-install \
  --domain=bcnconsulting.com \
  --realm=BCNCONSULTING.COM \
  --ds-password=redhat00 \
  --admin-password=redhat00 \
  --hostname=idm.bcnconsulting.com \
  --no-setup-dns \
  --no-host-dns \
  --unattended
```

First run takes several minutes.

---

## 4. Verify IdM

```bash
kinit admin
ipa ping
ipa user-show admin
```

Copy this repository to the IdM host. Mapping scripts that use `--execute` must
run **on IdM** with an admin ticket.

---

## What not to do yet

| Skip | Why |
|------|-----|
| `ipa migrate-ds` | Would create native users; AD is the identity store |
| `ipa_trust_overrides.py --execute` | No trust yet — no AD principals to override |
| `ipa-adtrust-install` | Next document; needs DNS to AD first |

**Next:** [04-ad-trust.md](04-ad-trust.md).
