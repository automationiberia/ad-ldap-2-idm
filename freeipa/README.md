# IdM / FreeIPA (lab + mapping scripts)

IdM is the **Linux policy engine**. Users and passwords stay in AD after trust.

| Path | Role |
|------|------|
| [docs/03-idm-lab.md](../docs/03-idm-lab.md) | Install IdM |
| [docs/04-ad-trust.md](../docs/04-ad-trust.md) | One-way trust (AD → IdM) + Kerberos tests |
| [docs/05-mapping.md](../docs/05-mapping.md) | ID Overrides, HBAC, sudo |
| [docs/08-analyze-source.md](../docs/08-analyze-source.md) | Inventory source LDIF (`analyze_source_ldif.py`) |
| [migration/](migration/) | Python helpers (copy the **whole** folder) |
| `schema/specialAttributes-idm.ldif` | Optional 389 schema for **migrate-ds only** — not the trust path |

Trust-path scripts (need `ipa_lib.py` beside them except `analyze_source_ldif.py`):

- `analyze_source_ldif.py` — LDIF inventory ([docs/08-analyze-source.md](../docs/08-analyze-source.md))
- `ipa_bootstrap_trust_catalog.py`
- `ipa_match_ad_users.py` / `ipa_match_ad_groups.py`
- `ipa_trust_overrides.py`
- `ipa_remap_trust_policy.py`

Legacy `migrate-ds` helpers (`ipa_remap_access.py`, `ipa_suggest_idrange.py`,
`ipa_delete_from_ldif.py`, `ipa_reset_passwords.py`) are documented in
[docs/07-troubleshooting.md](../docs/07-troubleshooting.md) appendix.
