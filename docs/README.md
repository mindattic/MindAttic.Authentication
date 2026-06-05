# MindAttic.Authentication — Documentation

Exhaustive docs for the unified, Vault-backed authentication library. Start with the root
[`../README.md`](../README.md) for the overview, then:

| Doc | What it covers |
|---|---|
| [`SECURITY_SPEC.md`](SECURITY_SPEC.md) | The Legion-hardened, red-teamed design — every control with its OWASP ASVS / NIST 800-63B mapping, the full EF schema, the public API, the threat model, residual risks, and the ratified owner decisions. The authoritative *why*. |
| [`API.md`](API.md) | Exhaustive public API reference — every type and member (constants, options, secrets, crypto, entities, data seam, services, web wiring, components). |
| [`INTEGRATION.md`](INTEGRATION.md) | Step-by-step host adoption: package reference, `IAuthDataContext`, DI/middleware/endpoints, pages, email, secret provisioning, user migration. |
| [`CONFIGURATION.md`](CONFIGURATION.md) | Every config key + Vault secret + option, with defaults and an example `appsettings.json`. |
| [`OPERATIONS.md`](OPERATIONS.md) | Runbook: secret provisioning, bootstrap, pepper/DP-key rotation, disaster recovery, email (Psst), Windows deployment, and the red-team-mandated operational must-dos. |
| [`VERSIONING.md`](VERSIONING.md) | The major-only versioning policy (`1.0.0` → `2.0.0` → `3.0.0`) and what a major bump means. |

## At a glance

- **Algorithm:** Argon2id (64 MiB / t=3 / p=4) + HMAC-SHA256 **pepper** from Vault; self-describing PHC;
  legacy bcrypt/SHA-256 upgraded on login.
- **Sessions:** `__Host-` cookie, 8h absolute / 30m idle, SecurityStamp revalidated every 1 min, DP key
  ring persisted via Vault, per-app trust boundaries.
- **MFA:** TOTP (RFC 6238) + single-use recovery codes; **Admin requires MFA** (forced enrollment).
- **Defense:** persistent per-account/per-IP exponential backoff, uniform responses + timing floor (no
  enumeration), DB-backed audit, HIBP breach check (fail-open + offline), password history, secure reset.
- **Secure-by-default:** fail-closed secrets, no default credentials, no dev-auto-login, race-safe Vault
  bootstrap, antiforgery on every POST, scoped CSP nonce.
- **Standards:** OWASP ASVS L2 (L3-leaning), NIST SP 800-63B AAL2.
