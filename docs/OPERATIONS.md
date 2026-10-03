# Operations runbook

Provisioning, rotation, disaster recovery, email, and deployment for MindAttic.Authentication. These are
**operator/IaC** responsibilities — the running app is a read-only consumer of secrets and never writes
production secrets.

---

## 1. Secret provisioning

The app is **fail-closed**: no `pepper.v1` ⇒ won't start; no `bootstrap-token` ⇒ can't seed the first admin.

**Dev** (writable file store, `%APPDATA%\MindAttic\Security\tokens.json`):
```jsonc
{
  "pepper.v1":        "<base64 of 32 random bytes>",
  "bootstrap-token":  "<a strong ≥12-char string>",
  "dp-kek":           "<base64 of 32 random bytes>",
  "reset-token-key":  "<base64 of 32 random bytes>"
}
```
The provisioning CLR tool (`tools/`, 📋 planned) generates these via `RandomNumberGenerator` and writes the
dev file / prints values for prod seeding. Generate a pepper manually meanwhile:
```powershell
[Convert]::ToBase64String((1..32 | % { Get-Random -Max 256 } | % { [byte]$_ }))
```

**Prod** (read-only): seed the same names as Azure Key Vault secrets / App Service settings
(`MindAttic__Vault__Security__pepper.v1`, …) via IaC **before** deploy. The app only reads them.

## 2. First-run bootstrap

`AuthBootstrapper.SeedAdminAsync()` (called once at startup) creates the `admin` account **iff no users
exist**, using `bootstrap-token` as the initial password, with `MustChangePassword = MustEnrollMfa = true`.
**Immediately rotate `bootstrap-token`** in Vault afterward — it is a standing backdoor until rotated
(the app logs a warning reminding you).

## 3. Rotation

- **Pepper:** add `pepper.v2` to Vault, set `Crypto:CurrentPepperKeyId = "v2"`, keep `pepper.v1` readable.
  Hashes re-pepper on each user's next login (`NeedsRehash`). Retire `v1` only when telemetry shows ~0 rows
  reference it. **Back up every pepper** (Key Vault soft-delete/versioning) — loss ⇒ forced reset for all
  affected users.
- **Data Protection keys:** auto-roll at the 90-day lifetime; persisted via Azure Blob, wrapped by Key
  Vault. Never let the ring be deleted (cookies become unverifiable).
- **Reset-token key:** rotating invalidates in-flight reset links (acceptable; they're short-lived).

## 4. Disaster recovery

| Loss | Effect | Recovery |
|---|---|---|
| Pepper (no backup) | All password hashes unverifiable | Forced password reset for all users. **Back it up.** |
| DP key ring | Existing auth cookies invalid | Users re-login; restore the ring from Blob/KV backup to avoid mass re-login. |
| `bootstrap-token` leaked | Backdoor until rotated | Rotate; the seeded admin must already have changed its password. |

**Pre-launch gate:** pepper + DP-KEK backed up in Key Vault with a **tested restore drill**.

## 5. Email (password reset / security alerts)

Auth emails go through `IAuthEmailSender`, which `AddMindAtticAuthentication` chooses at first use:

| Configuration | Sender | Result |
|---|---|---|
| `MindAttic:Vault:Notifications:email` has `smtpHost`, `username`, `password`, `from` (`smtpPort` optional, default 587) | `SmtpAuthEmailSender` | Mail is delivered over SMTP (MailKit). Port 465 = implicit TLS; any other port requires STARTTLS. |
| Section absent or incomplete | `LoggingAuthEmailSender` | Nothing is delivered. A startup **warning** says so and names the missing fields. |
| Host registered its own `IAuthEmailSender` | the host's | The library's registration steps aside. |

- **Provisioning:** dev — `%APPDATA%\MindAttic\Notifications\providers.json`
  (`{ "email": { "smtpHost", "smtpPort", "username", "password", "from" } }`); prod — app settings
  `MindAttic__Vault__Notifications__email__smtpHost` … `__from` (or Key Vault references). Also set
  `MindAttic__Auth__Reset__PublicBaseUrl` to the app's public https origin: a reset link must be absolute,
  so with SMTP on and no base URL the sender refuses reset mail and the startup log warns.
- **Delivery is queued.** The reset request returns without waiting on SMTP, so a slow or failing mail
  server cannot become an enumeration oracle ([LAW-3](BIBLE.md#AUTH-LAW-3)). Each message gets 3 attempts
  (2 s, 4 s back-off); a final failure is logged as an error. Queued mail drains on graceful shutdown.
- **Logs never carry** the reset link (a bearer credential) or the SMTP password; recipients are masked
  (`a***@example.com`). Confirm the startup line `auth email is delivered over SMTP (host:port as user from …)`.
- Reset is enumeration-safe ("if an account exists, we've emailed a link") and the link base comes from
  `PublicBaseUrl`, never `Request.Host`.

## 6. Deployment (Windows App Service, Prose-style)

GitHub Actions on `windows-latest`, **build → migrate → deploy**:
- **build:** `dotnet publish`; restore the private packages (Vault, Authentication, Legion) from the
  local-packages feed + nuget.org.
- **migrate:** apply EF migrations (creates/updates the `auth` schema) via an **OIDC service principal**
  with `db_ddladmin`; the App Service managed identity is read/write only and cannot run DDL.
- **deploy:** push to the App Service slot. App settings carry the `MindAttic__Vault__Security__*` secrets
  (or Key Vault references); `UseHsts`, `UseForwardedHeaders` `KnownProxies`, and an edge WAF / global
  rate-limit are required (the per-IP throttle assumes a correct client IP and the WAF backstops
  distributed stuffing).

## 7. Operational must-dos (red-team mandated)

- Configure `ForwardedHeaders` `KnownProxies`/`KnownNetworks` (empty ⇒ per-IP throttle collapses to global).
- Edge WAF / global rate-limit in front (documented hard dependency).
- Enable the cluster anomaly brake + CAPTCHA step-up.
- Operator MFA reset requires **dual-control** for Admin targets + an out-of-band owner notification.
- Run a proactive **forced-reset campaign** for dormant legacy-hash accounts (don't wait for next login).
- Monitor DP key-ring age + Argon2 verify latency; alert on a shrunk/empty key set.
