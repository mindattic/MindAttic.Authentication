# Configuration reference

Everything is **secure-by-default**: the only things you *must* supply are the Vault secrets and (in prod)
the Data Protection key-ring wiring. All config keys below are optional overrides with the defaults shown.

---

## Vault secrets — `MindAttic:Vault:Security:<name>` (REQUIRED)

Resolved through the fail-closed `IAuthSecrets` (a blank value throws; the app won't start). Dev:
`%APPDATA%\MindAttic\Security`. Prod: env vars / Azure Key Vault (read-only).

| Secret name | Required | What it is |
|---|---|---|
| `pepper.v1` | **yes** | ≥32 random bytes, base64. HMAC key for the password pre-hash. Different trust domain than the DB. |
| `bootstrap-token` | **yes (first run)** | ≥12-char string — the initial admin password (forced-change on first login). **Rotate immediately after seeding.** |
| `dp-kek` | dev / non-Azure prod | Key-encryption key for the dev Data Protection ring (AES). |
| `reset-token-key` | when reset enabled | HMAC key for password-reset tokens at rest. |
| `captcha-secret` | when CAPTCHA enabled | Server-side CAPTCHA verification secret. |

Pepper rotation adds `pepper.v2`, … and sets `Crypto:CurrentPepperKeyId`; older ids stay readable until
all rows re-hash. See [`OPERATIONS.md`](OPERATIONS.md).

## `MindAttic:Auth:Crypto` (`AuthCryptoOptions`)

| Key | Default | Notes |
|---|---|---|
| `MemoryKiB` | `65536` | 64 MiB. Floor 19456. |
| `Iterations` | `3` | **Calibrate on prod hardware** to ~250–500 ms/verify. Floor 2. |
| `Parallelism` | `4` | ≤ 2× physical cores. Floor 1. |
| `SaltBytes` / `HashBytes` | `16` / `32` | Floors 16 / 32. |
| `MinPasswordChars` / `MaxPasswordChars` | `12` / `128` | Max caps Argon2/HMAC input (DoS guard). |
| `CurrentPepperKeyId` | `"v1"` | New hashes use `pepper.<id>`. |
| `MaxConcurrentHashes` | `0` | `0` ⇒ `ProcessorCount`. Caps peak Argon2 RAM = N × MemoryKiB. |

Invalid values **fail startup** (`ValidateOrThrow`).

## `MindAttic:Auth:Session` (`AuthSessionOptions`)

| Key | Default |
|---|---|
| `AbsoluteTimeout` | `08:00:00` (8 h) |
| `IdleTimeout` | `00:30:00` (30 m) |
| `RevalidationInterval` | `00:01:00` (1 m) — cookie + circuit stamp recheck cadence |

## `MindAttic:Auth:Mfa` (`MfaOptions`)

| Key | Default |
|---|---|
| `Issuer` | `"MindAttic"` |
| `Digits` / `PeriodSeconds` / `WindowSteps` | `6` / `30` / `1` |
| `SecretBytes` | `20` (160-bit) |
| `RecoveryCodeCount` / `RecoveryCodeBytes` | `10` / `10` |
| `PendingEnrollmentMinutes` | `10` |
| `RequireForAdmin` | `true` |

## `MindAttic:Auth:Policy` (`AuthPolicyOptions`)

| Key | Default |
|---|---|
| `MinLength` / `MaxLength` | `12` / `128` |
| `CheckHibp` | `true` |
| `HibpRangeBaseUrl` | `https://api.pwnedpasswords.com/range/` |
| `HibpTimeoutMs` | `2000` |
| `HibpFailOpen` | `true` (offline corpus still applies; skip is audited) |
| `HistoryDepth` | `5` |

## Host code options (`MindAtticAuthOptions`, set in `AddMindAtticAuthentication`)

| Member | Default | Notes |
|---|---|---|
| `AppName` | `"App"` | Per-app Data-Protection isolation. Set per app (`"Ideas"`, `"StreetSamurai"`, `"Tutor"`). |
| `IsProduction` | `false` | `true` ⇒ requires `ConfigureDataProtection` (fail-closed). |
| `ConfigureDataProtection` | — | PROD: persist + protect the key ring (Azure Blob + Key Vault). |
| `DevKeyRingPath` | `%APPDATA%\MindAttic\DataProtection\{AppName}` | Dev key ring location. |
| `ConfigureAdditionalPolicies` | — | App-specific authorization policies (never redefine `MaPolicies.Admin`). |

## Connection string

The library does **not** own a connection string — it operates over the app's `DbContext`. Configure your
context's connection as you already do (Vault/`IConfiguration`/env). The `auth` schema is created by your
app's EF migration.

## Example `appsettings.json`

```jsonc
{
  "MindAttic": {
    "Auth": {
      "Crypto":  { "Iterations": 3, "CurrentPepperKeyId": "v1" },
      "Session": { "AbsoluteTimeout": "08:00:00", "IdleTimeout": "00:30:00" },
      "Mfa":     { "Issuer": "MindAttic Ideas" },
      "Policy":  { "CheckHibp": true }
    }
    // Vault:Security:* secrets come from %APPDATA% (dev) or Key Vault/env (prod), never appsettings/git.
  }
}
```
