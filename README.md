# MindAttic.Authentication

Maximally-secure, **Vault-backed** authentication for the MindAttic ecosystem — shipped as a single
Razor Class Library (NuGet) so MindAttic.Ideas, StreetSamurai, and Tutor all authenticate **identically**
instead of each rolling its own. Built to **OWASP ASVS L2 (L3 where feasible)** and **NIST SP 800-63B
AAL2**, under a threat model that assumes a skilled attacker *and a future full database breach*.

> **Status:** v2 **built, compiling clean, and packed to the local feed** (`2.0.0`) — full auth engine
> including login → TOTP step-up → enrollment → change-password → logout, password reset (email),
> all Razor components, Blazor/endpoint wiring, and the complete security-logic core.
> Provisioning CLI and the three app adoptions (StreetSamurai → Ideas → Tutor) are the remaining work.
>
> **Versioning:** major-only — `2.0.0` is the current release; the next release is `3.0.0` (never
> `2.1.0`). See [`docs/VERSIONING.md`](docs/VERSIONING.md).
>
> **Documentation:** [`docs/`](docs/README.md) — [SECURITY_SPEC](docs/SECURITY_SPEC.md) (design + control
> mappings) · [API](docs/API.md) (every public type) · [INTEGRATION](docs/INTEGRATION.md) ·
> [CONFIGURATION](docs/CONFIGURATION.md) · [OPERATIONS](docs/OPERATIONS.md) · [VERSIONING](docs/VERSIONING.md).
>
> **Only hard dependency:** [`MindAttic.Vault`](https://github.com/mindattic/MindAttic.Vault) (secrets).
> Argon2 via Konscious; legacy verify via BCrypt.Net; EF Core for the owned schema; ASP.NET Core for
> cookies / Data Protection / antiforgery / components.

---

## Why this exists

A security audit of the three apps found divergent, partly **critical** auth:

| App | Verdict | Worst issues |
|---|---|---|
| **Tutor** | 🔴 critically broken | plain **SHA-256, no salt**; hardcoded `aaa` admin; no sessions / lockout / MFA |
| **StreetSamurai** | 🟡 soft | BCrypt ✓ but hardcoded default password, a **dev-auto-login** middleware that can fire in prod, volatile in-memory lockout, 30-day sliding sessions, no MFA |
| **Ideas** | 🟡 minimal | BCrypt ✓ but SecurityStamp revalidation unwired, no lockout/MFA yet |

Common gaps: **no MFA, no audit log, no breached-password check, secrets not Vault-backed, three
implementations to keep correct.** This library replaces all three with one hardened engine.

The design was produced by an adversarial review ("Legion") — seven independent attack lenses (crypto,
session, lockout/enumeration, MFA, secrets/Vault, policy/recovery, Blazor/packaging) → a synthesized
spec → a red-team pass whose verdict was *"build to this after the 6 must-fixes."* All six are folded in.

---

## Security design

### Password storage ✅
- **Argon2id** (Konscious, RFC 9106) — `m=64 MiB, t=3, p=4, 16-byte salt, 32-byte hash`; defaults exceed
  the OWASP floor and **startup-validated** (fail-closed if a config drops below `m≥19456, t≥2, p≥1`).
  Calibrate `t` on prod hardware to ~250–500 ms/verify.
- **Pepper** applied as `HMAC-SHA256(key = Vault pepper, NFKC-UTF8(password))` → Argon2id over the fixed
  32-byte pre-hash. The pepper lives in **Vault** — a *different trust domain than the DB* — so a DB-only
  breach yields nothing crackable. Versioned + **rotatable** (`pepper.v1`, `v2`, …); rehash-on-next-login.
- **Self-describing PHC** strings (`$argon2id$v=19$m=…,t=…,p=…$salt$hash`) so work factors rise over time
  and `NeedsRehash` is deterministic.
- **Transparent legacy upgrade:** stored bcrypt/SHA-256 hashes are verified with the original password and
  silently re-hashed to Argon2id+pepper on the next successful login; dormant accounts get a forced reset.
- **Enumeration & DoS resistance:** a precomputed **decoy** Argon2id verify runs for absent/inactive users
  (uniform timing), `FixedTimeEquals` comparisons, a 128-char input cap before the HMAC, and a
  `SemaphoreSlim` gate capping concurrent Argon2 (peak RAM = N × 64 MiB) so the hash can't be weaponized.

### Sessions & Data Protection 📋
- `__Host-MindAttic.Auth` cookie: HttpOnly · Secure=Always · SameSite · Path=/ · **8h absolute + 30m idle**,
  **no infinite sliding**. Session fixation defeated (fresh ticket only after full credential **+ MFA**).
- **SecurityStamp revalidated every 1 minute** on both the HTTP path and the Blazor circuit — a revoked
  admin loses access within ≤60 s.
- ASP.NET **Data Protection key ring persisted via Vault** (Key Vault-wrapped in prod), so auth cookies
  survive restarts and unify across scaled-out instances — never written to ephemeral disk. Fail-closed at
  startup *and* at runtime (a shrunk/empty key set is an alert, never a silent regenerate).
- Per-app `SetApplicationName` ⇒ a stolen cookie from one app **cannot** authenticate to another.
- `AuthSession` table → per-session revoke, "sign out other sessions", and global logout (stamp rotation).

### Brute-force, lockout & enumeration 📋
- **Persistent, DB-backed** throttle (per-account **and** per-/64-IP), exponential backoff, **survives
  restart and is shared across instances** (no volatile in-memory state). No hard permanent lockout (DoS-safe).
- **Uniform response + uniform timing** across every outcome (unknown user / bad password / locked /
  unverified / MFA-required) on login, registration, reset, and MFA-challenge.
- Trusted client IP only from `ForwardedHeaders` with a host allowlist (empty ⇒ fail-closed); CAPTCHA
  step-up at a soft threshold + an enabled-by-default cluster anomaly brake; edge WAF a documented hard dep.

### MFA — TOTP + recovery codes 📋
- **TOTP** (RFC 6238: HMAC-SHA1, 6 digits, 30 s, ±1 step), 160-bit secret, **replay-guarded** (consumed
  step recorded), **verify-before-enable** enrollment, secrets Data-Protection-encrypted at rest.
- **Recovery codes**: single-use, stored only as Argon2id+pepper hashes, batch-regenerable.
- **Admin role requires MFA** (global policy + forced enrollment). Password reset **never bypasses MFA**.
- Device-loss → recovery code → forced re-enroll; all-codes-lost → **dual-control** operator reset with
  out-of-band owner notification (no single-human MFA bypass).
- Email delivery (enrollment notices, alerts, reset links) flows through **MindAttic.Psst** (email channel;
  Twilio/SMS off) behind an `IAuthEmailSender` abstraction.

### Password policy & reset 📋
- NIST-aligned: **≥12 chars**, up to 128, all Unicode (NFKC), **no composition rules, no forced rotation**.
- **HIBP** breached-password check (k-anonymity, privacy-preserving) — **fail-open** online with a bundled
  **offline fallback** + audited skip (a HIBP outage never DoSes all password changes).
- Password **history** (reuse prevention). Change-password requires current password + fresh reauth.
- Reset tokens: **256-bit** single-use, ≤15 min, stored as HMAC-SHA256 (keyed by a Vault secret),
  enumeration-safe, out-of-band only, rotate the stamp, and **do not auto-login**.

### Secrets (Vault contract) ✅ *(wrapper)* / 📋 *(provisioning)*
- All auth secrets — pepper, DP key-ring KEK, reset-token key, CAPTCHA secret, bootstrap token — resolve
  through a **fail-closed `IAuthSecrets`** over the Vault `Security` bucket: a missing/blank secret **throws**
  (never coerces to empty — neutralizing Vault's best-effort "null on any error").
- **Dev** = writable file store; **prod** = read-only env / Azure Key Vault (asserted at startup). A
  separate **provisioning tool** generates CSPRNG pepper/KEK/keys — the running app never writes prod secrets.
- **No secret in source / appsettings / git.** Pepper + KEK are backed up in Key Vault (tested restore) —
  loss is catastrophic by design.

### Packaging & secure-by-default ✅ *(EF model)* / 📋 *(DI, endpoints, components)*
- **Endpoints own sign-in, never components** — `<MaLogin/>` etc. are presentation-only static-SSR forms;
  antiforgery on every POST.
- A fail-closed `IStartupFilter` asserts the middleware order; the library is safe even if the host
  misconfigures. **No dev-auto-login. No hardcoded credentials.** Race-safe first-run bootstrap requires a
  Vault bootstrap token (invalidated immediately after seeding).
- Canonical EF model in an isolated `auth` schema with a **migration fingerprint** the host checks at startup.
- Signed, deterministic NuGet; `MindAttic.Vault` exact-pinned; `packages.lock.json` committed.

---

## Adopting it in an app (target shape)

```csharp
// Program.cs
builder.Services.AddMindAtticVault(builder.Configuration);            // secrets
builder.Services.AddMindAtticAuthentication(builder.Configuration, o =>
{
    o.AppName = "Ideas";                                             // per-app trust boundary
    o.ConfigureAdditionalPolicies = ab => ab.AddPolicy(/* app-specific */);
});

app.UseMindAtticAuthentication();      // ordered middleware (forwarded headers → authn → authz → antiforgery)
app.MapMindAtticAuthEndpoints();       // /_ma-auth/login, /logout, /change-password, /mfa-challenge
```

```csharp
// the app's DbContext
protected override void OnModelCreating(ModelBuilder b)
    => b.ApplyMindAtticAuthConfiguration();   // owns the `auth` schema; app runs `dotnet ef migrations add`
```

```razor
@* /login *@
<MaLogin ReturnUrl="@ReturnUrl" />
```

Each app keeps its own DbContext/connection and brands the components via constrained `AuthUiOptions`
(text + allow-listed logo/CSS class — never raw markup). The three remain **separate trust boundaries**.

---

## Ratified decisions

- **MFA:** TOTP + recovery codes in **v1**; WebAuthn/FIDO2 deferred to **v2** (additive). AITM relay is the
  accepted v1 residual.
- **Existing users:** carry legacy hashes, upgrade to Argon2id+pepper on next login; **forced reset for
  dormant accounts** (no indefinite weak-hash residual).
- **HIBP:** fail-open online + offline fallback + audited skip.
- **Trust boundaries:** the three apps are **separate** (per-app Data Protection isolation); no cross-app SSO in v1.

## Residual risks (accepted)

AITM/Evilginx session relay defeats TOTP (FIDO2 closes it in v2) · pepper + KEK reside in process memory ·
Vault/Key Vault outage = auth outage by **fail-closed** design · ≤60 s stale-principal window on a live
circuit · operator MFA reset is a process-gated bypass (dual-control + notification mitigate) · distributed
low-and-slow stuffing under thresholds (anomaly brake + edge WAF required).

---

## Build status

```
MindAttic.Authentication/
├─ src/MindAttic.Authentication/        (RCL, net10.0, → NuGet)
│  ├─ Options/   AuthCryptoOptions                              ✅
│  ├─ Secrets/   IAuthSecrets, ConfigAuthSecrets (fail-closed)  ✅
│  ├─ Crypto/    Phc, IPasswordHasher, Argon2idPasswordHasher   ✅
│  ├─ Entities/  8 auth entities + enums                        ✅
│  ├─ Data/      ApplyMindAtticAuthConfiguration (auth schema)  ✅
│  ├─ Services/  lockout ✅ · audit ✅ · policy/HIBP ✅ · TOTP/recovery ✅ · login pipeline ✅ · MFA-enroll ✅ · change-pw ✅ · bootstrap ✅ · password-reset(email) ✅
│  ├─ Web/       DI ✅ · cookie+MFA-pending schemes ✅ · revalidating auth-state ✅ · UseMindAtticAuthentication+CSP ✅ · endpoints (login/mfa/logout/change-pw) ✅ · startup-filter ✅
│  └─ Components/ MaLogin ✅ · MaLogout ✅ · MaChangePassword ✅ · MaMfaChallenge ✅ · MaMfaSetup ✅ · MaForgotPassword ✅ · MaResetPassword ✅
├─ tools/        provisioning CLI (pepper/KEK/keys)             📋
└─ docs/SECURITY_SPEC.md   (Legion-hardened, red-teamed)        ✅

Published: MindAttic.Authentication 2.0.0 → C:\LocalNuGet (consumable as a PackageReference).
```

**Done & verified (compile clean):** full security-logic core, all Razor components, and complete endpoint/middleware wiring — Argon2id+pepper hasher, fail-closed Vault secrets, 8-entity `auth` model, persistent lockout, audit writer, password policy (HIBP + offline + history), TOTP + recovery-code generation, the `LoginAsync`/`ConfirmMfaAsync` pipeline, 1-minute revalidating auth-state provider, `AddMindAtticAuthentication` DI extension, all seven Blazor components, and password-reset (email) service.
**Remaining:** provisioning CLI (pepper/KEK/key generation). **Then** adopt into StreetSamurai → Ideas → Tutor + the Ideas Admin UI.

---

## Stack

.NET 10 · Razor Class Library → signed NuGet · `MindAttic.Vault` (secrets) · Konscious Argon2id ·
BCrypt.Net (legacy verify) · EF Core (owned `auth` schema) · ASP.NET Core cookie auth + Data Protection +
antiforgery · MindAttic.Psst (email). Targets OWASP ASVS L2/L3 · NIST SP 800-63B AAL2.
