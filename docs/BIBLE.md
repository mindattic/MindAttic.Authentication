---
codex: 1
project: MindAttic.Authentication
code: AUTH
layer: bible
status: living
updated: 2026-06-07
---

# MindAttic.Authentication — Project Bible
> Single source of truth for what MindAttic.Authentication IS, is NOT, and the rules that keep it coherent.
> README.md says how to build/run; this says how to think about the system.
> Layer map: L0 this bible · L1 [AMENDMENTS](AMENDMENTS.md) (amendment wins) · L2 [USER_STORIES](USER_STORIES.md) · rfc [docs/rfc](rfc/) · generated [BIBLE.digest.md](BIBLE.digest.md).
> The exhaustive design rationale lives in [SECURITY_SPEC.md](SECURITY_SPEC.md) (Legion-hardened, red-teamed); this bible is the navigable canon over it.

## 1. The one sentence {#AUTH-§1}
MindAttic.Authentication is a maximally-secure, **Vault-backed** authentication engine shipped as a single Razor Class Library (NuGet) so MindAttic.Ideas, StreetSamurai, and Tutor all authenticate **identically** — built to OWASP ASVS L2 (L3 where feasible) and NIST SP 800-63B AAL2, under a threat model that assumes a skilled attacker **and a future full database breach**.

## 2. The product promise {#AUTH-§2}
- **One hardened engine, not three.** Replaces three divergent (one critically broken) per-app auth implementations with a single library that is correct in one place — see [§3](#AUTH-§3) for what it deliberately is not.
- **Secure even when the host misconfigures.** Fail-closed secrets, fail-closed Data-Protection key ring, a fail-closed startup filter asserting middleware order — the library refuses to run insecurely rather than degrading silently.
- **Survives a full DB breach.** Argon2id+pepper where the pepper lives in a *different trust domain* (Vault), so a DB-only dump yields nothing crackable. See [LAW-1](#AUTH-LAW-1).
- **No enumeration, no timing oracle.** Uniform response + uniform timing across every outcome (unknown user / bad password / locked / unverified / MFA-required). See [LAW-3](#AUTH-LAW-3).
- **MFA that cannot be bypassed.** TOTP + single-use recovery codes; admin requires MFA; password reset never bypasses MFA. See [LAW-4](#AUTH-LAW-4).
- **Per-app trust boundaries.** A stolen cookie from one app cannot authenticate to another; no cross-app SSO in v1. See [LAW-6](#AUTH-LAW-6).
- **Presentation never owns auth.** Endpoints own sign-in/out; Razor components are presentation-only static-SSR forms. See [LAW-5](#AUTH-LAW-5).

## 3. What it is NOT {#AUTH-§3}
- **NOT a per-app rolled scheme.** Apps do not implement password hashing, lockout, MFA, or sessions; they adopt this library (org [HOUSE-LAW-7](../../MindAttic.HouseRules.md#HOUSE-LAW-7)).
- **NOT a cross-app SSO / identity provider.** The three apps are **separate trust boundaries**; no shared login session across apps in v1.
- **NOT a secrets store.** It *consumes* secrets through `MindAttic.Vault`; it never invents defaults and the running app never writes prod secrets (provisioning is a separate operator tool).
- **NOT WebAuthn/FIDO2 (yet).** Phishing-resistant hardware MFA is deferred to v2; AITM/Evilginx relay against TOTP is an **accepted v1 residual** ([§6](#AUTH-§6)).
- **NOT the owner of UI markup.** Components accept constrained `AuthUiOptions` (text + allow-listed logo/CSS class) — never raw `MarkupString`/HTML on any auth surface.
- **NOT a hard-delete system.** Account removal is a reversible disable (org [HOUSE-LAW-2](../../MindAttic.HouseRules.md#HOUSE-LAW-2)).
- **NOT semver.** Whole-number major bumps only (org [HOUSE-LAW-1](../../MindAttic.HouseRules.md#HOUSE-LAW-1); [VERSIONING.md](VERSIONING.md)).

## 4. Architecture canon {#AUTH-§4}

```
                       consuming app (Ideas / StreetSamurai / Tutor)
                                   |  PackageReference (NuGet)
   +-------------------------------v--------------------------------------+
   |                    MindAttic.Authentication (RCL, net10.0)           |
   |                                                                      |
   |  Web/ ........ AddMindAtticAuthentication -> Use... -> Map...Endpoints|
   |   (DI graph)   (ordered middleware)   (/_ma-auth/login,logout,...)   |
   |      |                  |                        |                   |
   |  Components/ <MaLogin> <MaMfaChallenge> ...  (presentation-only SSR) |
   |      |                                                               |
   |  Services/ AuthenticationService, MfaEnrollment, PasswordChange,     |
   |            PasswordReset, Totp, AccountLockout, AuthAuditWriter,     |
   |            PasswordPolicy, UserStore, UserAdmin, AuthBootstrapper    |
   |      |              |                |                   |           |
   |  Crypto/ Argon2id+PHC   Secrets/ IAuthSecrets   Data/ auth schema    |
   |   (IPasswordHasher)      (fail-closed)          (IAuthDataContext)   |
   +-----------|---------------------|------------------------|----------+
               |                     |                        |
        Konscious Argon2      MindAttic.Vault          host EF Core DbContext
        BCrypt (legacy)    (Security/DataProtection)    (owns `auth` schema)
```

### 4.1 Projects / layout
- `src/MindAttic.Authentication/` — the RCL, `net10.0`, packed to NuGet (`1.0.0`). Subfolders: `Options/`, `Secrets/`, `Crypto/`, `Entities/`, `Data/`, `Services/`, `Web/`, `Components/`, `Internal/`. Root-level constants: `MaClaims.cs` (claim types, roles, policies, scheme names). (`MindAttic.Authentication.csproj`)
- `tests/MindAttic.Authentication.Tests/` — NUnit 4 suite (184 tests). (`MindAttic.Authentication.Tests.csproj`)
- **Only hard dependency:** `MindAttic.Vault` (exact-pinned). Plus Konscious Argon2 (1.3.1, exact-pin), BCrypt.Net-Next (legacy verify), EF Core Relational.
- Adopted by three subscribers as a NuGet PackageReference — propagation procedure is mandatory; see [CLAUDE.md](../CLAUDE.md) and [LAW-7](#AUTH-LAW-7).

### 4.2 Domain model (NOUNS)
Canonical identity schema owned by the library, all tables in the isolated `auth` schema, **no FKs into app tables** (`Entities/AuthEntities.cs`):
- **AuthUser** — an account; `PasswordHash` is a self-describing PHC string (or tagged legacy hash); carries `SecurityStamp`, `Role`, MFA/`MustChange`/`MustEnroll`/`IsActive` flags.
- **AuthUserMfa** — TOTP state 1:1 with AuthUser; DP-encrypted secret + `LastTotpStepUsed` replay guard.
- **AuthRecoveryCode** — single-use recovery code, stored only as an Argon2id+pepper hash.
- **AuthSession** — an active session (`sid` claim); enables per-session revoke + global logout; stores `IpHash`, never raw IP.
- **AuthLoginThrottle** — persistent per-account / per-IP brute-force backoff (`ThrottleScope`).
- **AuthAuditLog** — every attempt (success+failure); `AuthEventType`/`AuthOutcome`/server-only `AuthReasonCode`.
- **AuthPasswordHistory** — reuse prevention (newest N per user).
- **AuthPasswordResetToken** — reset token stored only as an HMAC-SHA256 hash; single-use, short TTL.

### 4.3 Key services (VERBS)
- **AuthenticationService** — the `LoginAsync` / `ConfirmMfaAsync` pipeline (credential verify → decoy timing → lockout → MFA step-up). (`Services/AuthenticationService.cs`)
- **Argon2idPasswordHasher** (`IPasswordHasher`) — hash/verify/`NeedsRehash`; pepper HMAC pre-hash; legacy upgrade-on-login. (`Crypto/Argon2idPasswordHasher.cs`, `Crypto/Phc.cs`)
- **AccountLockoutService** — persistent exponential backoff, per-account and per-IP. (`Services/AccountLockoutService.cs`)
- **TotpService** — RFC 6238 TOTP generate/validate with replay guard. (`Services/TotpService.cs`)
- **MfaEnrollmentService** — verify-before-enable enrollment + recovery-code generation. (`Services/MfaEnrollmentService.cs`)
- **PasswordPolicy** — NIST policy + HIBP (fail-open + offline) + history. (`Services/PasswordPolicy.cs`)
- **PasswordChangeService** / **PasswordResetService** — reauth'd change; out-of-band reset (no auto-login). (`Services/PasswordChangeService.cs`, `Services/PasswordResetService.cs`)
- **AuthAuditWriter** — sanitized, hashed-key audit writes. (`Services/AuthAuditWriter.cs`)
- **UserStore** / **UserAdminService** — account lookup / admin create-disable (no hard delete). (`Services/UserStore.cs`, `Services/UserAdminService.cs`)
- **AuthBootstrapper** — race-safe first-run admin seed gated on a Vault bootstrap token. (`Services/AuthBootstrapper.cs`)
- **ConfigAuthSecrets** (`IAuthSecrets`) — fail-closed Vault secret access. (`Secrets/ConfigAuthSecrets.cs`)
- Web seam — `AddMindAtticAuthentication` (`Web/MindAtticAuthExtensions.cs`), `UseMindAtticAuthentication` (`Web/MindAtticAuthAppExtensions.cs`), `MapMindAtticAuthEndpoints` (`Web/AuthEndpoints.cs`), `ApplyMindAtticAuthConfiguration` (`Data/AuthModel.cs`), `MaRevalidatingAuthenticationStateProvider` (`Web/MaRevalidatingAuthenticationStateProvider.cs`), `CookieValidation` (`Web/CookieValidation.cs` — idle timeout + SecurityStamp recheck on the HTTP path), `IMaClaimsAugmentor` (`Web/IMaClaimsAugmentor.cs` — app hook to bake extra claims at sign-in), `DevAuthBypass` (`Web/DevAuthBypass.cs` — `#if MA_DEV_AUTH` Debug-only; compiled out of Release builds entirely).

## 5. The Laws {#AUTH-§5}
This project **inherits all org-wide laws** in [`MindAttic.HouseRules.md`](../../MindAttic.HouseRules.md) by reference (do not restate). Most directly load-bearing here: [HOUSE-LAW-1](../../MindAttic.HouseRules.md#HOUSE-LAW-1) (whole-number versioning), [HOUSE-LAW-2](../../MindAttic.HouseRules.md#HOUSE-LAW-2) (soft-disable), [HOUSE-LAW-3](../../MindAttic.HouseRules.md#HOUSE-LAW-3) (Vault secrets), [HOUSE-LAW-7](../../MindAttic.HouseRules.md#HOUSE-LAW-7) (adopt this library), [HOUSE-LAW-8](../../MindAttic.HouseRules.md#HOUSE-LAW-8) (done = verified). The following are **project-specific** laws.

### {#AUTH-LAW-1} AUTH-LAW-1 — Passwords are Argon2id + a Vault pepper, never anything weaker
Every credential at rest is Argon2id (RFC 9106; m≥19456,t≥2,p≥1 floor, startup-validated fail-closed) over an `HMAC-SHA256(Vault pepper, NFKC-UTF8(password))` pre-hash, stored as a self-describing PHC string. The pepper lives in Vault — a different trust domain than the DB. Legacy bcrypt/SHA-256 hashes are verified once then transparently re-hashed on next login. *(Verified by `Argon2idPasswordHasherTests`, `PhcArgon2Tests`, `AuthCryptoOptionsTests`.)*

### {#AUTH-LAW-2} AUTH-LAW-2 — Secrets resolve fail-closed through Vault; the app never writes prod secrets
All auth secrets (pepper, DP KEK, reset-token key, CAPTCHA secret, bootstrap token) resolve through `IAuthSecrets` over the Vault `Security` bucket. A missing/blank secret **throws** — it never coerces to empty. Provisioning is a separate operator tool; the running app never writes prod secrets. (Specializes org [HOUSE-LAW-3](../../MindAttic.HouseRules.md#HOUSE-LAW-3).) *(Verified by `ConfigAuthSecretsTests`.)*

### {#AUTH-LAW-3} AUTH-LAW-3 — Uniform response and uniform timing; no enumeration oracle
Every authentication outcome returns one generic message and runs the same work (decoy Argon2id verify for absent/inactive users) behind a measured timing floor (750ms + ≤100ms jitter on the login endpoint). Reason codes are server-only and never surfaced. Comparisons use `FixedTimeEquals`. *(Verified by `TimingFloorTests`, `AuthKeysTests`, decoy/uniform paths in `AuthAuditWriterTests`.)*

### {#AUTH-LAW-4} AUTH-LAW-4 — MFA is enforced and never bypassed
TOTP (RFC 6238, replay-guarded, verify-before-enable) plus single-use recovery codes stored only as Argon2id+pepper hashes. Admin role requires MFA (global policy + forced enrollment). Password reset preserves MFA, never sets `amr=mfa`, and never auto-logs-in. *(Verified by `TotpServiceTests`, `PasswordResetServiceTests`.)*

### {#AUTH-LAW-5} AUTH-LAW-5 — Endpoints own sign-in; components are presentation-only
All `SignInAsync`/`SignOutAsync` happen in `[ValidateAntiforgery]` minimal-API endpoints (`/_ma-auth/*`), never inside a Blazor circuit or component. `<MaLogin/>` and siblings are static-SSR `<form method=post>` with antiforgery on every POST; no component contains a sign-in call. A fail-closed `IStartupFilter` asserts the middleware order. *(Verified by `UrlSafetyTests` (returnUrl safety on the endpoint path); build-enforced component shape.)*

### {#AUTH-LAW-6} AUTH-LAW-6 — Each app is a separate trust boundary
`SetApplicationName("MindAttic.Auth:{AppName}")` per app, so a cookie minted for one app cannot authenticate to another. The `auth` schema is isolated and has no FKs into app tables. No cross-app SSO in v1. *(Verified by per-app Data Protection isolation in the DI extension; build.)*

### {#AUTH-LAW-7} AUTH-LAW-7 — A release is not done until all subscribers reference it and build
This library ships as a NuGet PackageReference to Ideas (×2 csproj), StreetSamurai, and Tutor. Every release bumps `<Version>` (whole-number), packs to the local feed, updates all subscriber csproj references, and rebuilds each subscriber. Missing any reference point is an incomplete release. (See [CLAUDE.md](../CLAUDE.md) for the exhaustive reference-point table.) *(Verified operationally; no in-repo test.)*

## 6. Verified state {#AUTH-§6}
Evidence captured 2026-06-07 on this working tree:
- **Build:** `dotnet build -c Debug` → **succeeded, 0 warnings, 0 errors.** Library packs to `1.0.0`.
- **Tests:** `dotnet test` → **Passed! Failed: 0, Passed: 184, Skipped: 0, Total: 184** (NUnit 4, net10.0).
- **Proven working (✅, test-cited):** Argon2id+pepper hasher + PHC; fail-closed Vault secrets (`IAuthSecrets`); the 8-entity `auth` model; persistent per-account/per-IP lockout backoff; audit writer (sanitized, hashed keys); password policy (HIBP fail-open + offline + history); TOTP generate/validate + replay guard; password-reset request/consume; account-admin create/disable; URL-safety (open-redirect) guard; timing floor; account-key NFKC normalization; crypto options floor validation.
- **🟡 partial / built-but-unit-test-thin:** the `LoginAsync`/`ConfirmMfaAsync` end-to-end pipeline, MFA enrollment service, change-password service, bootstrap seeding, the Web DI/middleware/endpoints, the revalidating auth-state provider, and the Razor components are **compiled and present** but not all directly unit-tested in isolation — see [USER_STORIES](USER_STORIES.md).
- **⬜ planned:** email-delivered password reset wiring, the provisioning CLI (`tools/`), signed deterministic pack, and the three app adoptions (StreetSamurai → Ideas → Tutor).

## 7. Active frontier {#AUTH-§7}
- Design notes: [docs/rfc/](rfc/) — see [RFC 0001](rfc/0001-provisioning-cli.md) (provisioning CLI for CSPRNG secrets).
- Open epics in [USER_STORIES](USER_STORIES.md): **Epic E (Reset/Recovery delivery)**, **Epic F (Provisioning & packaging)**, **Epic G (App adoption)**.
- Authoritative design detail and residual-risk register: [SECURITY_SPEC.md](SECURITY_SPEC.md) §8 (accepted residuals: AITM relay vs TOTP; pepper/KEK in process memory; Vault outage = fail-closed auth outage; ≤60s stale-principal window; operator-reset MFA-bypass channel; distributed low-and-slow stuffing).

## 8. Quality bar {#AUTH-§8}
A feature is **done** (✅) only when:
1. It builds clean (`dotnet build`, 0 warnings) and the full suite is green (`dotnet test`).
2. It has a verifying test named in [USER_STORIES](USER_STORIES.md); security-critical paths assert the failure/edge case (weak input, absent user, replay, blank secret), not just the happy path.
3. It honors the Laws ([§5](#AUTH-§5)) — fail-closed, no enumeration oracle, no secret in source, no hard delete, whole-number version.
4. For a release: all subscriber csprojs reference the new version and build ([LAW-7](#AUTH-LAW-7)).
Anything not meeting (1)+(2) is marked 🟡/⬜, never ✅. (Org [HOUSE-LAW-8](../../MindAttic.HouseRules.md#HOUSE-LAW-8).)

## 9. Glossary {#AUTH-§9}
- **PHC string** — self-describing password-hash encoding `$argon2id$v=19$m=…,t=…,p=…$salt$hash`; makes `NeedsRehash` deterministic.
- **Pepper** — a Vault-resident secret HMAC'd with the password before Argon2id; lives in a different trust domain than the DB.
- **Decoy verify** — a precomputed Argon2id verify run for absent/inactive users to keep timing uniform (anti-enumeration).
- **SecurityStamp** — per-user GUID rotated on password/MFA/role/disable/global-logout; revalidated every ~1 min to revoke live sessions.
- **Step-up / `amr`** — partial principal `amr=pwd` after password, exchanged for full `amr=[pwd,mfa]` only after MFA verify.
- **Timing floor** — minimum elapsed time (750ms + jitter) enforced on the login endpoint so fast/slow paths are indistinguishable.
- **Throttle scope** — `Account` or `Ip`; the unit a brute-force backoff counter is keyed on.
- **HIBP** — Have I Been Pwned k-anonymity breached-password check; fail-open online with a bundled offline fallback.
- **DP key ring** — ASP.NET Data Protection keys, persisted via Vault, app-name-isolated per subscriber.
- **Trust boundary** — an app's isolated auth domain; a cookie/ticket valid in one is invalid in another.
