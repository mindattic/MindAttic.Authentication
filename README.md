# MindAttic.Authentication

Maximally-secure, Vault-fed authentication for the MindAttic ecosystem — shipped as a single Razor
Class Library (RCL) so MindAttic.Ideas, Prose, and Tutor authenticate **identically** instead of each
rolling its own. Designed to OWASP ASVS L2 (L3 where feasible) and NIST SP 800-63B AAL2, under a
threat model that assumes a skilled attacker **and** a future full database breach.

> **Status:** the security-logic core, the EF model, the Web DI/middleware/endpoint wiring, and all
> seven Razor components **build clean and pass their local test suite** (184/184, NUnit 4 — verified
> 2026-08-14, see [Current status](#current-status)). Nothing has adopted this library yet: the
> provisioning CLI and the three planned app adoptions (Prose → Ideas → Tutor) are still ⬜ not started.
> Read this section honestly before assuming any given feature is production-proven — "compiles and is
> unit-tested in isolation" is not the same claim as "battle-tested behind a real login form."

| | |
|---|---|
| **Package** | `MindAttic.Authentication`, current `<Version>` = **`3.0.0`** (whole-number/major-only, see [Versioning](#versioning)) |
| **Target** | `net10.0`, Razor Class Library (`Microsoft.NET.Sdk.Razor`) |
| **Only hard dependency declared in the csproj** | `MindAttic.Vault 1.0.0` — see the honest caveat in [Current status](#current-status): no C# in this library actually calls a Vault API |
| **Crypto** | Argon2id via Konscious (RFC 9106); BCrypt.Net-Next for legacy verify-then-upgrade |
| **Data** | EF Core (`Microsoft.EntityFrameworkCore.Relational`) — the library owns an isolated `auth` schema, the host owns the `DbContext`/connection |
| **Canon** | [`docs/`](docs/README.md) — start with [`docs/BIBLE.md`](docs/BIBLE.md) for architecture/laws, this file for build/run |

---

## Contents

- [Why this exists](#why-this-exists)
- [What it is / is not](#what-it-is--is-not)
- [Architecture](#architecture)
- [Integration pattern](#integration-pattern)
- [Public surface at a glance](#public-surface-at-a-glance)
- [Security design (summary)](#security-design-summary)
- [Directory layout](#directory-layout)
- [Build, test, and pack](#build-test-and-pack)
- [Documentation map](#documentation-map)
- [Current status](#current-status)
- [Versioning](#versioning)
- [Ratified decisions & accepted residual risks](#ratified-decisions--accepted-residual-risks)

---

## Why this exists

A security audit of the three apps this library is meant to replace found divergent, partly
**critical**, hand-rolled auth:

| App | Verdict | Worst issues |
|---|---|---|
| **Tutor** | 🔴 critically broken | plain **SHA-256, no salt**; hardcoded `aaa` admin; no sessions / lockout / MFA |
| **Prose** | 🟡 soft | BCrypt ✓ but hardcoded default password, a **dev-auto-login** middleware that can fire in prod, volatile in-memory lockout, 30-day sliding sessions, no MFA |
| **Ideas** | 🟡 minimal | BCrypt ✓ but SecurityStamp revalidation unwired, no lockout/MFA yet |

Common gaps across all three: no MFA, no audit log, no breached-password check, secrets not
Vault-backed, and three separate implementations to keep correct. This library is meant to replace
all three with one hardened engine — though as of today none of the three has adopted it yet (see
[Current status](#current-status)).

The design was produced by an adversarial review ("Legion") — seven independent attack lenses
(crypto, session, lockout/enumeration, MFA, secrets/Vault, policy/recovery, Blazor/packaging) → a
synthesized spec → a red-team pass. The full rationale, control-by-control OWASP/NIST mapping, and
residual-risk register live in [`docs/SECURITY_SPEC.md`](docs/SECURITY_SPEC.md).

## What it is / is not

See [`docs/BIBLE.md` §1–§3](docs/BIBLE.md#AUTH-§1) for the canonical statement. In short:

- **Is:** one hardened auth engine consumed as a NuGet `PackageReference`, owning its own `auth` EF
  schema, its own cookie/DP scheme, and presentation-only Razor components. Endpoints — never
  components — perform `SignInAsync`/`SignOutAsync`.
- **Is not:** a cross-app SSO/identity provider (each app is a separate trust boundary; no shared
  session across apps), a secrets store (it *consumes* secrets via Vault-shaped configuration, see
  the caveat below), WebAuthn/FIDO2 (deferred to a future major), or semver (whole-number major bumps
  only, per house rules).

## Architecture

```
                       consuming app (Ideas / Prose / Tutor)
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
        Konscious Argon2       IConfiguration           host EF Core DbContext
        BCrypt (legacy)   ("MindAttic:Vault:Security:*")  (owns `auth` schema)
```

The host owns its own `DbContext` and connection string; this library never opens a connection
itself — it configures the `auth` schema onto the host's model via
`ApplyMindAtticAuthConfiguration()` and operates through the host-implemented `IAuthDataContext` seam.

## Integration pattern

This is the shape the library is built for (verified against the actual `Web/` source in this repo,
`net10.0`). No app has wired this up yet — see [Current status](#current-status) — so treat this as
"what the API supports today," not "what's running in production."

```csharp
// Program.cs
builder.Services.AddMindAtticAuthentication<AppDbContext>(builder.Configuration, o =>
{
    o.AppName = "Ideas";                       // per-app Data Protection trust boundary
    o.IsProduction = builder.Environment.IsProduction();
    o.ConfigureDataProtection = dp => dp        // REQUIRED in prod — fail-closed if omitted
        .PersistKeysToAzureBlobStorage(blobUri, credential)
        .ProtectKeysWithAzureKeyVault(keyVaultKeyUri, credential);
    o.ConfigureAdditionalPolicies = ab =>
        ab.AddPolicy("CanEditPosts", p => p.RequireRole("Editor"));
});

var app = builder.Build();

app.UseForwardedHeaders();                      // BEFORE UseMindAtticAuthentication
app.UseMindAtticAuthentication();               // authn -> [dev bypass, Debug-only] -> authz -> forced-step -> CSP nonce
app.MapMindAtticAuthEndpoints(group =>
    group.RequireRateLimiting("auth"));         // /_ma-auth/login, /mfa-challenge, /logout, /change-password, /reset/*
```

```csharp
// AppDbContext.cs — implement the data seam, then apply the owned schema
public class AppDbContext : DbContext, IAuthDataContext
{
    public DbSet<AuthUser> AuthUsers => Set<AuthUser>();
    public DbSet<AuthUserMfa> AuthUserMfa => Set<AuthUserMfa>();
    public DbSet<AuthRecoveryCode> AuthRecoveryCodes => Set<AuthRecoveryCode>();
    public DbSet<AuthSession> AuthSessions => Set<AuthSession>();
    public DbSet<AuthLoginThrottle> AuthLoginThrottles => Set<AuthLoginThrottle>();
    public DbSet<AuthAuditLog> AuthAuditLog => Set<AuthAuditLog>();
    public DbSet<AuthPasswordHistory> AuthPasswordHistory => Set<AuthPasswordHistory>();
    public DbSet<AuthPasswordResetToken> AuthPasswordResetTokens => Set<AuthPasswordResetToken>();

    protected override void OnModelCreating(ModelBuilder b)
        => b.ApplyMindAtticAuthConfiguration();   // owns the isolated `auth` schema; app runs its own migration
}
```

```razor
@* /login *@
<MaLogin ReturnUrl="@ReturnUrl" Error="@(Request.Query["error"] == "1")" />

@* /mfa *@
<MaMfaChallenge ReturnUrl="@ReturnUrl" Error="@(Request.Query["error"] == "1")" />

@* anywhere authenticated *@
<MaLogout Text="Sign out" />
```

Each app keeps its own `DbContext`/connection and brands the components through the host's own
markup around them — the components themselves take only a small, typed parameter set (`ReturnUrl`,
`Error`, `Text`, `Sent`, `Token` — see [`docs/API.md`](docs/API.md) for the exhaustive list per
component). The three apps remain **separate trust boundaries**: `SetApplicationName` scopes Data
Protection per `AppName`, so a cookie minted for one app cannot authenticate another.

## Public surface at a glance

The full member-by-member reference is [`docs/API.md`](docs/API.md); this is the shape of it.

**Web wiring** (`Web/`)
| Member | Purpose |
|---|---|
| `AddMindAtticAuthentication<TContext>(IServiceCollection, IConfiguration, Action<MindAtticAuthOptions>)` | Registers the full DI graph: options (floor-validated, fail-closed), crypto/secrets, per-request services, cookie + MFA-pending auth schemes, the `ma:admin` policy, Data Protection (per-app key ring), Blazor cascading auth state. `TContext : DbContext, IAuthDataContext`. |
| `UseMindAtticAuthentication(IApplicationBuilder)` | Orders `UseAuthentication` → (Debug-only dev bypass) → `UseAuthorization` → a forced-step redirect (must-enroll-MFA / must-change-password) → a scoped CSP nonce applied only to `/login`, `/mfa`, `/account`, `/_ma-auth`. |
| `MapMindAtticAuthEndpoints(IEndpointRouteBuilder, Action<RouteGroupBuilder>? configureGroup = null)` | Maps the `/_ma-auth` group (below); `configureGroup` lets a host attach rate limiting. |

**`/_ma-auth` endpoints** (`Web/AuthEndpoints.cs`) — every POST validates antiforgery; login/MFA/reset paths run behind a uniform timing floor
| Route | Method | Notes |
|---|---|---|
| `/_ma-auth/login` | POST | credential verify → decoy timing on failure → issues cookie or redirects to `/mfa` |
| `/_ma-auth/mfa-challenge` | POST | consumes the MFA-pending principal → TOTP or recovery code → issues the real cookie |
| `/_ma-auth/logout` | POST | revokes the current `AuthSession`, signs out |
| `/_ma-auth/change-password` | POST | `[RequireAuthorization]` |
| `/_ma-auth/reset/request` | POST | enumeration-safe: always the same response/timing whether or not the account exists |
| `/_ma-auth/reset/confirm` | POST | consumes a reset token, sets the new password, never auto-logs-in |

**Razor components** (`Components/`) — all presentation-only static-SSR `<form method="post">`, antiforgery token included, no component calls `SignInAsync`
`MaLogin` · `MaLogout` · `MaChangePassword` · `MaMfaChallenge` · `MaMfaSetup` (interactive — enrollment + one-time recovery-code display) · `MaForgotPassword` · `MaResetPassword`

**Options** (bound from `IConfiguration`, section paths below; see [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) for every key + default)
| Type | Section | Highlights |
|---|---|---|
| `AuthCryptoOptions` | `MindAttic:Auth:Crypto` | Argon2 memory/time/parallelism, salt/hash sizes, password length bounds, current pepper key id; `ValidateOrThrow()` enforces OWASP floors at startup |
| `AuthPolicyOptions` | `MindAttic:Auth:Policy` | min/max length, HIBP check + fail-open, password history depth |
| `AuthSessionOptions` | `MindAttic:Auth:Session` | absolute/idle timeout, revalidation interval |
| `MfaOptions` | `MindAttic:Auth:Mfa` | TOTP issuer/digits/period/window, recovery-code count/size, `RequireForAdmin` |
| `AuthResetOptions` | `MindAttic:Auth:Reset` | public base URL, reset path, token TTL, emails/hour cap |

**Data seam** (`Data/`, `Entities/`) — `IAuthDataContext` exposes 8 `DbSet<T>`s over the `auth` schema (`AuthModel.DefaultSchema`), applied via `ApplyMindAtticAuthConfiguration()`; `AuthModel.ModelFingerprint` is currently `"auth-v2"` so a host can assert its migration matches.

## Security design (summary)

Full control-by-control detail, OWASP/NIST mapping, and the residual-risk register live in
[`docs/SECURITY_SPEC.md`](docs/SECURITY_SPEC.md). Verified-by-test claims are cited in
[`docs/USER_STORIES.md`](docs/USER_STORIES.md); only what's cited there is ✅.

- **Password storage.** Argon2id (Konscious, RFC 9106) — `m=64 MiB, t=3, p=4, 16-byte salt, 32-byte
  hash` — over `HMAC-SHA256(pepper, NFKC-UTF8(password))`. The pepper is resolved by key id
  (`pepper.v1`, `v2`, …) so it can rotate; hashes are self-describing PHC strings so `NeedsRehash` is
  deterministic. Legacy bcrypt/SHA-256 hashes verify with the original algorithm once, then silently
  re-hash to Argon2id+pepper. A precomputed decoy Argon2id verify runs for absent/inactive accounts so
  timing doesn't reveal existence; a `SemaphoreSlim` gate caps concurrent hashing (peak RAM = N × 64 MiB).
- **Sessions.** `__Host-MindAttic.Auth` cookie — HttpOnly, `Secure=Always`, `SameSite=Lax`, 8h
  absolute / 30m idle, no infinite sliding. `SecurityStamp` is revalidated on both the HTTP path
  (`CookieValidation`) and the Blazor circuit (`MaRevalidatingAuthenticationStateProvider`) every
  minute. `AuthSession` rows enable per-session revoke and global logout via stamp rotation.
  ASP.NET Data Protection uses a per-`AppName` key ring; production wiring is fail-closed (throws at
  startup if `ConfigureDataProtection` isn't supplied).
- **Brute-force & enumeration.** `AuthLoginThrottle` is a persistent, DB-backed exponential backoff
  keyed per-account and per-IP (survives restart, shared across instances — no in-memory state).
  Login/MFA/reset responses are uniform in content and timing (`TimingFloor`) across every outcome.
- **MFA.** TOTP (RFC 6238: HMAC-SHA1, 6 digits, 30s, ±1 step), replay-guarded (`LastTotpStepUsed`),
  verify-before-enable enrollment, plus single-use recovery codes stored only as Argon2id+pepper
  hashes. `MfaOptions.RequireForAdmin` (default `true`) forces the `Admin` role through enrollment
  before reaching protected surfaces (`ma:admin` policy requires `amr=mfa`).
- **Password policy & reset.** NIST-aligned: ≥12 chars, up to 128, all Unicode, no composition rules,
  no forced rotation. HIBP k-anonymity breach check, fail-open with an audited skip on outage.
  Password history (reuse prevention). Reset tokens are single-use, ≤15 min TTL, stored as an
  HMAC-SHA256 hash — never a bare token — and never auto-sign the user in.
- **Secrets.** `IAuthSecrets`/`ConfigAuthSecrets` reads `MindAttic:Vault:Security:<name>` from
  `IConfiguration` and **throws** rather than returning empty on a missing/blank value — see the
  honest caveat about the `MindAttic.Vault` dependency in [Current status](#current-status).
- **Packaging.** Endpoints — never components — own `SignInAsync`/`SignOutAsync`; every POST is
  antiforgery-protected; a scoped CSP nonce applies only to the auth surface so it never clobbers a
  host app's own CSP needs; `#if MA_DEV_AUTH` gates the dev-only localhost auth bypass so it compiles
  out of Release builds entirely (the constant is defined only under `Configuration == 'Debug'`).

## Directory layout

```
MindAttic.Authentication/
├─ src/MindAttic.Authentication/          RCL, net10.0 → NuGet
│  ├─ Components/    7 presentation-only Razor forms (MaLogin, MaLogout, MaChangePassword,
│  │                 MaMfaChallenge, MaMfaSetup, MaForgotPassword, MaResetPassword)
│  ├─ Crypto/         Argon2idPasswordHasher, IPasswordHasher, Phc (PHC codec)
│  ├─ Data/           AuthModel (EF config owning the `auth` schema), IAuthDataContext
│  ├─ Entities/       AuthEntities.cs — the 8 owned tables + enums
│  ├─ Internal/       AuthKeys, TimingFloor, UrlSafety — implementation detail, not covered
│  │                  by the cross-version API stability promise (see docs/VERSIONING.md)
│  ├─ Options/        AuthCryptoOptions, AuthPolicyOptions, AuthResetOptions,
│  │                  AuthSessionOptions, MfaOptions, PasswordPolicyDescriptor
│  ├─ Secrets/        IAuthSecrets, ConfigAuthSecrets (fail-closed config-based secret access)
│  ├─ Services/       AccountLockoutService, AuthAuditWriter, AuthBootstrapper,
│  │                  AuthenticationService, IAuthEmailSender (+ LoggingAuthEmailSender stub),
│  │                  MfaEnrollmentService, PasswordChangeService, PasswordPolicy,
│  │                  PasswordResetService, TotpService, UserAdminService, UserStore
│  ├─ Web/            MindAtticAuthExtensions (DI), MindAtticAuthAppExtensions (middleware),
│  │                  AuthEndpoints (/_ma-auth/*), CookieValidation, IMaClaimsAugmentor,
│  │                  MaRevalidatingAuthenticationStateProvider, DevAuthBypass (#if MA_DEV_AUTH)
│  └─ MaClaims.cs     Claim type / role / policy / scheme-name constants
├─ tests/MindAttic.Authentication.Tests/   NUnit 4, 184 tests — all green (see Current status)
├─ tools/             codex.ps1 (Codex doctor/digest CLI) — the provisioning CLI itself
│                     (pepper/KEK/reset-key generation) does not exist yet, see docs/rfc/0001
├─ pack/, pack-out/   Local nupkg snapshots from earlier manual `dotnet pack` runs
│                     (1.0.0/2.0.0) — stale; not regenerated by anything in this repo automatically
├─ docs/              Codex canon + prose detail docs — see Documentation map below
└─ MindAttic.Authentication.sln / .slnx
```

## Build, test, and pack

```powershell
# Build (there's both a .sln and a .slnx at the repo root — pass one explicitly,
# `dotnet build` alone fails with MSB1011 because more than one solution file is present)
dotnet build MindAttic.Authentication.sln -c Debug

# Test — NUnit 4, 184 tests
dotnet test MindAttic.Authentication.sln -c Debug

# Pack into the shared local feed (per docs/CLAUDE.md's release procedure)
dotnet pack src/MindAttic.Authentication/MindAttic.Authentication.csproj -c Release -o C:\LocalNuGet
```

`nuget.config` at the repo root points restore at two sources: a `LocalNuGet` feed
(`C:\LocalNuGet`) and `nuget.org`. The csproj defines `MA_DEV_AUTH` only when
`Configuration == 'Debug'`, so a `Release` pack never contains the dev-only localhost auth bypass —
pack `Debug` only for a local dev feed, `Release` for anything a real app will reference.

A release is not "done" until every subscriber's `PackageReference` is bumped and rebuilds — see the
exhaustive reference-point table in [`CLAUDE.md`](CLAUDE.md) and
[`docs/BIBLE.md` LAW-7](docs/BIBLE.md#AUTH-LAW-7). No subscriber references this library today (see
[Current status](#current-status)).

## Documentation map

This repo follows the MindAttic Codex documentation standard — a fact lives in exactly one layer.

| Doc | Layer | What it covers |
|---|---|---|
| [`docs/BIBLE.md`](docs/BIBLE.md) | L0 | What the system IS/is NOT, architecture, the Laws, verified state |
| [`docs/AMENDMENTS.md`](docs/AMENDMENTS.md) | L1 | Append-only change log — an amendment wins over the bible |
| [`docs/USER_STORIES.md`](docs/USER_STORIES.md) | L2 | Every story cites its verifying NUnit test |
| [`docs/rfc/`](docs/rfc/) | rfc | Design notes not yet graduated into L0/L2 (currently: the provisioning-CLI proposal) |
| [`docs/BIBLE.digest.md`](docs/BIBLE.digest.md) | generated | Produced by `tools/codex.ps1 digest` — never hand-edit |
| [`docs/SECURITY_SPEC.md`](docs/SECURITY_SPEC.md) | detail | Legion-hardened, red-teamed design rationale; full control/OWASP/NIST mapping |
| [`docs/API.md`](docs/API.md) | detail | Exhaustive public API reference, every type and member |
| [`docs/INTEGRATION.md`](docs/INTEGRATION.md) | detail | Step-by-step host adoption walkthrough |
| [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) | detail | Every config key + secret + option, with an example `appsettings.json` |
| [`docs/OPERATIONS.md`](docs/OPERATIONS.md) | detail | Runbook: provisioning, bootstrap, rotation, disaster recovery, email, deployment |
| [`docs/ADOPTION_PLAYBOOK.md`](docs/ADOPTION_PLAYBOOK.md) | detail | Per-app adoption strategy and order (Prose → Ideas → Tutor) |
| [`docs/VERSIONING.md`](docs/VERSIONING.md) | detail | The major-only versioning policy and what a major bump means |

Org-wide rules are inherited by reference from `../MindAttic.HouseRules.md` (not restated here); see
[`CLAUDE.md`](CLAUDE.md) for the working rules and the mandatory downstream-propagation procedure.

## Current status

Verified directly against this working tree on 2026-08-14 (build + test run as part of writing this
README — not carried forward from stale docs):

- **Build:** `dotnet build MindAttic.Authentication.sln -c Debug` → succeeded, **0 warnings, 0 errors**.
- **Tests:** `dotnet test MindAttic.Authentication.sln -c Debug` → **184/184 passing**, NUnit 4, net10.0.
- **`<Version>` in the csproj is `3.0.0`** today. Treat any other version number you see elsewhere in
  this repo as stale: the `pack/` and `pack-out/` folders hold leftover `1.0.0`/`2.0.0` nupkgs from
  earlier manual pack runs, and `obj/**/*.nuspec` under `src`/`tests` contains generated artifacts for
  `1.0.0`, `2.0.0`, `3.0.0`, and `4.0.0` from prior build configurations — none of that reflects the
  currently-checked-out source.
- **A cryptographic-primitive extraction was tried and fully reverted.** Commit `e1b94af` moved
  Argon2id/PHC/TOTP/secret-resolution into a standalone `MindAttic.Cryptography` package (bumping to
  `4.0.0`) and `a618b74` updated the Codex docs to match; commit `3c9fb8e` — titled only "Revert 'fix:
  SessionStart hook…'" — actually reverted all three of those commits' file changes back to the prior
  state (its diff touches `Crypto/`, `Secrets/`, `Internal/`, the docs, and the csproj, not just the
  hook script its message names). The working tree today, and the docs canon in `docs/`, are
  consistent with the **pre-extraction** state: Argon2id/PHC/TOTP/secrets live locally in this
  library, as described above. Worth knowing if you go looking for `MindAttic.Cryptography` — it was
  tried here and backed out, not merely "not yet done."
- **The `MindAttic.Vault` PackageReference is declared but unused by any code in this library.** The
  csproj pins `MindAttic.Vault 1.0.0` as "the only hard dependency," but a repo-wide search finds no
  `using MindAttic.Vault` anywhere in `src/` — `ConfigAuthSecrets` resolves every secret through plain
  `IConfiguration` under `MindAttic:Vault:Security:<name>` by string convention. In practice this means
  a host must wire its own Vault-backed configuration provider (or any provider) that populates that
  section; this library never calls a Vault API directly. (The extraction commit above independently
  reached the same conclusion and dropped the reference — that change was reverted along with
  everything else, so the unused reference is back.)
- **No app has adopted this library yet.** `docs/CLAUDE.md`'s propagation table names Ideas, Prose,
  and Tutor as the intended subscribers; none currently has a `PackageReference` to
  `MindAttic.Authentication` (out of scope to verify further — those are separate repos).
- **`tools/` contains only `codex.ps1`** (the Codex doctor/digest CLI). The provisioning CLI for
  generating the pepper/DP-KEK/reset-token key ([`docs/rfc/0001-provisioning-cli.md`](docs/rfc/0001-provisioning-cli.md))
  has not been built.
- **🟡 Compiles and is exercised indirectly, but has no dedicated unit test of its own:** the
  `AuthenticationService.LoginAsync`/`ConfirmMfaAsync` end-to-end pipeline, `MfaEnrollmentService`,
  `PasswordChangeService`, `AuthBootstrapper`, the Web DI/middleware/endpoint wiring, the
  revalidating auth-state provider, and all seven Razor components. See
  [`docs/USER_STORIES.md`](docs/USER_STORIES.md) for the story-by-story breakdown (Epics D3, E3, G1–G4).
- **⬜ Not started:** the provisioning CLI, a signed/deterministic pack with a committed
  `packages.lock.json`, and all three app adoptions.

## Versioning

Whole-number, major-only — `1.0.0`, then `2.0.0`, then `3.0.0`, … Minor and patch are always `0`.
Consumers exact-pin (`<PackageReference Include="MindAttic.Authentication" Version="3.0.0" />`).
Crypto agility (Argon2 cost, pepper rotation) is in-band via config + `NeedsRehash`, not a version
bump. Full policy: [`docs/VERSIONING.md`](docs/VERSIONING.md).

## Ratified decisions & accepted residual risks

- **MFA:** TOTP + recovery codes now; WebAuthn/FIDO2 deferred (additive, non-breaking when it lands).
  AITM/Evilginx session relay against TOTP is the accepted residual until then.
- **Existing users:** legacy hashes upgrade to Argon2id+pepper on next successful login; dormant
  accounts get a forced reset rather than an indefinite weak-hash residual.
- **HIBP:** fail-open online with a bundled offline fallback and an audited skip — a HIBP outage never
  blocks password changes.
- **Trust boundaries:** the three apps stay separate; no cross-app SSO.
- Other accepted residuals (pepper/KEK in process memory, Vault/config outage = fail-closed auth
  outage, the ≤60s stale-principal window, the operator-gated MFA-reset bypass channel, distributed
  low-and-slow credential stuffing under per-scope thresholds) are enumerated with mitigations in
  [`docs/SECURITY_SPEC.md`](docs/SECURITY_SPEC.md) §8.
