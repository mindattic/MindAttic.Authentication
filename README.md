# MindAttic.Authentication

Shared authentication for MindAttic's ASP.NET Core apps as one Razor Class Library: Argon2id passwords, TOTP MFA, secure reset and audit logging, built to OWASP ASVS L2 and NIST SP 800-63B AAL2.

![C#](https://img.shields.io/badge/language-C%23-239120) ![.NET](https://img.shields.io/badge/.NET-10-512BD4) ![Razor Class Library](https://img.shields.io/badge/package-Razor%20Class%20Library-5C2D91) ![Version](https://img.shields.io/badge/version-4.0.0-blue) ![Tests](https://img.shields.io/badge/tests-196%20passing-brightgreen) ![Argon2id](https://img.shields.io/badge/hashing-Argon2id-555555)

```text
                       consuming app (Ideas / Prose / Tutor / IdiotProof)
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
        BCrypt (legacy)   ("MindAttic:Vault:Security:*")  (owns the auth schema)
```

This is a library, so there is no app to screenshot. Install it as the NuGet package `MindAttic.Authentication` from the MindAttic local feed (see [Building and testing](#building-and-testing)).

## Why

- Stop hand-rolling login in every app: one engine gives MindAttic.Ideas, IdiotProof, Prose and Tutor the same hardened sign-in, MFA, reset and audit trail.
- Survive a database breach: passwords are Argon2id over a peppered HMAC, so a stolen table alone is not enough to crack them.
- Give attackers nothing to enumerate: login, MFA and reset answer with the same content and timing whether or not the account exists.
- Make admins prove it twice: the Admin role is forced through TOTP enrollment before it reaches protected pages.
- Upgrade old users silently: legacy bcrypt and SHA-256 hashes verify once, then re-hash to Argon2id on the next login.
- Fail closed, not open: a missing secret or missing production key-ring wiring stops startup instead of running insecurely.

The design came from an adversarial review: seven independent attack lenses (crypto, session, lockout and enumeration, MFA, secrets and Vault, policy and recovery, Blazor and packaging), a synthesized spec, then a red-team pass. The full rationale, control-by-control OWASP and NIST mapping and residual-risk register are in [`docs/SECURITY_SPEC.md`](docs/SECURITY%5FSPEC.md).

## Features

The design target, as stated in [docs/BIBLE.md](docs/BIBLE.md): OWASP ASVS L2 (L3 where feasible) and NIST SP 800-63B AAL2, under a threat model that assumes a skilled attacker and a future full database breach. Verified-by-test claims are cited story by story in [`docs/USER_STORIES.md`](docs/USER%5FSTORIES.md).

### Password storage

- Argon2id (Konscious, RFC 9106) with m=64 MiB, t=3, p=4, a 16-byte salt and a 32-byte hash, over `HMAC-SHA256(pepper, NFKC-UTF8(password))`.
- The pepper is resolved by key id (`pepper.v1`, `v2`, ...) so it can rotate; hashes are self-describing PHC strings, so `NeedsRehash` is deterministic.
- Legacy bcrypt and SHA-256 hashes verify with the original algorithm once, then silently re-hash to Argon2id plus pepper.
- A precomputed decoy Argon2id verify runs for absent or inactive accounts so timing does not reveal existence; a `SemaphoreSlim` gate caps concurrent hashing (peak RAM is N x 64 MiB).

### Sessions

- `__Host-MindAttic.Auth` cookie: HttpOnly, `Secure=Always`, `SameSite=Lax`, 8 h absolute and 30 min idle, no infinite sliding.
- `SecurityStamp` is revalidated every minute on both the HTTP path (`CookieValidation`) and the Blazor circuit (`MaRevalidatingAuthenticationStateProvider`).
- `AuthSession` rows enable per-session revoke, and global logout via stamp rotation.
- ASP.NET Data Protection uses a per-`AppName` key ring; production wiring is fail-closed (startup throws if `ConfigureDataProtection` is not supplied).

### Brute force and enumeration

- `AuthLoginThrottle` is a persistent, database-backed exponential backoff keyed per account and per IP. It survives restarts and is shared across instances, with no in-memory state.
- Login, MFA and reset responses are uniform in content and timing (`TimingFloor`) across every outcome.

### MFA

- TOTP (RFC 6238: HMAC-SHA1, 6 digits, 30 s, plus or minus one step), replay-guarded via `LastTotpStepUsed`, with verify-before-enable enrollment.
- Single-use recovery codes, stored only as Argon2id plus pepper hashes.
- `MfaOptions.RequireForAdmin` (default `true`) forces the `Admin` role through enrollment; the `ma:admin` policy requires `amr=mfa`.

### Password policy and reset

- NIST-aligned: at least 12 characters, up to 128, all Unicode, no composition rules, no forced rotation.
- HIBP k-anonymity breach check, fail-open with an audited skip on outage. Password history prevents reuse.
- Reset tokens are single-use, live at most 15 minutes, are stored only as an HMAC-SHA256 hash and never sign the user in automatically.

### Secrets

`IAuthSecrets` and `ConfigAuthSecrets` read `MindAttic:Vault:Security:<name>` from `IConfiguration` and throw rather than return empty on a missing or blank value. Since 4.0.0 a lookup also matches names that Azure App Service on Linux rewrites when it turns settings into environment variables (for example a dot or hyphen removed): an exact match first, then a letters-and-digits comparison, and two keys that differ only by punctuation raise an ambiguity error instead of a guess.

### Packaging

- Endpoints, never components, own `SignInAsync` and `SignOutAsync`; every POST is antiforgery-protected.
- A scoped CSP nonce applies only to the auth surface, so it never clobbers the host app's own CSP.
- `#if MA_DEV_AUTH` gates the dev-only localhost auth bypass; the symbol is defined only under `Configuration == 'Debug'`, so it compiles out of Release builds entirely.

## Quick start

Reference the package (consumers pin an exact whole-number version):

```xml
<PackageReference Include="MindAttic.Authentication" Version="4.0.0" />
```

Wire it up in `Program.cs`:

```csharp
builder.Services.AddMindAtticAuthentication<AppDbContext>(builder.Configuration, o =>
{
    o.AppName = "Ideas";                       // per-app Data Protection trust boundary
    o.IsProduction = builder.Environment.IsProduction();
    o.ConfigureDataProtection = dp => dp        // REQUIRED in prod: fail-closed if omitted
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

Implement the data seam on your own `DbContext` and apply the owned schema:

```csharp
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
        => b.ApplyMindAtticAuthConfiguration();   // owns the isolated auth schema; the app runs its own migration
}
```

Drop the components into your pages:

```razor
@* /login *@
<MaLogin ReturnUrl="@ReturnUrl" Error="@(Request.Query["error"] == "1")" />

@* /mfa *@
<MaMfaChallenge ReturnUrl="@ReturnUrl" Error="@(Request.Query["error"] == "1")" />

@* anywhere authenticated *@
<MaLogout Text="Sign out" />
```

Then provide the required secrets through your configuration provider under `MindAttic:Vault:Security` (see [docs/CONFIGURATION.md](docs/CONFIGURATION.md)). The full step-by-step walkthrough, including email and user migration, is [docs/INTEGRATION.md](docs/INTEGRATION.md).

Each app keeps its own `DbContext` and connection and brands the components through its own markup around them; the components take only a small typed parameter set (`ReturnUrl`, `Error`, `Text`, `Sent`, `Token`; see [docs/API.md](docs/API.md)). Apps stay separate trust boundaries: `SetApplicationName` scopes Data Protection per `AppName`, so a cookie minted for one app cannot authenticate another.

## How it works

The host owns its `DbContext` and connection string; this library never opens a connection itself. It configures the `auth` schema onto the host's model via `ApplyMindAtticAuthConfiguration()` and works through the host-implemented `IAuthDataContext` seam.

What it is: one hardened auth engine consumed as a NuGet `PackageReference`, owning its own `auth` EF schema, its own cookie and Data Protection scheme, and presentation-only Razor components.

What it is not: a cross-app SSO or identity provider (no shared session across apps), a secrets store (it consumes secrets through configuration), WebAuthn or FIDO2 (deferred to a future major), or semver. The canonical statement is [docs/BIBLE.md](docs/BIBLE.md), sections 1 to 3.

## API

The member-by-member reference is [docs/API.md](docs/API.md); this is its shape.

### Web wiring

| Member | Purpose |
| --- | --- |
| `AddMindAtticAuthentication<TContext>(services, configuration, configure)` | Registers the full DI graph: floor-validated, fail-closed options; crypto and secrets; per-request services; cookie and MFA-pending auth schemes; the `ma:admin` policy; per-app Data Protection key ring; Blazor cascading auth state. `TContext` is a `DbContext` that implements `IAuthDataContext`. |
| `UseMindAtticAuthentication(app)` | Orders `UseAuthentication`, the Debug-only dev bypass, `UseAuthorization`, a forced-step redirect (must enroll MFA or must change password), then a scoped CSP nonce applied only to `/login`, `/mfa`, `/account` and `/_ma-auth`. |
| `MapMindAtticAuthEndpoints(endpoints, configureGroup)` | Maps the `/_ma-auth` group below; the optional `configureGroup` lets a host attach rate limiting. |

### Endpoints

Every POST validates antiforgery; login, MFA and reset paths run behind a uniform timing floor (`Web/AuthEndpoints.cs`).

| Route | Method | Notes |
| --- | --- | --- |
| `/_ma-auth/login` | POST | Credential verify, decoy timing on failure, then issues the cookie or redirects to `/mfa`. |
| `/_ma-auth/mfa-challenge` | POST | Consumes the MFA-pending principal, checks a TOTP or recovery code, issues the real cookie. |
| `/_ma-auth/logout` | POST | Revokes the current `AuthSession` and signs out. |
| `/_ma-auth/change-password` | POST | Requires authorization. |
| `/_ma-auth/reset/request` | POST | Enumeration-safe: the same response and timing whether or not the account exists. |
| `/_ma-auth/reset/confirm` | POST | Consumes a reset token and sets the new password; never auto-logs-in. |

### Razor components

All are presentation-only static-SSR forms with an antiforgery token, and none calls `SignInAsync`: `MaLogin`, `MaLogout`, `MaChangePassword`, `MaMfaChallenge`, `MaMfaSetup` (interactive: enrollment plus one-time recovery-code display), `MaForgotPassword`, `MaResetPassword`.

### Data seam

`IAuthDataContext` exposes eight `DbSet` properties over the `auth` schema (`AuthModel.DefaultSchema`), applied via `ApplyMindAtticAuthConfiguration()`. `AuthModel.ModelFingerprint` is currently `"auth-v2"`, so a host can assert its migration matches.

## Configuration

Options bind from `IConfiguration`. Every key, secret and default, with an example `appsettings.json`, is in [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

| Type | Section | Highlights |
| --- | --- | --- |
| `AuthCryptoOptions` | `MindAttic:Auth:Crypto` | Argon2 memory, time and parallelism; salt and hash sizes; password length bounds; current pepper key id. `ValidateOrThrow()` enforces OWASP floors at startup. |
| `AuthPolicyOptions` | `MindAttic:Auth:Policy` | Min and max length, HIBP check and fail-open, password history depth (default 5). |
| `AuthSessionOptions` | `MindAttic:Auth:Session` | Absolute timeout (8 h), idle timeout (30 min), revalidation interval (1 min). |
| `MfaOptions` | `MindAttic:Auth:Mfa` | TOTP issuer, digits, period and window; recovery-code count and size; `RequireForAdmin`. |
| `AuthResetOptions` | `MindAttic:Auth:Reset` | Public base URL, reset path, token TTL (15 min), emails-per-hour cap (3). |

Secrets are read from `MindAttic:Vault:Security:<name>` and the library fails closed when one is missing. How to provision and rotate them is in [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Project layout

```text
MindAttic.Authentication/
├─ src/MindAttic.Authentication/          RCL, net10.0, packed to NuGet
│  ├─ Components/    7 presentation-only Razor forms (MaLogin, MaLogout, MaChangePassword,
│  │                 MaMfaChallenge, MaMfaSetup, MaForgotPassword, MaResetPassword)
│  ├─ Crypto/        Argon2idPasswordHasher, IPasswordHasher, Phc (PHC codec)
│  ├─ Data/          AuthModel (EF config owning the auth schema), IAuthDataContext
│  ├─ Entities/      AuthEntities.cs: the 8 owned tables + enums
│  ├─ Internal/      AuthKeys, TimingFloor, UrlSafety: implementation detail, not covered
│  │                 by the cross-version API stability promise (see docs/VERSIONING.md)
│  ├─ Options/       AuthCryptoOptions, AuthPolicyOptions, AuthResetOptions,
│  │                 AuthSessionOptions, MfaOptions, PasswordPolicyDescriptor
│  ├─ Secrets/       IAuthSecrets, ConfigAuthSecrets (fail-closed config-based secret access)
│  ├─ Services/      AccountLockoutService, AuthAuditWriter, AuthBootstrapper,
│  │                 AuthenticationService, IAuthEmailSender (+ LoggingAuthEmailSender stub),
│  │                 MfaEnrollmentService, PasswordChangeService, PasswordPolicy,
│  │                 PasswordResetService, TotpService, UserAdminService, UserStore
│  ├─ Web/           MindAtticAuthExtensions (DI), MindAtticAuthAppExtensions (middleware),
│  │                 AuthEndpoints (/_ma-auth/*), CookieValidation, IMaClaimsAugmentor,
│  │                 MaRevalidatingAuthenticationStateProvider, DevAuthBypass (#if MA_DEV_AUTH)
│  └─ MaClaims.cs    claim type, role, policy and scheme-name constants
├─ tests/MindAttic.Authentication.Tests/   NUnit 4 suite
├─ tools/            codex.ps1 (Codex doctor/digest), build-readme.ps1 (README.htm)
├─ pack/, pack-out/  stale local nupkg snapshots (1.0.0, 2.0.0) from earlier manual packs
├─ docs/             Codex canon + detail docs (see Documentation)
└─ MindAttic.Authentication.sln / .slnx
```

## Building and testing

```powershell
# There is both a .sln and a .slnx at the root, so name one explicitly;
# plain `dotnet build` fails with MSB1011.
dotnet build MindAttic.Authentication.sln -c Debug

# NUnit 4 suite
dotnet test MindAttic.Authentication.sln -c Debug

# Pack into the shared local feed
dotnet pack src/MindAttic.Authentication/MindAttic.Authentication.csproj -c Release -o C:\LocalNuGet
```

`nuget.config` points restore at two sources: a `LocalNuGet` feed (`C:\LocalNuGet`) and nuget.org. Because `MA_DEV_AUTH` is defined only for `Debug`, a `Release` pack never contains the dev-only localhost auth bypass: pack `Debug` only for a local dev feed and `Release` for anything a real app will reference.

A release is not done until every subscriber's `PackageReference` is bumped and rebuilds; see [docs/BIBLE.md](docs/BIBLE.md) (`AUTH-LAW-7`).

## Versioning

Whole-number, major-only: `1.0.0`, then `2.0.0`, then `3.0.0`, and so on; minor and patch are always `0`. The current `<Version>` in the csproj is `4.0.0`. Consumers exact-pin. Crypto agility (Argon2 cost, pepper rotation) is in-band through configuration and `NeedsRehash`, not a version bump. Full policy: [docs/VERSIONING.md](docs/VERSIONING.md).

## Status

Checked against this working tree on 2026-10-03:

- `dotnet test MindAttic.Authentication.sln -c Debug`: 196 of 196 tests pass (NUnit 4, net10.0).
- Package version `4.0.0`. The 4.0.0 change is the Linux App Service secret-name matching described under Secrets.
- Four sibling apps use the package, at different versions: MindAttic.Ideas at 4.0.0, IdiotProof at 3.0.0, Prose and Tutor at 2.0.0 (see [docs/BIBLE.md](docs/BIBLE.md) section 4.1a). Bumping them is each app's own work.
- No consumer registers its own `IAuthEmailSender`, so reset emails currently go to the log-only default sender.
- The `MindAttic.Vault 1.0.0` package reference is declared, but no code in `src/` uses it: `ConfigAuthSecrets` resolves every secret through plain `IConfiguration` by naming convention. A host wires its own Vault-backed (or any) configuration provider that fills that section.
- Compiles and is exercised indirectly, but has no dedicated unit test of its own: the `AuthenticationService` login and MFA-confirm pipeline, `MfaEnrollmentService`, `PasswordChangeService`, `AuthBootstrapper`, the Web DI, middleware and endpoint wiring, the revalidating auth-state provider, and the seven Razor components. See [`docs/USER_STORIES.md`](docs/USER%5FSTORIES.md).
- The `pack/` and `pack-out/` folders hold stale 1.0.0 and 2.0.0 nupkgs; nothing regenerates them.

## Roadmap

Planned, not built:

- The provisioning CLI for generating the pepper, Data Protection KEK and reset-token key ([docs/rfc/0001-provisioning-cli.md](docs/rfc/0001-provisioning-cli.md)).
- A signed, deterministic pack with a committed `packages.lock.json`.
- WebAuthn and FIDO2 (additive, non-breaking when it lands).

## Accepted risks

- MFA is TOTP plus recovery codes for now; adversary-in-the-middle session relay against TOTP is the accepted residual until WebAuthn lands.
- Legacy hashes upgrade to Argon2id plus pepper on the next successful login; dormant accounts get a forced reset rather than an indefinite weak-hash residual.
- HIBP is fail-open online with a bundled offline fallback and an audited skip, so an HIBP outage never blocks password changes.
- The apps stay separate trust boundaries; there is no cross-app SSO.
- Other accepted residuals (pepper and KEK in process memory, a Vault or configuration outage becoming a fail-closed auth outage, the 60-second stale-principal window, the operator-gated MFA-reset channel, distributed low-and-slow credential stuffing under per-scope thresholds) are listed with mitigations in [`docs/SECURITY_SPEC.md`](docs/SECURITY%5FSPEC.md), section 8.

## Documentation

This repo follows the MindAttic Codex documentation standard; a fact lives in exactly one layer.

| Doc | Layer | What it covers |
| --- | --- | --- |
| [docs/BIBLE.md](docs/BIBLE.md) | L0 | What the system is and is not, architecture, the Laws, verified state |
| [docs/AMENDMENTS.md](docs/AMENDMENTS.md) | L1 | Pending decisions not yet folded into the bible (normally empty) |
| [`docs/USER_STORIES.md`](docs/USER%5FSTORIES.md) | L2 | Every story cites its verifying NUnit test |
| [docs/rfc/](docs/rfc) | rfc | Design notes not yet graduated (currently the provisioning-CLI proposal) |
| [docs/BIBLE.digest.md](docs/BIBLE.digest.md) | generated | Produced by `tools/codex.ps1 digest`; never hand-edited |
| [`docs/SECURITY_SPEC.md`](docs/SECURITY%5FSPEC.md) | detail | Red-teamed design rationale; full control, OWASP and NIST mapping |
| [docs/API.md](docs/API.md) | detail | Exhaustive public API reference |
| [docs/INTEGRATION.md](docs/INTEGRATION.md) | detail | Step-by-step host adoption |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | detail | Every config key, secret and option, with an example appsettings.json |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | detail | Runbook: provisioning, bootstrap, rotation, disaster recovery, email, deployment |
| [docs/VERSIONING.md](docs/VERSIONING.md) | detail | The major-only versioning policy |
| [docs/README.md](docs/README.md) | index | Index of the detail docs |

Instructions for coding agents working in this repo are in [AGENTS.md](AGENTS.md).

## License

This repository has no LICENSE file. All rights reserved.

Part of [MindAttic](https://mindattic.com) — see more projects at [github.com/mindattic](https://github.com/mindattic). Related: [MindAttic.Vault](https://github.com/mindattic/MindAttic.Vault), [MindAttic.Ideas](https://github.com/mindattic/MindAttic.Ideas), [IdiotProof](https://github.com/mindattic/IdiotProof), [Prose](https://github.com/mindattic/Prose), [Tutor](https://github.com/mindattic/Tutor).
