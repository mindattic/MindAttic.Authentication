# MindAttic.Authentication — Security Spec (Legion-hardened, red-teamed)

> Adversarially reviewed against OWASP ASVS L2/L3 + NIST SP 800-63B AAL2 (7 attack lenses → synthesis → red-team). Red-team verdict: build to this after folding the must-fix items.

---

# MindAttic.Authentication â€” Hardened Implementation-Ready Spec (v1)

net10.0 Razor Class Library, packaged as a signed NuGet, depends on `MindAttic.Vault`. Adopted by MindAttic.Ideas, StreetSamurai, Tutor. Target: OWASP ASVS L2 (L3 where noted), NIST SP 800-63B AAL2, OWASP Auth/Session/Password-Storage cheat sheets. Threat model: skilled attacker + future full DB breach; the library must be secure even when the host misconfigures (secure-by-default, fail-closed on secrets).

## 0. Conflict resolutions (decided here, do not relitigate)

1. **Pepper application â€” DECIDED: HMAC-SHA256 pre-hash.** `preHash = HMAC-SHA256(key=pepper, msg=NFKC-UTF8(password))` â†’ Argon2id over the fixed 32-byte `preHash`. Chosen over Konscious's `KnownSecret`/secret-K param because (a) it gives a fixed 32-byte Argon2 input that neutralizes long-password DoS into Argon2, (b) clean domain separation + keyed rotation, (c) does not depend on the secret-param being present/identical across a future hasher swap. The `MaxPasswordChars=128` cap is enforced *before* the HMAC so HMAC cost is also bounded.
2. **Vault bucket naming â€” DECIDED: one bucket `Security`** (folder `%APPDATA%\MindAttic\Security`) holding peppers, the dev DP wrapping key (KEK), reset-token key, CAPTCHA secret, and the bootstrap token. **DP key-ring XML lives in a separate bucket `DataProtection`** (folder `%APPDATA%\MindAttic\DataProtection`) because it is a multi-element XML repository, not single secrets. The lens variants ("Auth"/"Security") are unified to `Security`. Both buckets are added to `MindAtticConfigurationSource.Buckets`.
3. **`SetApplicationName` â€” DECIDED: per-app isolation.** `SetApplicationName($"MindAttic.Auth:{AppName}")`. Cookies are portable across *instances of the same app* (scale-out requirement) but are NOT cross-app replayable (a stolen Ideas cookie cannot authenticate to StreetSamurai). The DP key ring itself is shared in the same Vault `DataProtection` bucket but app-name purpose-isolation prevents cross-app ticket reuse. Cross-app SSO is explicitly out of scope for v1.
4. **Circuit revalidation interval â€” DECIDED: 1 minute** (`RevalidatingServerAuthenticationStateProvider.RevalidationInterval = 1m`) and **cookie `SecurityStampValidatorOptions.ValidationInterval = 1 min`** kept equal so the HTTP path and circuit path converge. (The session lens proposed 5m; the blazor-deploy lens proposed 1m. 1m wins â€” it bounds the revoked-admin window to â‰¤60s; the DB cost is one indexed stamp read per user per minute, acceptable.)
5. **HIBP â€” DECIDED: fail-OPEN online + bundled offline fallback, 2s timeout, audited skip.** Never block all password changes on a third-party outage; the offline corpus still blocks the worst-known passwords. Audit `HibpOnlineSkipped` on every skip. (Resolves crypto-lens "offline fallback" vs policy-lens "fail-open" by combining both.)
6. **Cookie name â€” DECIDED: `__Host-MindAttic.Auth`.** `__Host-` prefix mandates Secure + Path=/ + no Domain.
7. **Timing-floor â€” DECIDED: applied to the login *endpoint* pipeline (750ms + â‰¤100ms jitter), validated > worst-case Argon2 verify at startup.** Not applied to read-only state checks.
8. **Reset-token at-rest â€” DECIDED: HMAC-SHA256 keyed by a Vault `reset-token-key`** (not Argon2id) â€” reset tokens are already 256-bit CSPRNG so a fast keyed hash with a Vault key is sufficient and cheap, and avoids paying Argon2 cost on a high-frequency, low-value-per-row table. Recovery codes and passwords use Argon2id+pepper.

## 1. Crypto / Password Storage

- **Algorithm:** Argon2id via `Konscious.Security.Cryptography.Argon2` `[1.3.1]` (exact-pin). Behind `IPasswordHasher` for swap-ability. Never roll our own.
- **Params (above OWASP floor; L3-leaning):** `m=65536 KiB (64 MiB)`, `t=3`, `p=4`, `salt=16B` CSPRNG, `hash=32B`. Startup floors (reject if below, fail-closed): `mâ‰¥19456, tâ‰¥2, pâ‰¥1, saltâ‰¥16, hashâ‰¥32`. Calibrate `t` on **prod** hardware to ~250â€“500ms/verify.
- **Self-describing storage (PHC):** `$argon2id$v=19$m=65536,t=3,p=4$<b64salt>$<b64hash>`. Pepper key id stored in the sidecar column `AuthUser.PasswordPepperKeyId` (NOT inside the PHC, to keep PHC standard-parseable). `NeedsRehash` â‡” algoâ‰ argon2id OR any param < current OR `PasswordPepperKeyId != active`.
- **Pepper:** HMAC pre-hash (see Â§0.1). Pepper â‰¥32B random, resolved from Vault `Security` bucket key `pepper.<id>` via the fail-closed `IAuthSecrets` wrapper. Loaded once at startup into a long-lived buffer; `CryptographicOperations.ZeroMemory` on transient `preHash` buffers in `finally`.
- **Versioned, additive rotation:** add `pepper.v3`, set `CurrentPepperKeyId="v3"`, keep older readable. Re-hash on next successful login (same `NeedsRehash` path). Retire only after telemetry shows ~0 rows reference the old id. **Pepper MUST be backed up** (Key Vault soft-delete/versioning); loss â‡’ forced reset for all affected rows (documented DR runbook item).
- **Legacy migration on login** (detect by prefix, verify against ORIGINAL un-normalized password to avoid NFKC mismatch):
  - `$2a$/$2b$/$2y$` â†’ `BCrypt.Net.BCrypt.Verify(rawPassword, hash)` (legacy was unpeppered). On success â†’ re-hash Argon2id+pepper, bump SecurityStamp.
  - `sha256:` / 44-char base64 (Tutor) â†’ `CryptographicOperations.FixedTimeEquals(SHA256(UTF8(rawPassword)), stored)`. On success â†’ re-hash, bump stamp.
  - else Argon2id path.
- **Constant-time + enumeration kill:** ALWAYS run the full pepper+Argon2id verify against the real hash OR a startup-precomputed **decoy Argon2id hash with identical current params** when the user is absent/inactive. Compare with `FixedTimeEquals`. Lockout/active/verified checks happen AFTER verify. Single message: `"Your sign-in attempt was unsuccessful. Please try again."`
- **DoS controls:** `MaxPasswordChars=128` (reject before HMAC); NFKC normalize then UTF-8; bounded `SemaphoreSlim(MaxConcurrentHashes = Environment.ProcessorCount)` around every hash/verify (peak RAM â‰ˆ N Ã— 64 MiB); the cheap persistent lockout pre-filter runs BEFORE acquiring the gate so floods never pay Argon2 cost.

## 2. Session / Cookie / Data Protection

- **Cookie:** `__Host-MindAttic.Auth`; HttpOnly; `SecurePolicy=Always`; `SameSite=Lax`; `Path=/`; `Domain=null`; `ExpireTimeSpan=8h`; `SlidingExpiration=false`; `IsPersistent=false`. Idle timeout 30m via `AuthenticationProperties.Items["la"]` (last-activity, ISO-8601) checked in `OnValidatePrincipal`.
- **Data Protection:** `SetApplicationName($"MindAttic.Auth:{AppName}")`, `SetDefaultKeyLifetime(90d)`, custom `VaultXmlRepository` over Vault `DataProtection` bucket. **Encrypt at rest:** prod = `ProtectKeysWithAzureKeyVault(kvKeyUri, cred)` (RSA-wrapped, key never leaves KV); non-Azure prod = `ProtectKeysWithCertificate`; dev = AES-GCM with `Security:dp-kek`. `VaultXmlRepository.StoreElement` writes to the file store in dev, **throws `InvalidOperationException`** (read-only) in prod. `AutoGenerateKeys = !IsProduction()`. **Startup guard:** in prod, if `GetAllElements()` yields 0 usable unexpired keys â†’ throw (no ephemeral fallback).
- **SecurityStamp revalidation:** `SecurityStampValidatorOptions.ValidationInterval = 1m`; `MaRevalidatingAuthenticationStateProvider : RevalidatingServerAuthenticationStateProvider` with `RevalidationInterval = 1m` reloads `AuthUser`, rejecting if null/`!IsActive`/stamp-mismatch/session-revoked. Stamp (GUID "N") rotates on: password change/reset, MFA enroll/disable/reset, recovery-code regen, role change, account disable/lock, explicit global logout.
- **Fixation defense:** `SignInAsync` only after full credential+MFA success (fresh ticket). MFA-pending state in a SEPARATE short-lived (5m) scheme `__Host-MindAttic.MfaPending` granting NO app access; exchanged for the real cookie only after TOTP/recovery verify.
- **All SignIn/SignOut via HTTP endpoints, never inside a circuit** (Â§5).
- **Session table:** `AuthSession` row per active session; `sid` claim in the cookie. Enables "sign out other sessions", per-session revoke, concurrency/impossible-travel forensics. Global logout rotates the stamp (kills all within â‰¤1m).
- **Open-redirect-safe returnUrl:** hardened `UrlSafety.IsLocalUrl` (reject control chars incl. `\t\r\n` before AND after decode; reject `//`, `/\`, scheme:, `@`, absolute URIs) + optional host allowlist (`ReturnUrlPolicy.AllowList` + `AllowedReturnUrlPrefixes`). Fallback `DefaultReturnUrl="/"`. Validated on GET and POST.
- **CSP nonce + HSTS:** per-request 128-bit nonce middleware (`script-src 'self' 'nonce-â€¦'; style-src 'self' 'nonce-â€¦'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`). HSTS (host-owned; library WARNs if absent in non-dev).

## 3. Lockout / Brute-force / Enumeration

- **Persistent, DB-backed throttle** (`AuthLoginThrottle`), per-Account AND per-IP scopes, survives restart + shared across instances. Optimistic concurrency via `RowVersion`.
- **Exponential backoff, no hard lockout** (anti-DoS, NIST-compliant): `BackoffFor(f) = f<=3 ? 0 : min(900s, 2^(f-4) s)`. Account counter resets ONLY on full success (password AND MFA). Per-IP scope: same curve, gating starts at 20 failures / rolling 10m; IPv6 keyed on /64.
- **Trusted client IP:** ONLY from `ForwardedHeaders` with host-supplied `KnownProxies`/`KnownNetworks` allowlist (default empty = fail-closed); never raw XFF.
- **Uniform response + uniform timing across ALL outcomes** (unknown/bad-pw/throttled/unverified/MFA-required): decoy Argon2id (Â§1), then `EnforceTimingFloorAsync(floor=750ms, jitterâ‰¤100ms)` measured from request start â€” do NOT short-circuit early on lockout. Startup asserts floor > worst-case verify.
- **Enumeration-safe register/reset/MFA-challenge:** generic responses, identical work + decoy paths, throttled verify endpoints, constant-time compares.
- **Reset tokens / recovery codes:** â‰¥128-bit (codes â‰¥50-bit), single-use, hashed at rest, short TTL, throttled verify, `FixedTimeEquals`. TOTP + recovery failures feed the SAME account backoff counter.
- **Progressive step-up:** server-verified CAPTCHA (Turnstile/hCaptcha) at soft threshold (5 account / per-IP); secret from Vault `Security` bucket. Optional cluster-wide anomaly brake.
- **Audit every attempt** (success+failure) to `AuthAuditLog`; reasons server-only, never surfaced; newline/null-sanitized (`SanitizeForLog` donor pattern); async/batched off the hot path.

## 4. MFA / TOTP / Recovery

- **TOTP pinned:** HMAC-SHA1, 6 digits, 30s period, window Â±1 step (3 steps/90s), secret 160-bit CSPRNG, Base32. `otpauth://` URI carries explicit `algorithm=SHA1&digits=6&period=30` (apps fail closed). Issuer from `Mfa.Issuer`.
- **Replay defense:** `AuthUserMfa.LastTotpStepUsed` (long). Reject `matchedStep <= LastTotpStepUsed`; update under `RowVersion` concurrency inside the login txn.
- **Verify-before-enable:** `BeginEnrollment` writes `PendingSecretEncrypted` + `PendingExpiresUtc=now+10m`, `Enabled=false`. `ConfirmEnrollment(code, reauthPassword)` requires valid TOTP from pending + fresh password â†’ promotes pendingâ†’active, sets `LastTotpStepUsed=confirmStep`, generates 10 recovery codes, bumps stamp. Orphan pending purged after TTL.
- **Secrets at rest:** TOTP secret encrypted via dedicated DP purpose `"MindAttic.Authentication.Totp.v1"` (key ring in Vault). Recovery codes stored ONLY as Argon2id+pepper hashes. otpauth secret shown ONCE on a `no-store` CSP-nonce'd page, never logged.
- **Step-up state machine:** post-password â†’ partial principal `amr=pwd` + `mfa=pending` (grants nothing). `ConfirmMfaChallenge` â†’ full principal `amr=[pwd,mfa]`, bumps stamp, resets lockout, 5m challenge TTL bound to the partial session.
- **Admin requires MFA (global policy, not per-page):** `MaPolicies.Admin = RequireRole(Admin) + RequireClaim(amr, mfa)`. Forced-enroll middleware: `IsInRole(Admin) && !MfaEnabled` â†’ redirect to allowlisted `/account/mfa/setup`; cannot reach admin surfaces until enrolled. Role changes bump stamp so live non-MFA admin sessions are forced through enrollment within â‰¤1m.
- **Rate limit:** challenge failures (TOTP + recovery) share the persistent account backoff; threshold 5; uniform constant-time responses.
- **Reset does NOT bypass MFA:** password reset preserves `Enabled`/secret/recovery codes; drops user into normal MFA challenge; never sets `amr=mfa`; never auto-logs-in. Admin can never become MFA-disabled via reset.
- **Device-loss recovery:** recovery code â†’ full session â†’ forced re-enroll (rotates secret + regenerates codes). All codes lost â‡’ out-of-band audited operator reset (logged with operator identity). Any MFA disable/rotate/regen requires fresh step-up + stamp bump.

## 5. Blazor / Packaging boundary

- **Endpoints own auth, never components.** `MapMindAtticAuthEndpoints()` maps `[ValidateAntiforgery]` minimal-API POSTs: `/_ma-auth/login`, `/logout`, `/change-password`, `/mfa-challenge`. These call `SignInAsync`/`SignOutAsync` before the body starts. `<MaLogin/>` etc. are presentation-only static SSR `<form method=post>`; zero `SignInAsync` in any component.
- **StartupFilter fail-closed:** `MindAtticAuthStartupFilter : IStartupFilter` asserts `UseForwardedHeaders`â†’`UseAuthentication`â†’`UseAuthorization`â†’`UseAntiforgery` are present and ordered before component endpoints; throws on missing antiforgery/auth. WARNs (non-dev) if `UseHsts` absent.
- **EF ownership, no drift:** all tables in dedicated `auth` schema via `ApplyMindAtticAuthConfiguration(modelBuilder, schema:"auth")`. NO FKs from auth tables into app tables. Package embeds a model fingerprint; `AddMindAtticAuthentication` runs a startup compatibility check (throws on stale migration). Each app applies config in `OnModelCreating` and runs its own `dotnet ef migrations add`. Ideas runs a one-time data migration mapping `Core.Entities.User` â†’ `AuthUser` (bcrypt hashes carried for rehash-on-login; `Cms.AuthorRawMarkup` stays an app claim).
- **Canonical constants:** `MaRoles`, `MaClaims`, `MaPolicies`. Apps EXTEND via `ConfigureAdditionalPolicies`, never redefine shared ones.
- **Branding constrained:** `AuthUiOptions` exposes text-encoded `ProductName`, validated `LogoUrl` (relative `/_content` or allowlisted https), `ThemeCssClass` (class, not markup), host-defined named `RenderFragment`s. NO `MarkupString`/raw HTML on any auth component; auth surface never honors `Cms.AuthorRawMarkup`.
- **Supply chain:** exact-pin `MindAttic.Vault` `[x.y.z]`; deterministic build; SourceLink; embedded PDB; NuGet package signing; private feed only; `packages.lock.json` committed; static assets under immutable `_content/MindAttic.Authentication/` (hosts must not shadow).
- **Bootstrap, NO defaults, race-safe:** `SeedAsync` requires Vault `Security:bootstrap-token`; absent in prod â‡’ throw (no invented default). Runs inside a DB transaction + app-level lock (unique bootstrap row / SQL app lock) so concurrent instances cannot double-seed; no-op if any Admin exists. Seeded admin gets `MustChangePassword=true` + `MustEnrollMfa=true`. NO dev-auto-login middleware anywhere.

## 6. Secrets handling (Vault contract)

- Add `Security` and `DataProtection` to `MindAtticConfigurationSource.Buckets` and a `SecuritySection` const to `VaultConfigurationKeys`.
- **Fail-CLOSED wrapper `IAuthSecrets`** over the `Security` section: `GetRequired(name)` throws `InvalidOperationException` if null/blank â€” a null pepper NEVER coerces to empty. Validated at startup via `IValidateOptions` + `IHostedService` (`ValidateOnStart`) before first request. Cache resolved secrets in memory after first read (KV availability mitigation).
- **Dev = writable file store; prod = read-only `IConfiguration`/`ConfigurationCredentialStore`.** Provisioning is a SEPARATE operator tool (`dotnet run --provision`) emitting CSPRNG pepper/KEK/reset-key: dev writes to `CredentialStore`/`TokenStore`; prod operator/IaC seeds env/Key Vault out-of-band; the running app NEVER writes (any prod rotation UI prints operator instructions, never `SetKey`).
- Secrets vs non-secret: SECRET = pepper, DP KEK/wrapping key, reset-token key, CAPTCHA secret, bootstrap token. NON-SECRET (appsettings) = Argon2 params, pepper key id, key lifetime, HIBP base URL. Redact `Security`/`DataProtection` buckets from any config dump; never log secret values or put them in audit `Reason` fields.

## 7. Password policy & recovery

- NIST-aligned: min 12, max 128 (â‰¥64 accepted), all printable Unicode + NFKC, NO composition rules, NO rotation, NO hints/KBA.
- HIBP k-anonymity (5-char SHA-1 prefix, `Add-Padding: true`), reject countâ‰¥1, 2s timeout, fail-open + bundled offline fallback, audit on skip.
- Password history (`AuthPasswordHistory`, depth 5) â€” reject reuse of current + last N on change AND reset.
- Change-password: current-pw constant-time verify + fresh reauth (â‰¤5m) + antiforgery â†’ rehash, push history, rotate stamp, keep current session only.
- Reset token: 256-bit CSPRNG base64url, single-use, TTL â‰¤15m, stored as HMAC-SHA256(Vault `reset-token-key`), bound to userId, constant-time lookup. Out-of-band email only; link base from `PublicBaseUrl` config (never `Request.Host`). On completion: rehash, push history, rotate stamp, consume token, invalidate all other tokens, audit, DO NOT auto-login (forces fresh login â†’ MFA). Per-account+per-IP throttle + â‰¤3 emails/address/hour cap.

## 8. Residual risks accepted (for the owner)
AITM/Evilginx session relay defeats TOTP (FIDO2 deferred to v2); pepper+KEK in process memory; pepper/KEK loss is catastrophic (DR runbook); KV outage = auth outage by fail-closed design; distributed low-and-slow stuffing under thresholds; â‰¤1m stale-principal window on live circuit; operator-reset is an MFA-bypass channel gated only by human process; edge WAF/rate-limit required and out of library scope.


---

# EF Schema (owned by the library, uth schema)

All tables in the dedicated **`auth`** schema, applied via `ApplyMindAtticAuthConfiguration(modelBuilder, schema:"auth")`. NO FKs into app tables.

**AuthUser** (PK Id GUID)
- Id GUID PK
- UserName nvarchar(256) NOT NULL; NormalizedUserName nvarchar(256) NOT NULL â€” UNIQUE index on NormalizedUserName
- Email nvarchar(256) NULL; NormalizedEmail nvarchar(256) NULL â€” index
- EmailVerified bit NOT NULL default 0
- PasswordHash nvarchar(512) NOT NULL â€” full PHC string (never raw bytes); algo-tagged for migration
- PasswordPepperKeyId nvarchar(16) NULL â€” e.g. "v2" (nullable for pre-pepper legacy rows)
- LegacyHashScheme nvarchar(16) NULL â€” "bcrypt"|"sha256" until first rehash-on-login
- PasswordUpdatedUtc datetime2 NOT NULL
- SecurityStamp nvarchar(64) NOT NULL â€” GUID "N", rotated on pw/mfa/role/disable/global-logout
- Role nvarchar(64) NOT NULL
- MfaEnabled bit NOT NULL default 0
- MustChangePassword bit NOT NULL default 0
- MustEnrollMfa bit NOT NULL default 0
- IsActive bit NOT NULL default 1
- LastLoginUtc datetime2 NULL
- CreatedUtc datetime2 NOT NULL
- RowVersion rowversion (concurrency token)

**AuthUserMfa** (1:1 with AuthUser)
- UserId GUID PK, FKâ†’AuthUser.Id
- Enabled bit NOT NULL default 0
- SecretEncrypted varbinary(512) NULL â€” DP-protected active 160-bit secret
- PendingSecretEncrypted varbinary(512) NULL â€” DP-protected, enrollment-in-progress
- PendingExpiresUtc datetime2 NULL â€” now+10min
- LastTotpStepUsed bigint NOT NULL default 0 â€” replay guard (consumed Unix step)
- ActivatedUtc datetime2 NULL
- RowVersion rowversion (concurrency token for replay-consume txn)

**AuthRecoveryCode** (1:many)
- Id GUID PK
- UserId GUID FKâ†’AuthUser.Id â€” indexed
- CodeHash nvarchar(512) NOT NULL â€” Argon2id(code + pepper)
- BatchId GUID NOT NULL â€” regeneration batch; regen invalidates prior batches
- UsedUtc datetime2 NULL â€” null = unused (single-use)
- CreatedUtc datetime2 NOT NULL

**AuthSession** (concurrent-session tracking / global logout)
- Id GUID PK â€” surfaced as `sid` claim
- AuthUserId GUID FKâ†’AuthUser.Id â€” indexed
- CreatedUtc datetime2 NOT NULL; LastSeenUtc datetime2 NOT NULL; AbsoluteExpiryUtc datetime2 NOT NULL
- IpHash char(64) NOT NULL â€” SHA-256 of canonical IP (never raw)
- UserAgent nvarchar(512) NOT NULL
- RevokedUtc datetime2 NULL; RevokedReason nvarchar(64) NULL

**AuthLoginThrottle** (persistent per-account AND per-IP backoff â€” replaces all in-memory lockout)
- Id bigint identity PK
- Scope tinyint NOT NULL â€” 0=Account, 1=Ip
- KeyHash binary(32) NOT NULL â€” SHA-256 of normalized key (email NFKC+Trim+lower, or IP /64) â€” UNIQUE index on (Scope, KeyHash)
- ConsecutiveFailures int NOT NULL default 0
- FirstFailureUtc datetime2 NOT NULL; LastFailureUtc datetime2 NOT NULL
- NextAttemptAllowedUtc datetime2 NULL â€” backoff gate; null = no wait
- RowVersion rowversion (optimistic concurrency for cross-instance increments)

**AuthAuditLog** (every login/register/reset/MFA/change attempt)
- Id bigint identity PK
- TimestampUtc datetime2 NOT NULL â€” index
- UserId GUID NULL â€” null when account unknown (no enumeration via DB join)
- UserNameAttempted nvarchar(256) NULL
- EventType tinyint NOT NULL â€” Login/Register/PasswordReset/MfaChallenge/ChangePassword/MfaEnroll/RecoveryUsed/RecoveryRegen/MfaDisabled/MfaOperatorReset/HibpOnlineSkipped
- Outcome tinyint NOT NULL â€” Success/Failure/Throttled/StepUpRequired
- ReasonCode tinyint NOT NULL â€” UnknownUser/BadPassword/Locked/Unverified/MfaRequired/MfaBad/Ok (SERVER-ONLY, never surfaced)
- AccountKeyHash binary(32) NULL â€” index
- SourceIp nvarchar(45) NOT NULL â€” canonicalized, /64 for v6
- UserAgent nvarchar(512) NOT NULL â€” sanitized
- CaptchaPresented bit NOT NULL default 0

**AuthPasswordHistory** (reuse prevention, keep newest N=5 per user)
- Id GUID PK
- UserId GUID FKâ†’AuthUser.Id â€” indexed
- PasswordHash nvarchar(512) NOT NULL â€” Argon2id PHC
- CreatedUtc datetime2 NOT NULL

**AuthPasswordResetToken**
- Id GUID PK
- UserId GUID FKâ†’AuthUser.Id â€” indexed (UserId, ConsumedUtc)
- TokenHash char(64) NOT NULL â€” HMAC-SHA256 hex of token, UNIQUE index (never plaintext)
- CreatedUtc datetime2 NOT NULL; ExpiresUtc datetime2 NOT NULL â€” Created+15m
- ConsumedUtc datetime2 NULL â€” single-use
- RequestIp nvarchar(45) NOT NULL; RequestUserAgent nvarchar(512) NOT NULL


---

# Public API

// â”€â”€ DI / middleware â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
public static AuthBuilder AddMindAtticAuthentication(
    this IServiceCollection services, IConfiguration configuration, Action<MindAtticAuthOptions> configure); // ValidateOnStart
public static void UseMindAtticAuthentication(this IApplicationBuilder app); // marker; real ordering enforced by MindAtticAuthStartupFilter : IStartupFilter
public static void MapMindAtticAuthEndpoints(this IEndpointRouteBuilder app);
//   POST /_ma-auth/login           [ValidateAntiforgery][RequireRateLimiting("ma-login")]
//   POST /_ma-auth/logout          [ValidateAntiforgery]
//   POST /_ma-auth/change-password [ValidateAntiforgery]
//   POST /_ma-auth/mfa-challenge   [ValidateAntiforgery][RequireRateLimiting("ma-mfa")]
public static ModelBuilder ApplyMindAtticAuthConfiguration(this ModelBuilder b, string schema = "auth");

public sealed class MindAtticAuthOptions {
    public string AppName { get; set; } = "";                 // REQUIRED: DP app-name + cookie purpose
    public TimeSpan AbsoluteSessionTimeout { get; set; } = TimeSpan.FromHours(8);
    public TimeSpan IdleTimeout            { get; set; } = TimeSpan.FromMinutes(30);
    public TimeSpan RevalidationInterval   { get; set; } = TimeSpan.FromMinutes(1);
    public ReturnUrlPolicy ReturnUrlPolicy { get; set; } = ReturnUrlPolicy.LocalOnly;
    public string[] AllowedReturnUrlPrefixes { get; set; } = Array.Empty<string>();
    public string   DefaultReturnUrl       { get; set; } = "/";
    public string[] TrustedProxies         { get; set; } = Array.Empty<string>(); // KnownProxies (fail-closed empty)
    public string   PublicBaseUrl          { get; set; } = "";  // reset links; never Request.Host
    public string   BootstrapAdminSecretKey{ get; set; } = "bootstrap-token"; // Vault Security bucket
    public string   DbSchema               { get; set; } = "auth";
    public AuthUiOptions       Ui     { get; set; } = new();
    public AuthCryptoOptions   Crypto { get; set; } = new();
    public LockoutOptions      Lockout{ get; set; } = new();
    public MfaOptions          Mfa    { get; set; } = new();
    public PasswordPolicyOptions Password { get; set; } = new();
    public Action<AuthorizationBuilder>? ConfigureAdditionalPolicies { get; set; } // extend, never redefine
    public Task SeedAsync(IServiceProvider sp, CancellationToken ct);              // race-safe bootstrap
}

// â”€â”€ Crypto â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
public sealed class AuthCryptoOptions {
    public int MemoryKiB=65536; public int Iterations=3; public int DegreeOfParallelism=4;
    public int SaltLength=16; public int HashLength=32; public int MaxPasswordChars=128;
    public string CurrentPepperKeyId="v2"; public int MaxConcurrentHashes=Environment.ProcessorCount;
}
public interface IPasswordHasher {
    string Hash(string password, string pepperKeyId);                       // returns PHC
    PasswordVerifyResult Verify(string password, string storedHash, string? pepperKeyId);
}
public readonly record struct PasswordVerifyResult(bool Succeeded, bool NeedsRehash);

// â”€â”€ Secrets (fail-closed) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
public interface IAuthSecrets {
    string GetRequired(string name);                  // throws if null/blank; NEVER returns ""
    string? GetOptional(string name);
    (string keyId, byte[] value) ActivePepper();
    IReadOnlyDictionary<string, byte[]> AllPeppers(); // keyId -> bytes, for verify
    byte[] DataProtectionKek();                        // dev only
    byte[] ResetTokenKey();
}

// â”€â”€ Authentication â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
public interface IAuthenticationService {
    Task<LoginResult> LoginAsync(LoginRequest req, CancellationToken ct);          // uniform outcome+timing
    Task LogoutAsync(Guid sessionId, bool global, CancellationToken ct);
    Task ChangePasswordAsync(Guid userId, string current, string next, bool reauthFresh, CancellationToken ct);
}
public interface IAccountLockoutService {
    Task<ThrottleDecision> CheckAsync(ThrottleScope scope, string normalizedKey, CancellationToken ct);
    Task RecordFailureAsync(ThrottleScope scope, string normalizedKey, CancellationToken ct); // RowVersion retry
    Task ResetAsync(ThrottleScope scope, string normalizedKey, CancellationToken ct);          // FULL success only
}
public readonly record struct ThrottleDecision(bool Allowed, TimeSpan RetryAfter, bool RequireCaptcha);

// â”€â”€ MFA â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
public interface ITotpService {
    EnrollmentInfo BeginEnrollment(Guid userId, string accountName);               // writes pending; { Base32Secret, OtpAuthUri, QrPngBytes }
    Task<MfaConfirmResult> ConfirmEnrollmentAsync(Guid userId, string code, string reauthPassword, CancellationToken ct); // returns plaintext recovery codes once
    Task<bool> VerifyTotpAsync(Guid userId, string code, CancellationToken ct);     // Â±1 window, step>LastTotpStepUsed under RowVersion
    Task<bool> VerifyRecoveryCodeAsync(Guid userId, string code, CancellationToken ct); // constant-time, single-use
    Task<IReadOnlyList<string>> RegenerateRecoveryCodesAsync(Guid userId, string reauthPassword, CancellationToken ct);
    Task DisableMfaAsync(Guid userId, string reauthPassword, CancellationToken ct); // step-up + stamp bump + audit
}

// â”€â”€ Password policy / reset â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
public interface IPasswordPolicy { Task<PasswordValidationResult> ValidateAsync(string pwd, AuthUser? user, CancellationToken ct); }
public interface IPasswordResetService {
    Task<ResetInitiationResult> InitiateAsync(string emailOrUsername, string ip, string ua, CancellationToken ct); // always generic
    Task<ResetCompletionResult> CompleteAsync(string token, string userId, string newPassword, string ip, string ua, CancellationToken ct);
}

// â”€â”€ Constants / policies â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
public static class MaRoles  { public const string Admin = "Admin"; }
public static class MaClaims { public const string SecurityStamp="ma:stamp"; public const string Amr="amr"; public const string AmrMfa="mfa"; public const string SessionId="sid"; public const string LastActivityUtc="ma:la"; }
public static class MaPolicies { public const string Admin="ma:Admin"; public const string MfaSatisfied="ma:MfaSatisfied"; }
//   AddPolicy(MfaSatisfied, p => p.RequireClaim(Amr, AmrMfa));
//   AddPolicy(Admin, p => p.RequireRole(MaRoles.Admin).RequireClaim(Amr, AmrMfa));

// â”€â”€ EF entry points (IEntityTypeConfiguration) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
internal sealed class AuthUserConfiguration        : IEntityTypeConfiguration<AuthUser>
internal sealed class AuthUserMfaConfiguration     : IEntityTypeConfiguration<AuthUserMfa>
internal sealed class AuthRecoveryCodeConfiguration: IEntityTypeConfiguration<AuthRecoveryCode>
internal sealed class AuthSessionConfiguration     : IEntityTypeConfiguration<AuthSession>
internal sealed class AuthLoginThrottleConfiguration: IEntityTypeConfiguration<AuthLoginThrottle>
internal sealed class AuthAuditLogConfiguration    : IEntityTypeConfiguration<AuthAuditLog>
internal sealed class AuthPasswordHistoryConfiguration : IEntityTypeConfiguration<AuthPasswordHistory>
internal sealed class AuthPasswordResetTokenConfiguration : IEntityTypeConfiguration<AuthPasswordResetToken>

// â”€â”€ Components (presentation-only; post to endpoints) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// <MaLogin/> <MaLogout/> <MaChangePassword/> <MaMfaSetup/> <MaMfaChallenge/> <MaAccount/>
// MaRevalidatingAuthenticationStateProvider : RevalidatingServerAuthenticationStateProvider (RevalidationInterval = Options.RevalidationInterval)
// VaultXmlRepository : IXmlRepository (read all from DataProtection bucket; StoreElement writes dev, throws prod)


---

# Security checklist (control → standard)

- Argon2id m=64MiB,t=3,p=4,salt16,hash32 with startup floors -> OWASP Password Storage CS; NIST 800-63B 5.1.1.2; ASVS V2.4.1/V2.4.2/V2.4.4 -> IPasswordHasher over Konscious 1.3.1, floors throw at startup
- Self-describing PHC + rehash-on-login (param/algo/pepper upgrade) -> OWASP Password Storage CS; ASVS V2.4.1 -> NeedsRehash on every successful verify
- Pepper via HMAC-SHA256 pre-hash, key in Vault Security bucket, separate trust domain from DB -> OWASP Password Storage CS (peppering); NIST 800-63B 5.1.1.2; ASVS V2.10.4/V6.4.1 -> IAuthSecrets.ActivePepper(), versioned keyId in AuthUser.PasswordPepperKeyId
- Versioned additive pepper rotation, backed up in KV -> OWASP Password Storage CS; ASVS V6.4.2 -> CurrentPepperKeyId, AllPeppers() for verify, retire after drain
- Transparent legacy bcrypt/SHA256 migration on login (verify raw, rehash Argon2id+pepper) -> OWASP Password Storage CS; ASVS V2.4.1 -> LegacyHashScheme column, prefix detection
- Constant-time verify + startup decoy Argon2id for unknown/inactive users; single generic error -> OWASP Auth CS; NIST 800-63B 5.2.2; ASVS V2.2.1/V3.2 -> FixedTimeEquals, checks after verify
- Password input cap 128 pre-HMAC + NFKC + bounded SemaphoreSlim(CPU) hash gate + lockout pre-filter -> OWASP Auth CS; ASVS V2.2.1/V11.x; NIST 800-63B 5.2.2 -> MaxPasswordChars, MaxConcurrentHashes, gate after cheap throttle check
- __Host- cookie, HttpOnly, Secure=Always, SameSite=Lax, Path=/, no Domain -> OWASP Session Mgmt CS; ASVS 3.4.1-3.4.5; NIST 800-63B 7.1.1 -> __Host-MindAttic.Auth
- 8h absolute (SlidingExpiration=false) + 30m idle via last-activity claim -> ASVS 3.3.1/3.3.2; NIST 800-63B 7.2; OWASP Session Mgmt CS -> ExpireTimeSpan + OnValidatePrincipal idle check; 30-day sliding removed
- Data Protection key ring in Vault, encrypted at rest (KV-wrapped prod / cert / dev AES-GCM), per-app SetApplicationName, 90d lifetime -> MS DP guidance; ASVS 6.4.1/6.4.2; OWASP Crypto Storage CS -> VaultXmlRepository + ProtectKeysWithAzureKeyVault
- DP key provisioning out-of-band (read-only prod), fail-fast if 0 usable keys -> ASVS 6.4.1/14.1.x; OWASP Secrets Mgmt CS -> StoreElement throws in prod, startup guard
- SecurityStamp revalidation 1m on BOTH cookie and live circuit -> MS Blazor security; ASVS 3.3.3/3.3.4 -> SecurityStampValidatorOptions + MaRevalidatingAuthenticationStateProvider
- Session fixation: fresh ticket only after full auth; MFA-pending in separate __Host-MindAttic.MfaPending scheme -> OWASP Session Mgmt CS; ASVS 3.2.1/3.2.3
- SignIn/SignOut only via HTTP endpoints, never circuit -> MS Blazor auth; OWASP Session Mgmt CS -> MapMindAtticAuthEndpoints
- Antiforgery on all state-changing POSTs, __Host antiforgery cookie, UseAntiforgery ordered after auth -> ASVS 4.2.2/13.2.3; OWASP CSRF CS -> ValidateAntiforgery + StartupFilter assertion
- Global logout + per-session AuthSession table -> ASVS 3.3.1-3.3.4; NIST 800-63B 7.1; OWASP Session Mgmt CS -> stamp rotation + sid claim
- Open-redirect-safe returnUrl (hardened IsLocalUrl + optional allowlist) -> ASVS 5.1.5; OWASP Unvalidated Redirects CS -> UrlSafety.IsLocalUrl, ReturnUrlPolicy
- Per-request CSP nonce (no unsafe-inline) + HSTS preload -> ASVS 14.4.3/14.4.5; OWASP Session Mgmt CS -> nonce middleware
- Persistent DB-backed per-account+per-IP exponential backoff (survives restart/scale-out) -> ASVS 2.2.1/2.2.2; NIST 800-63B 5.2.2 -> AuthLoginThrottle, RowVersion
- Exponential backoff not hard lockout (anti-DoS), reset only on full pwd+MFA success -> NIST 800-63B 5.2.2; OWASP Auth CS -> BackoffFor curve
- Per-IP throttle from trusted-proxy allowlist only, IPv6 /64 keying -> ASVS 2.2.1; OWASP Credential Stuffing CS -> ForwardedHeaders KnownProxies (fail-closed empty)
- Uniform response + timing floor 750ms+jitter across all outcomes incl throttled -> ASVS 2.2.4; OWASP Auth CS -> EnforceTimingFloorAsync, no early return
- Enumeration-safe register/reset/MFA-challenge (generic response, decoy work) -> ASVS 2.5.x/2.1.x; OWASP Forgot Password CS
- Reset tokens/recovery codes >=128/50-bit, single-use, hashed at rest, throttled, constant-time -> NIST 800-63B 5.1.2/5.1.3.2; ASVS 2.7/2.8 -> HMAC reset token, Argon2id recovery codes
- Progressive server-verified CAPTCHA at soft threshold + global anomaly brake -> ASVS 2.2.1; OWASP Credential Stuffing CS -> secret from Vault Security bucket
- Full audit log of every attempt (server-only reasons, sanitized) -> ASVS 7.1/7.2; NIST 800-63B 5.2.2; OWASP Logging CS -> AuthAuditLog
- TOTP SHA1/6/30 window +/-1, explicit otpauth params -> RFC 6238 4/5.2; NIST 800-63B 5.1.4.2; OWASP MFA CS
- TOTP single-use replay guard via LastTotpStepUsed under RowVersion -> RFC 6238 5.2; NIST 800-63B 5.2.8; ASVS 2.8.4/2.8.5
- Verify-before-enable enrollment (pending secret, 10m TTL, reauth) -> NIST 800-63B 6.1.1; ASVS 2.8.1; OWASP MFA CS
- TOTP secret + recovery codes encrypted/hashed at rest (dedicated DP purpose / Argon2id+pepper), shown once no-store -> NIST 800-63B 5.1.4.2; ASVS 2.8.2/6.2.1
- 10 recovery codes, >=50-bit, single-use, regenerate invalidates batch, remaining-count warning -> NIST 800-63B 5.1.2; ASVS 2.8.4/2.7.6
- Server-side step-up state machine (partial principal grants nothing; amr=mfa only after verify) -> NIST 800-63B 4.2; ASVS 2.8.x/3.3.x; OWASP MFA CS
- Admin-requires-MFA as global policy + forced-enroll middleware + stamp bump on role change -> NIST 800-63B 4.2.1; ASVS 2.8.6/1.2.x
- MFA challenge endpoint rate-limited via shared persistent lockout, uniform constant-time responses -> NIST 800-63B 5.2.2/5.1.4.2; ASVS 2.2.1/2.8.x
- Password reset preserves MFA, never auto-logs-in, admin never MFA-disabled via reset -> NIST 800-63B 6.1.2.3/5.2.1; ASVS 2.5.x/2.8.7
- Device-loss recovery: recovery code or audited operator reset; step-up for all MFA-state changes -> NIST 800-63B 6.1.2; ASVS 2.8.x
- NIST-aligned password policy min12/max128, all Unicode+NFKC, no composition/rotation/hints -> NIST 800-63B 5.1.1.2; ASVS 2.1.1-2.1.10
- HIBP k-anonymity (5-char SHA1 prefix), reject count>=1, fail-open + offline fallback + audit -> NIST 800-63B 5.1.1.2; ASVS 2.1.7; OWASP Auth CS
- Password history depth 5, reject reuse on change+reset -> ASVS 2.1.x; NIST 800-63B
- Change-password requires current-pw + fresh reauth(5m) + antiforgery, rotate stamp, keep current session -> ASVS 2.1.x/3.3.x
- Reset link base from PublicBaseUrl config not Request.Host; returnUrl via IsLocalUrl -> ASVS 5.1.5/1.x; OWASP Unvalidated Redirects CS
- Fail-closed required-secret resolution (null pepper never coerces to empty), validate at startup -> ASVS 7.4.1/14.2.1; OWASP Auth CS; NIST 800-63B 5.2.2 -> IAuthSecrets.GetRequired throws
- Dedicated isolated Vault Security/DataProtection buckets, redacted from config dumps -> ASVS 6.4.1/2.10.4; NIST 800-63B 5.1.1.2
- No hardcoded/default credentials, no dev-auto-login; operator/Vault bootstrap token, race-safe seed -> ASVS 2.3.1/2.10/1.2.x; NIST 800-63B 5.1.1 -> SeedAsync app-lock, throws if absent in prod
- EF in isolated 'auth' schema, no FK to app tables, startup model-fingerprint check -> ASVS 1.1.x; OWASP Password Storage CS (migration)
- Centralized role/claim/policy constants, apps extend not redefine -> ASVS 4.1.1-4.1.5; NIST 800-63B AAL2 (admin)
- StartupFilter asserts middleware presence/order (fail-closed), WARN on missing HSTS -> ASVS 14.4/1.4.x
- Supply-chain: exact-pin Vault [x.y.z], signed package, lockfile, private feed, immutable _content -> ASVS 10.3.2/14.2.x; OWASP Supply Chain
- Branding constrained: text-encoded ProductName, validated LogoUrl, ThemeCssClass, no MarkupString, never honor Cms.AuthorRawMarkup -> ASVS 5.3.3/5.1.3; OWASP XSS CS
- Reverse-proxy: ForwardedHeaders with KnownProxies allowlist (fail-closed empty) so Secure cookie + per-IP lockout work -> ASVS 1.9.1/14.4.6; OWASP Auth CS


# Implementation order

- LIBRARY 1 â€” Vault prep: add SecuritySection const to VaultConfigurationKeys; add 'Security' and 'DataProtection' to MindAtticConfigurationSource.Buckets; build IAuthSecrets fail-closed wrapper + AuthSecretsOptions with ValidateOnStart IHostedService.
- LIBRARY 2 â€” Crypto core: AuthCryptoOptions (+startup floor validation), IPasswordHasher Argon2id impl over Konscious 1.3.1 with HMAC pepper pre-hash, PHC encode/parse, legacy bcrypt/SHA256 verify+NeedsRehash, startup decoy hash, SemaphoreSlim hash gate, ZeroMemory. Calibrate t on representative hardware.
- LIBRARY 3 â€” EF model: all 8 entities + IEntityTypeConfiguration in 'auth' schema, ApplyMindAtticAuthConfiguration, embedded model fingerprint + startup compatibility check.
- LIBRARY 4 â€” Lockout: AuthLoginThrottle persistence, IAccountLockoutService with RowVersion optimistic increments + lazy TTL eviction, BackoffFor curve, ThrottleDecision, trusted-IP /64 normalization.
- LIBRARY 5 â€” Audit: AuthAuditLog writer (async/batched, SanitizeForLog), reason enums server-only.
- LIBRARY 6 â€” Password policy + reset: IPasswordPolicy (length/NFKC/HIBP k-anonymity fail-open+offline fallback/history), AuthPasswordHistory, IPasswordResetService (HMAC reset token, enumeration-safe, no auto-login, preserves MFA).
- LIBRARY 7 â€” MFA: ITotpService (RFC6238 SHA1/6/30 +/-1, LastTotpStepUsed replay guard), AuthUserMfa, AuthRecoveryCode (Argon2id+pepper, single-use, batch regen), DP purpose for secret encryption, verify-before-enable enrollment, otpauth/QR.
- LIBRARY 8 â€” Session + Data Protection: cookie scheme wiring, VaultXmlRepository (read DataProtection bucket; StoreElement dev-write/prod-throw) + at-rest encryption, SetApplicationName per app, 90d lifetime, prod startup key guard, SecurityStampValidatorOptions=1m, MaRevalidatingAuthenticationStateProvider=1m, AuthSession + global logout, MfaPending scheme, idle-timeout claim.
- LIBRARY 9 â€” AuthenticationService.LoginAsync pipeline: cheap throttle pre-filter -> decoy/real verify under hash gate -> MFA step-up -> ResetAsync only on full success -> audit -> EnforceTimingFloorAsync; uniform LoginResult.
- LIBRARY 10 â€” DI + middleware + endpoints: AddMindAtticAuthentication (options ValidateOnStart, AddAuthorizationBuilder with MaPolicies, ForwardedHeaders, DataProtection, ConfigureAdditionalPolicies hook), MindAtticAuthStartupFilter, MapMindAtticAuthEndpoints, SeedAsync race-safe bootstrap (no defaults), forced-enroll middleware, CSP nonce middleware.
- LIBRARY 11 â€” Components: MaLogin/MaLogout/MaChangePassword/MaMfaSetup/MaMfaChallenge/MaAccount (presentation-only static SSR forms), AuthUiOptions constrained branding, returnUrl resolver.
- LIBRARY 12 â€” Provisioning tool: separate 'dotnet run --provision' entrypoint generating CSPRNG pepper/dp-kek/reset-token-key/bootstrap-token into the dev file store; prints values for prod operator KV seeding (never writes prod).
- LIBRARY 13 â€” Packaging: deterministic build, SourceLink, embedded PDB, package signing, exact-pin MindAttic.Vault, packages.lock.json, publish to private feed.
- ADOPT 1 â€” StreetSamurai (greenest donor besides Frontend, highest-risk gaps): add ApplyMindAtticAuthConfiguration to its DbContext, dotnet ef migrations add, AddMindAtticAuthentication(o.AppName='StreetSamurai'), remove DevAutoLoginMiddleware + hardcoded default password + in-memory lockout, map endpoints, seed via Vault bootstrap token.
- ADOPT 2 â€” Ideas: same wiring (o.AppName='Ideas', ConfigureAdditionalPolicies AuthorRawMarkup), plus one-time data migration mapping Core.Entities.User -> AuthUser (carry bcrypt hashes with LegacyHashScheme='bcrypt' for rehash-on-login), set ReturnUrlPolicy.AllowList, replace 30-day sliding sessions.
- ADOPT 3 â€” Tutor (cautionary baseline, most work): replace plain SHA256 LocalAuthController entirely, migrate any existing 'aaa' admin to a forced-reset row, wire full library, remove hardcoded creds, add sessions/lockout/MFA.
- POST â€” Per-deployment ops (out of library): seed pepper/DP-keys/reset-key/bootstrap-token into Key Vault, configure ProtectKeysWithAzureKeyVault, UseHsts, edge WAF/rate-limit, NTP, ForwardedHeaders KnownProxies, key-age monitoring/alerting, DR runbook for pepper/KEK backup.


# MUST-FIX (red-team — fold in before/at build)

- DP key-ring runtime read must fail-closed and never shrink: cache validated key elements in memory after the successful startup read, set AutoGenerateKeys=false in prod, and treat any subsequent empty/shrunk GetAllElements (Vault swallows IO/parse errors to 'no elements') as a logged+alerted error rather than triggering key rollover or silent regeneration. The current startup-only guard does not cover runtime corruption.
- Assert at startup (when IsProduction) that pepper, reset-token-key, and the DP KEK resolve from the read-only ConfigurationCredentialStore (env/Key Vault), NOT from the writable %APPDATA% file store. The roaming file store is shared across ALL MindAttic apps and other tooling and stores secrets as plaintext JSON; relying on it in prod contradicts the 'no plaintext secret files' goal. For dev, tighten the Security/DataProtection bucket directory ACLs to owner-only at startup (or loudly WARN).
- Define the cluster-wide anomaly brake as a concrete, enabled-by-default control (cluster failure-rate / distinct-failing-accounts-per-window â†’ force CAPTCHA on all logins) and gate the Argon2 decoy path behind the per-IP throttle. Distributed credential stuffing and distributed Argon2 decoy-flood currently slip under both the per-account (1 failure/account) and per-/64 (botnet-spread) thresholds; the 'optional' brake and 'edge WAF out of scope' leave a real gap for an InfoSec-grade product. Make the edge WAF/global rate-limit a documented HARD dependency, and elevate 'configure ForwardedHeaders KnownProxies' from POST-ops nicety to security-critical (empty allowlist collapses per-IP throttle to global behind a proxy).
- Invalidate / require rotation of the Vault bootstrap-token immediately after a successful seed, and make 'pepper + KEK backed up in KV with soft-delete and a TESTED restore drill' a hard pre-launch gate. A lingering valid bootstrap token is a standing backdoor; an untested backup is equivalent to no backup given the catastrophic loss residual.
- Harden the operator out-of-band MFA reset: require dual-control (two distinct operator identities) for Admin-role targets and send an out-of-band notification to the account owner's verified email on every operator MFA reset. As written it is a single-human-gated MFA bypass with audit-only detection.
- Run a proactive forced-reset campaign for dormant legacy bcrypt rows rather than relying solely on next-login rehash; post-breach, indefinitely-crackable bcrypt-12 rows are an unbounded residual an InfoSec owner should not accept. (Currently only an open decision.)


# Open decisions for the owner

- Argon2id iteration count 't' MUST be calibrated on actual PROD hardware to hit ~250-500ms/verify (Konscious pure-managed is 2-4x slower than native); confirm the target latency and re-benchmark on every hardware change. Default t=3 is a starting point, not a guarantee.
- Timing-floor value: 750ms + <=100ms jitter is proposed. Confirm acceptable login latency vs enumeration protection; floor must be validated > worst-case verify at startup.
- HIBP fail-open vs fail-closed: spec chose FAIL-OPEN online + bundled offline fallback + audited skip. Confirm this availability/security trade is acceptable for an InfoSec-grade product (fail-closed would self-DoS all password changes on HIBP outage).
- Session timeouts: 8h absolute / 30m idle chosen (tighter than NIST AAL2's 12h/30m). Confirm these exact values; kiosk/operator workflows may want tighter.
- Circuit + cookie revalidation interval: 1 minute chosen (bounds revoked-admin window to <=60s at cost of one indexed stamp read/user/minute). Confirm the DB-load vs staleness trade; instant circuit-kill (CircuitHandler abort) is deferred to a later version.
- Admin out-of-band MFA reset (all recovery codes lost): the library audits the operator action but cannot enforce operator identity-proofing rigor. The owner MUST define the human runbook for verifying the requester (this is a real MFA-bypass channel).
- CAPTCHA provider: Turnstile assumed as default CaptchaProviderId. Confirm provider choice and whether the global cluster-wide anomaly brake is enabled by default.
- Non-Azure prod hosting: ProtectKeysWithAzureKeyVault is Azure-specific. If any of the three apps deploy off-Azure, the owner must choose the at-rest DP wrapping mechanism (ProtectKeysWithCertificate) per deployment, else the key ring risks plaintext-at-rest.
- Concurrent-session / impossible-travel RESPONSE policy: the AuthSession table enables detection, but auto-revoke vs alert-only is a product decision left to the owner (without a policy the data is forensic-only).
- Dormant-account legacy bcrypt rows stay crackable (at bcrypt-12 cost) from a DB-only breach until each user next logs in. Decide whether to run a proactive forced-reset campaign for dormant accounts rather than relying solely on next-login upgrade.
- Cross-app SSO is OUT of scope for v1 (per-app SetApplicationName isolation). Confirm the three apps are intended as separate trust boundaries (no shared login).


# Residual risks accepted

- AITM/Evilginx real-time session relay defeats TOTP â€” FIDO2/WebAuthn phishing-resistant auth deferred to v2. Acceptable for AAL2 v1 given TOTP is still a strong second factor against non-relay attacks.
- Pepper and KEK reside in process memory while running â€” unavoidable for any peppered scheme; mitigated by ZeroMemory on transient buffers. Accept.
- KV/Vault outage = auth outage by fail-closed design. Correct trade for an InfoSec product (the alternative fails open and weakens hashing).
- â‰¤60s stale-principal window on a live circuit before revocation takes effect. Acceptable for AAL2; tighten only if the owner deems admin revocation latency unacceptable.
- HIBP fail-open online + bundled offline fallback + audited skip. Acceptable: blocking all password changes on a third-party outage is a self-inflicted DoS, and the offline corpus still blocks the worst-known passwords.
- Dev-only plaintext secret files and dev cookie-forgery (KEK co-located with key ring in the file store) â€” acceptable strictly for local dev provided prod is asserted to use Key Vault/env and dev is documented as a non-production trust boundary.
- Distributed low-and-slow credential stuffing that stays under all thresholds â€” partially accepted, but only AFTER the anomaly brake + edge WAF mustFix items are in place; without them the residual is too large.


# Red-team verdict

The spec is strong and, after the six mustFix items, ready to build to. It correctly eliminates every audit-confirmed gap (weak hashing, default creds, dev-auto-login, volatile lockout, sliding sessions, missing MFA/audit/breach-check, plaintext-coercion via the fail-closed IAuthSecrets wrapper, enumeration, weak reset) and its control-to-standard mappings are sound for ASVS L2/L3-leaning and NIST AAL2. The most important Vault-grounded risk â€” that the file store SWALLOWS all errors and returns null â€” is directly neutralized by IAuthSecrets.GetRequired + ValidateOnStart. The remaining real exposures are: (1) the DP key-ring read path is fail-closed only at startup, not at runtime, so swallowed corruption mid-run could silently shrink or regenerate keys; (2) the shared roaming %APPDATA% file store is plaintext and prod must be hard-asserted onto Key Vault/env, not merely 'recommended'; (3) distributed credential-stuffing and distributed Argon2 decoy-flood slip under the defined thresholds, leaving the 'optional' anomaly brake and 'out-of-scope' edge WAF as undefined load-bearing dependencies; plus tightening the bootstrap-token lifecycle, the operator-reset bypass channel, and the dormant-legacy-row crack window. None of these are architectural rewrites â€” they are concrete hardening of edges the design already anticipates. Fold in the mustFix list and build.


---

# Ratified owner decisions (2026-06-04)
- **MFA:** TOTP + recovery codes in v1; WebAuthn/FIDO2 deferred to v2 (additive). AITM relay accepted as v1 residual.
- **Existing-user cutover:** carry legacy hashes, transparently upgrade to Argon2id+pepper on next login; proactive forced-reset for dormant accounts (no indefinite weak-hash residual).
- **HIBP:** fail-open online + bundled offline fallback + audited skip.
- **Trust boundaries:** the three apps are SEPARATE (per-app DataProtection isolation); no cross-app SSO in v1.
- Plus all 6 red-team must-fixes are folded in as non-negotiable.
