# MindAttic.Authentication — Public API Reference

Exhaustive reference for every public type the library exposes (namespace `MindAttic.Authentication.*`).
For the *why* behind each control see [`SECURITY_SPEC.md`](SECURITY_SPEC.md); for wiring see
[`INTEGRATION.md`](INTEGRATION.md); for config keys see [`CONFIGURATION.md`](CONFIGURATION.md).

> **Versioning:** major-version-only. The assembly/package version is `1.0.0` for all of v1; the next
> release is `2.0.0`, then `3.0.0` — never `1.1.0`/`1.0.1`. The frozen behaviors below only change across
> a major bump. See [`VERSIONING.md`](VERSIONING.md).

---

## 1. Constants — `MindAttic.Authentication`

```csharp
public static class MaClaims {
    public const string UserId        = "ma:uid";
    public const string SecurityStamp = "ma:stamp";
    public const string SessionId     = "ma:sid";
    public const string Amr           = "amr";        // "pwd", "mfa"
}
public static class MaRoles    { public const string Admin = "Admin"; }
public static class MaPolicies { public const string Admin = "ma:admin"; }   // RequireRole(Admin) + RequireClaim(amr,"mfa")
public static class MaSchemes  {
    public const string Cookie     = "MindAttic.Auth";
    public const string MfaPending = "MindAttic.MfaPending";   // short-lived, pre-MFA, grants no app access
}
```

## 2. Options — `MindAttic.Authentication.Options`

| Type | Bound from | Key members (defaults) |
|---|---|---|
| `AuthCryptoOptions` | `MindAttic:Auth:Crypto` | `MemoryKiB=65536`, `Iterations=3`, `Parallelism=4`, `SaltBytes=16`, `HashBytes=32`, `MinPasswordChars=12`, `MaxPasswordChars=128`, `CurrentPepperKeyId="v1"`, `MaxConcurrentHashes=0` (⇒ `ProcessorCount`). `ValidateOrThrow()` enforces OWASP floors at startup. Floor consts: `Floor*`. |
| `MfaOptions` | `MindAttic:Auth:Mfa` | `Issuer="MindAttic"`, `Digits=6`, `PeriodSeconds=30`, `WindowSteps=1`, `SecretBytes=20`, `RecoveryCodeCount=10`, `RecoveryCodeBytes=10`, `PendingEnrollmentMinutes=10`, `RequireForAdmin=true`. |
| `AuthPolicyOptions` | `MindAttic:Auth:Policy` | `MinLength=12`, `MaxLength=128`, `CheckHibp=true`, `HibpRangeBaseUrl`, `HibpTimeoutMs=2000`, `HibpFailOpen=true`, `HistoryDepth=5`. Const `HibpHttpClient`. |
| `AuthSessionOptions` | `MindAttic:Auth:Session` | `AbsoluteTimeout=8h`, `IdleTimeout=30m`, `RevalidationInterval=1m`. |
| `MindAtticAuthOptions` | (host code) | `AppName="App"`, `ConfigureAdditionalPolicies`, `ConfigureDataProtection`, `DevKeyRingPath`, `IsProduction`. |

## 3. Secrets — `MindAttic.Authentication.Secrets`

```csharp
public interface IAuthSecrets {
    string  GetRequired(string name);       // throws if blank — fail-closed
    string? GetOptional(string name);
    byte[]  GetRequiredBytes(string name);  // base64-decoded
}
public sealed class ConfigAuthSecrets : IAuthSecrets {  // reads MindAttic:Vault:Security:<name>, caches
    public const string SectionPath = "MindAttic:Vault:Security";
}
```
Required secrets: `pepper.v1` (≥32 random bytes, base64), `bootstrap-token` (≥12 chars). Reserved:
`dp-kek`, `reset-token-key`, `captcha-secret`.

## 4. Crypto — `MindAttic.Authentication.Crypto`

```csharp
public readonly record struct PasswordHash(string Phc, string PepperKeyId);
public readonly record struct PasswordVerifyResult(bool Succeeded, bool NeedsRehash);

public interface IPasswordHasher {
    PasswordHash Hash(string password);
    PasswordVerifyResult Verify(string password, string storedHash, string? pepperKeyId, string? legacyScheme);
    void VerifyDecoy(string password);      // uniform-cost no-op for absent users
}
public sealed class Argon2idPasswordHasher : IPasswordHasher, IDisposable { }

public readonly record struct PhcArgon2(int Version, int MemoryKiB, int Iterations, int Parallelism, byte[] Salt, byte[] Hash) {
    public string Encode();
    public static bool TryParse(string? s, out PhcArgon2 result);
}
```
PHC format: `$argon2id$v=19$m=65536,t=3,p=4$<b64salt>$<b64hash>`. `legacyScheme`: `"bcrypt"` | `"sha256"` | `null`.

## 5. Entities — `MindAttic.Authentication.Entities`

`AuthUser`, `AuthUserMfa`, `AuthRecoveryCode`, `AuthSession`, `AuthLoginThrottle`, `AuthAuditLog`,
`AuthPasswordHistory`, `AuthPasswordResetToken` (full column lists in [`SECURITY_SPEC.md`](SECURITY_SPEC.md)
§"EF Schema"). Enums:

```csharp
public enum ThrottleScope : byte { Account = 0, Ip = 1 }
public enum AuthEventType : byte { Login, Register, PasswordReset, MfaChallenge, ChangePassword,
                                   MfaEnroll, RecoveryUsed, RecoveryRegen, MfaDisabled, MfaOperatorReset,
                                   HibpOnlineSkipped, Logout }
public enum AuthOutcome   : byte { Success, Failure, Throttled, StepUpRequired }
public enum AuthReasonCode: byte { Ok, UnknownUser, BadPassword, Locked, Unverified,
                                   MfaRequired, MfaBad, Disabled, TokenInvalid, PolicyRejected }   // server-only
```

## 6. Data — `MindAttic.Authentication.Data`

```csharp
public interface IAuthDataContext {                 // the app's DbContext implements this
    DbSet<AuthUser> AuthUsers { get; }
    DbSet<AuthUserMfa> AuthUserMfa { get; }
    DbSet<AuthRecoveryCode> AuthRecoveryCodes { get; }
    DbSet<AuthSession> AuthSessions { get; }
    DbSet<AuthLoginThrottle> AuthLoginThrottles { get; }
    DbSet<AuthAuditLog> AuthAuditLog { get; }
    DbSet<AuthPasswordHistory> AuthPasswordHistory { get; }
    DbSet<AuthPasswordResetToken> AuthPasswordResetTokens { get; }
    Task<int> SaveChangesAsync(CancellationToken ct = default);
}
public static class AuthModel {
    public const string DefaultSchema = "auth";
    public const string ModelFingerprint = "auth-v1";
    public static ModelBuilder ApplyMindAtticAuthConfiguration(this ModelBuilder b, string schema = DefaultSchema);
}
```

## 7. Services — `MindAttic.Authentication.Services`

```csharp
public enum LoginStatus { Success, MfaRequired, Failed }
public sealed record LoginResult(LoginStatus Status, Guid? UserId = null, IReadOnlyList<Claim>? Claims = null);
public interface IAuthenticationService {
    Task<LoginResult> LoginAsync(string userName, string password, string sourceIp, string userAgent, CancellationToken ct = default);
    Task<LoginResult> ConfirmMfaAsync(Guid userId, string code, bool isRecoveryCode, string sourceIp, string userAgent, CancellationToken ct = default);
}

public readonly record struct ThrottleDecision(bool Allowed, TimeSpan RetryAfter);
public interface IAccountLockoutService {
    Task<ThrottleDecision> CheckAsync(ThrottleScope scope, string rawKey, CancellationToken ct = default);
    Task RecordFailureAsync(ThrottleScope scope, string rawKey, CancellationToken ct = default);
    Task ResetAsync(ThrottleScope scope, string rawKey, CancellationToken ct = default);
}
public sealed class AccountLockoutService { public static TimeSpan BackoffFor(int consecutiveFailures); }

public sealed record AuthAuditEntry(AuthEventType EventType, AuthOutcome Outcome, AuthReasonCode Reason, Guid? UserId=null,
    string? UserNameAttempted=null, string? AccountKeyRaw=null, string? SourceIpRaw=null, string? UserAgent=null, bool CaptchaPresented=false);
public interface IAuthAuditWriter { Task WriteAsync(AuthAuditEntry entry, CancellationToken ct = default); }

public readonly record struct PasswordPolicyResult(bool Ok, string? Reason);
public interface IPasswordPolicy { Task<PasswordPolicyResult> ValidateAsync(string password, Guid? userId = null, CancellationToken ct = default); }

public interface ITotpService {
    byte[] GenerateSecret(); string ToBase32(byte[] secret);
    string BuildOtpAuthUri(byte[] secret, string accountName);
    long? Validate(byte[] secret, string code, long lastStepUsed);
    IReadOnlyList<string> GenerateRecoveryCodes();
}

public interface IUserStore {
    Task<AuthUser?> FindByUserNameAsync(string userName, CancellationToken ct = default);
    Task<AuthUser?> FindByIdAsync(Guid id, CancellationToken ct = default);
    Task<AuthUserMfa?> FindMfaAsync(Guid userId, CancellationToken ct = default);
    Task<bool> AnyUsersAsync(CancellationToken ct = default);
    Task SaveChangesAsync(CancellationToken ct = default);
    void ApplyRehash(AuthUser user, string phc, string pepperKeyId);
    void RecordLogin(AuthUser user, DateTime utcNow);
    static string Normalize(string userName);   // NFKC + trim + upper
}

public readonly record struct EnrollmentBeginResult(string SecretBase32, string OtpAuthUri);
public readonly record struct EnrollmentConfirmResult(bool Ok, IReadOnlyList<string>? RecoveryCodes, string? Error);
public interface IMfaEnrollmentService {
    Task<EnrollmentBeginResult> BeginAsync(Guid userId, CancellationToken ct = default);
    Task<EnrollmentConfirmResult> ConfirmAsync(Guid userId, string code, string currentPassword, CancellationToken ct = default);
}

public readonly record struct PasswordChangeResult(bool Ok, string? Error);
public interface IPasswordChangeService { Task<PasswordChangeResult> ChangeAsync(Guid userId, string currentPassword, string newPassword, CancellationToken ct = default); }

public sealed class AuthBootstrapper { Task SeedAdminAsync(string adminUserName = "admin", CancellationToken ct = default); }
```

## 8. Web wiring — `MindAttic.Authentication.Web`

```csharp
public static IServiceCollection AddMindAtticAuthentication<TContext>(
    this IServiceCollection services, IConfiguration config, Action<MindAtticAuthOptions> configure)
    where TContext : DbContext, IAuthDataContext;

public static IApplicationBuilder UseMindAtticAuthentication(this IApplicationBuilder app);  // authn→authz→scoped CSP
public static IEndpointRouteBuilder MapMindAtticAuthEndpoints(this IEndpointRouteBuilder endpoints);
//   POST /_ma-auth/login · /mfa-challenge · /logout · /change-password (RequireAuthorization)

public sealed class MaRevalidatingAuthenticationStateProvider : RevalidatingServerAuthenticationStateProvider;
public static class MindAtticAuthAppExtensions { public const string CspNonceItem = "ma-csp-nonce"; }
```

## 9. Components — `MindAttic.Authentication.Components`

| Component | Render | Parameters | Posts to |
|---|---|---|---|
| `MaLogin` | static SSR form | `ReturnUrl`, `Error` | `/_ma-auth/login` |
| `MaMfaChallenge` | static SSR form | `ReturnUrl`, `Error` | `/_ma-auth/mfa-challenge` |
| `MaChangePassword` | static SSR form | `Error` | `/_ma-auth/change-password` |
| `MaLogout` | static SSR form | `Text` | `/_ma-auth/logout` |
| `MaMfaSetup` | **interactive** | — (reads auth state) | calls `IMfaEnrollmentService` directly; shows recovery codes once |

CSS hooks: `.ma-auth`, `.ma-auth-field`, `.ma-auth-error`, `.ma-auth-submit`, `.ma-recovery-codes`, etc.
No component ever calls `SignInAsync`.

## 10. Internal helpers (public but not part of the stable contract)

`Internal.AuthKeys` (key canonicalization/hashing), `Internal.UrlSafety` (`IsLocalUrl`), `Internal.TimingFloor`.
Treat as implementation detail; not covered by the major-version stability promise.
