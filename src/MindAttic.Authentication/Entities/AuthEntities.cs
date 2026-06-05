namespace MindAttic.Authentication.Entities;

// ============================================================================================
//  Canonical identity schema OWNED by MindAttic.Authentication. All tables live in the `auth`
//  schema and have NO foreign keys into app tables. Each consuming app applies the configuration
//  in its own DbContext.OnModelCreating and runs its own EF migration.
// ============================================================================================

public enum ThrottleScope : byte { Account = 0, Ip = 1 }

public enum AuthEventType : byte
{
    Login = 0, Register = 1, PasswordReset = 2, MfaChallenge = 3, ChangePassword = 4,
    MfaEnroll = 5, RecoveryUsed = 6, RecoveryRegen = 7, MfaDisabled = 8,
    MfaOperatorReset = 9, HibpOnlineSkipped = 10, Logout = 11,
}

public enum AuthOutcome : byte { Success = 0, Failure = 1, Throttled = 2, StepUpRequired = 3 }

/// <summary>Server-only failure reason — NEVER surfaced to the client (enumeration safety).</summary>
public enum AuthReasonCode : byte
{
    Ok = 0, UnknownUser = 1, BadPassword = 2, Locked = 3, Unverified = 4,
    MfaRequired = 5, MfaBad = 6, Disabled = 7, TokenInvalid = 8, PolicyRejected = 9,
}

/// <summary>An account. PasswordHash is a self-describing PHC string (or a tagged legacy hash).</summary>
public sealed class AuthUser
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string UserName { get; set; } = "";
    public string NormalizedUserName { get; set; } = "";
    public string? Email { get; set; }
    public string? NormalizedEmail { get; set; }
    public bool EmailVerified { get; set; }

    public string PasswordHash { get; set; } = "";
    public string? PasswordPepperKeyId { get; set; }   // e.g. "v1"; null for pre-pepper legacy rows
    public string? LegacyHashScheme { get; set; }      // "bcrypt" | "sha256" until first rehash-on-login
    public DateTime PasswordUpdatedUtc { get; set; }

    public string SecurityStamp { get; set; } = Guid.NewGuid().ToString("N");
    public string Role { get; set; } = "";

    public bool MfaEnabled { get; set; }
    public bool MustChangePassword { get; set; }
    public bool MustEnrollMfa { get; set; }
    public bool IsActive { get; set; } = true;

    public DateTime? LastLoginUtc { get; set; }
    public DateTime CreatedUtc { get; set; }
    public byte[]? RowVersion { get; set; }
}

/// <summary>TOTP state, 1:1 with <see cref="AuthUser"/>. Secrets are Data-Protection encrypted at rest.</summary>
public sealed class AuthUserMfa
{
    public Guid UserId { get; set; }
    public bool Enabled { get; set; }
    public byte[]? SecretEncrypted { get; set; }
    public byte[]? PendingSecretEncrypted { get; set; }
    public DateTime? PendingExpiresUtc { get; set; }
    public long LastTotpStepUsed { get; set; }         // replay guard (consumed Unix TOTP step)
    public DateTime? ActivatedUtc { get; set; }
    public byte[]? RowVersion { get; set; }
}

/// <summary>Single-use recovery code; stored only as an Argon2id+pepper hash.</summary>
public sealed class AuthRecoveryCode
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public string CodeHash { get; set; } = "";
    public string? CodePepperKeyId { get; set; }
    public Guid BatchId { get; set; }
    public DateTime? UsedUtc { get; set; }
    public DateTime CreatedUtc { get; set; }
}

/// <summary>An active session (the <c>sid</c> claim). Enables per-session revoke + global logout.</summary>
public sealed class AuthSession
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid AuthUserId { get; set; }
    public DateTime CreatedUtc { get; set; }
    public DateTime LastSeenUtc { get; set; }
    public DateTime AbsoluteExpiryUtc { get; set; }
    public string IpHash { get; set; } = "";   // SHA-256 of canonical IP, never raw
    public string UserAgent { get; set; } = "";
    public DateTime? RevokedUtc { get; set; }
    public string? RevokedReason { get; set; }
}

/// <summary>Persistent brute-force backoff, per-account AND per-IP. Replaces all in-memory lockout.</summary>
public sealed class AuthLoginThrottle
{
    public long Id { get; set; }
    public ThrottleScope Scope { get; set; }
    public byte[] KeyHash { get; set; } = [];     // SHA-256 of normalized key (email or IP /64)
    public int ConsecutiveFailures { get; set; }
    public DateTime FirstFailureUtc { get; set; }
    public DateTime LastFailureUtc { get; set; }
    public DateTime? NextAttemptAllowedUtc { get; set; }
    public byte[]? RowVersion { get; set; }
}

/// <summary>Every auth attempt (success + failure). Reason codes are server-only.</summary>
public sealed class AuthAuditLog
{
    public long Id { get; set; }
    public DateTime TimestampUtc { get; set; }
    public Guid? UserId { get; set; }
    public string? UserNameAttempted { get; set; }
    public AuthEventType EventType { get; set; }
    public AuthOutcome Outcome { get; set; }
    public AuthReasonCode ReasonCode { get; set; }
    public byte[]? AccountKeyHash { get; set; }
    public string SourceIp { get; set; } = "";
    public string UserAgent { get; set; } = "";
    public bool CaptchaPresented { get; set; }
}

/// <summary>Password reuse prevention (keep newest N per user).</summary>
public sealed class AuthPasswordHistory
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public string PasswordHash { get; set; } = "";
    public string? PepperKeyId { get; set; }
    public DateTime CreatedUtc { get; set; }
}

/// <summary>A password-reset token, stored only as an HMAC-SHA256 hash (keyed by a Vault secret).</summary>
public sealed class AuthPasswordResetToken
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public string TokenHash { get; set; } = "";   // HMAC-SHA256 hex; never plaintext
    public DateTime CreatedUtc { get; set; }
    public DateTime ExpiresUtc { get; set; }
    public DateTime? ConsumedUtc { get; set; }     // single-use
    public string RequestIp { get; set; } = "";
    public string RequestUserAgent { get; set; } = "";
}
