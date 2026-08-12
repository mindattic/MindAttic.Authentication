namespace MindAttic.Authentication.Options;

/// <summary>TOTP + recovery-code settings (RFC 6238 pinned values).</summary>
public sealed class MfaOptions
{
    /// <summary>Issuer shown in the authenticator app (otpauth label).</summary>
    public string Issuer { get; set; } = "MindAttic";
    public int Digits { get; set; } = 6;
    public int PeriodSeconds { get; set; } = 30;
    /// <summary>Allowed step drift on each side (±1 ⇒ 90s acceptance window).</summary>
    public int WindowSteps { get; set; } = 1;
    public int SecretBytes { get; set; } = 20;        // 160-bit
    public int RecoveryCodeCount { get; set; } = 10;
    public int RecoveryCodeBytes { get; set; } = 10;  // ~80 bits before formatting (>50-bit floor)
    public int PendingEnrollmentMinutes { get; set; } = 10;
    /// <summary>If true, accounts in the Admin role must enroll MFA before reaching admin surfaces.</summary>
    public bool RequireForAdmin { get; set; } = true;
}
