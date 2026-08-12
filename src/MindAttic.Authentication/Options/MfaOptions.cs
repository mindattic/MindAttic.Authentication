namespace MindAttic.Authentication.Options;

/// <summary>
/// App-level MFA enrollment policy. The TOTP crypto parameters themselves (issuer, digits, period, window,
/// secret/recovery-code sizes) live in <see cref="MindAttic.Cryptography.Totp.TotpOptions"/> now — both bind
/// from the same "MindAttic:Auth:Mfa" config section, since <c>IOptions</c> binding ignores keys a type
/// doesn't declare.
/// </summary>
public sealed class MfaOptions
{
    public int PendingEnrollmentMinutes { get; set; } = 10;
    /// <summary>If true, accounts in the Admin role must enroll MFA before reaching admin surfaces.</summary>
    public bool RequireForAdmin { get; set; } = true;
}
