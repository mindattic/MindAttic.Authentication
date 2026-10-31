using MindAttic.Vault.Settings.Manifest;

namespace MindAttic.Authentication.Options;

/// <summary>NIST 800-63B-aligned password policy + breached-password (HIBP) settings.</summary>
public sealed class AuthPolicyOptions
{
    [Setting("Minimum password length", Help = "NIST 800-63B floor is 8; MindAttic uses 12.")]
    public int MinLength { get; set; } = 12;
    public int MaxLength { get; set; } = 128;

    /// <summary>Check candidates against Have I Been Pwned (k-anonymity range API).</summary>
    [Setting("Check breached passwords", Help = "Reject passwords found in Have I Been Pwned (k-anonymity range lookup).")]
    public bool CheckHibp { get; set; } = true;
    public string HibpRangeBaseUrl { get; set; } = "https://api.pwnedpasswords.com/range/";
    public int HibpTimeoutMs { get; set; } = 2000;
    /// <summary>FAIL-OPEN: on HIBP error/timeout, allow (after the offline check) and audit the skip.</summary>
    public bool HibpFailOpen { get; set; } = true;

    /// <summary>Reject reuse of the current + last N passwords.</summary>
    public int HistoryDepth { get; set; } = 5;

    /// <summary>Named HttpClient used for HIBP.</summary>
    public const string HibpHttpClient = "MindAttic.Auth.Hibp";
}
