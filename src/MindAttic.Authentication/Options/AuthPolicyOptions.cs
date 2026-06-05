namespace MindAttic.Authentication.Options;

/// <summary>NIST 800-63B-aligned password policy + breached-password (HIBP) settings.</summary>
public sealed class AuthPolicyOptions
{
    public int MinLength { get; set; } = 12;
    public int MaxLength { get; set; } = 128;

    /// <summary>Check candidates against Have I Been Pwned (k-anonymity range API).</summary>
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
