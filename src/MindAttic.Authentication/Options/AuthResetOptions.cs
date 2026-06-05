namespace MindAttic.Authentication.Options;

/// <summary>Password-reset settings.</summary>
public sealed class AuthResetOptions
{
    /// <summary>Absolute base URL for reset links (e.g. https://ideas.mindattic.com). NEVER derived from Request.Host.</summary>
    public string PublicBaseUrl { get; set; } = "";
    /// <summary>Relative path the reset link points at (token appended as ?token=...).</summary>
    public string ResetPath { get; set; } = "/account/reset";
    public int TokenTtlMinutes { get; set; } = 15;
    /// <summary>Cap reset emails per account per hour (anti-spam / enumeration amplification).</summary>
    public int MaxEmailsPerHour { get; set; } = 3;
}
