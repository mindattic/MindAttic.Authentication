using MindAttic.Vault.Settings.Manifest;

namespace MindAttic.Authentication.Options;

/// <summary>Session lifetime + cookie posture.</summary>
public sealed class AuthSessionOptions
{
    [Setting("Session lifetime", Help = "Sign-in expires after this long regardless of activity (hh:mm:ss).")]
    public TimeSpan AbsoluteTimeout { get; set; } = TimeSpan.FromHours(8);
    [Setting("Idle timeout", Help = "Sign-in expires after this long without activity (hh:mm:ss).")]
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromMinutes(30);
    /// <summary>Stamp + circuit revalidation cadence (revoked-admin window upper bound).</summary>
    public TimeSpan RevalidationInterval { get; set; } = TimeSpan.FromMinutes(1);
}
