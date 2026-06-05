namespace MindAttic.Authentication.Options;

/// <summary>Session lifetime + cookie posture.</summary>
public sealed class AuthSessionOptions
{
    public TimeSpan AbsoluteTimeout { get; set; } = TimeSpan.FromHours(8);
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromMinutes(30);
    /// <summary>Stamp + circuit revalidation cadence (revoked-admin window upper bound).</summary>
    public TimeSpan RevalidationInterval { get; set; } = TimeSpan.FromMinutes(1);
}
