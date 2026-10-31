using Microsoft.Extensions.Configuration;
using MindAttic.Vault.Settings.Manifest;

namespace MindAttic.Authentication.Options;

/// <summary>
/// Every non-secret auth option, as one group a host's MindAttic Vault settings class embeds
/// (<c>public MindAtticAuthSettings Auth { get; set; } = new();</c>) so they are edited on the host's tab in
/// MindAttic.Vault.Desktop. Secrets (pepper, TOTP key) never live here; they stay in <c>IAuthSecrets</c>.
/// </summary>
public sealed class MindAtticAuthSettings
{
    /// <summary>Where hosts configured these before Vault (<c>appsettings.json</c>).</summary>
    public const string LegacySection = "MindAttic:Auth";

    [Setting("Password hashing", Group = "Sign-in security", Order = 1)]
    public AuthCryptoOptions Crypto { get; set; } = new();

    [Setting("Password policy", Group = "Sign-in security", Order = 2)]
    public AuthPolicyOptions Policy { get; set; } = new();

    [Setting("Two-factor (MFA)", Group = "Sign-in security", Order = 3)]
    public MfaOptions Mfa { get; set; } = new();

    [Setting("Sessions", Group = "Sign-in security", Order = 4)]
    public AuthSessionOptions Session { get; set; } = new();

    [Setting("Password reset", Group = "Sign-in security", Order = 5)]
    public AuthResetOptions Reset { get; set; } = new();

    /// <summary>The values a host configured under <paramref name="section"/> (defaults for anything unset).</summary>
    public static MindAtticAuthSettings FromConfiguration(IConfiguration configuration, string section = LegacySection)
    {
        var s = new MindAtticAuthSettings();
        configuration.GetSection($"{section}:Crypto").Bind(s.Crypto);
        configuration.GetSection($"{section}:Policy").Bind(s.Policy);
        configuration.GetSection($"{section}:Mfa").Bind(s.Mfa);
        configuration.GetSection($"{section}:Session").Bind(s.Session);
        configuration.GetSection($"{section}:Reset").Bind(s.Reset);
        return s;
    }
}
