using Microsoft.Extensions.Configuration;
using MindAttic.Authentication.Options;
using MindAttic.Vault.Settings.Manifest;
using NUnit.Framework;

namespace MindAttic.Authentication.Tests;

[SettingsApp("AuthHost", "Auth host")]
public sealed class AuthHostSettings
{
    public MindAtticAuthSettings Auth { get; set; } = new();
}

/// <summary>LAMP (M.AUTH-T23): auth options embedded in a host's Vault settings, bound from its section.</summary>
public class LampAuthSettingsTests
{
    [Test]
    public void EmbeddedInAHost_TheManifestShowsEveryOptionUnderTheHostsAuthSection()
    {
        var m = SettingsManifestBuilder.Build<AuthHostSettings>();
        var names = m.AllFields().Select(f => f.Name).ToList();
        Assert.That(names, Does.Contain("MindAttic:Settings:AuthHost:auth:mfa:requireForAdmin"));
        Assert.That(names, Does.Contain("MindAttic:Settings:AuthHost:auth:reset:publicBaseUrl"));
        Assert.That(names, Does.Contain("MindAttic:Settings:AuthHost:auth:crypto:memoryKiB"));
        Assert.That(m.Find("MindAttic:Settings:AuthHost:auth:mfa:requireForAdmin")!.Help, Does.Contain("enroll"));
        Assert.That(m.Find("MindAttic:Settings:AuthHost:auth:reset:publicBaseUrl")!.Kind, Is.EqualTo(SettingKind.Url));
        Assert.That(m.Find("MindAttic:Settings:AuthHost:auth:session:idleTimeout")!.Kind, Is.EqualTo(SettingKind.TimeSpan));
    }

    [Test]
    public void FromConfiguration_ReadsTheLegacySectionHostsUseToday()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["MindAttic:Auth:Mfa:RequireForAdmin"] = "false",
            ["MindAttic:Auth:Reset:PublicBaseUrl"] = "https://localhost:7200",
        }).Build();
        var s = MindAtticAuthSettings.FromConfiguration(config);
        Assert.That(s.Mfa.RequireForAdmin, Is.False);
        Assert.That(s.Reset.PublicBaseUrl, Is.EqualTo("https://localhost:7200"));
        Assert.That(s.Policy.MinLength, Is.EqualTo(12), "unset options keep their defaults");
    }

    [Test]
    public void FromConfiguration_ReadsAHostsVaultSectionWithCamelCaseNames()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["MindAttic:Settings:Tutor:auth:mfa:requireForAdmin"] = "false",
            ["MindAttic:Settings:Tutor:auth:session:idleTimeout"] = "00:45:00",
        }).Build();
        var s = MindAtticAuthSettings.FromConfiguration(config, "MindAttic:Settings:Tutor:auth");
        Assert.That(s.Mfa.RequireForAdmin, Is.False);
        Assert.That(s.Session.IdleTimeout, Is.EqualTo(TimeSpan.FromMinutes(45)));
    }

    [Test]
    public void SettingsSection_DefaultsToTheLegacySectionSoUnmigratedHostsAreUnchanged() =>
        Assert.That(new Web.MindAtticAuthOptions().SettingsSection, Is.EqualTo("MindAttic:Auth"));
}
