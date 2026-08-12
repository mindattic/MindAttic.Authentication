using Microsoft.Extensions.Configuration;
using MindAttic.Authentication.Secrets;

namespace MindAttic.Authentication.Tests.Secrets;

/// <summary>
/// The fail-CLOSED secrets wrapper is the linchpin against MindAttic.Vault's "return null on any error"
/// behavior (red-team mustFix). A missing/blank required secret must THROW, never coerce to empty — a null
/// pepper that silently became "" would catastrophically weaken every hash.
/// </summary>
[TestFixture]
public sealed class ConfigAuthSecretsTests
{
    private static ConfigAuthSecrets New(params (string key, string? value)[] entries)
    {
        var dict = entries.ToDictionary(
            e => $"{ConfigAuthSecrets.SectionPath}:{e.key}", e => e.value);
        var config = new ConfigurationBuilder().AddInMemoryCollection(dict!).Build();
        return new ConfigAuthSecrets(config);
    }

    [Test]
    public void GetRequired_Present_ReturnsValue() =>
        Assert.That(New(("pepper.v1", "c2VjcmV0")).GetRequired("pepper.v1"), Is.EqualTo("c2VjcmV0"));

    [Test]
    public void GetRequired_Missing_Throws() =>
        Assert.That(() => New().GetRequired("pepper.v1"), Throws.InvalidOperationException);

    [TestCase("")]
    [TestCase("   ")]
    public void GetRequired_Blank_Throws_NeverCoercesToEmpty(string blank) =>
        Assert.That(() => New(("pepper.v1", blank)).GetRequired("pepper.v1"), Throws.InvalidOperationException);

    [Test]
    public void GetOptional_Missing_ReturnsNull() =>
        Assert.That(New().GetOptional("captcha-secret"), Is.Null);

    [Test]
    public void GetOptional_Present_ReturnsValue() =>
        Assert.That(New(("captcha-secret", "abc")).GetOptional("captcha-secret"), Is.EqualTo("abc"));

    [Test]
    public void GetRequiredBytes_ValidBase64_DecodesToBytes()
    {
        var b64 = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 });
        Assert.That(New(("reset-token-key", b64)).GetRequiredBytes("reset-token-key"),
            Is.EqualTo(new byte[] { 1, 2, 3, 4 }));
    }

    [Test]
    public void GetRequiredBytes_InvalidBase64_Throws() =>
        Assert.That(() => New(("pepper.v1", "!!!not-base64!!!")).GetRequiredBytes("pepper.v1"),
            Throws.InvalidOperationException);

    [Test]
    public void GetRequiredBytes_Missing_Throws() =>
        Assert.That(() => New().GetRequiredBytes("pepper.v1"), Throws.InvalidOperationException);

    [Test]
    public void Resolution_IsRepeatable_AfterCaching()
    {
        var secrets = New(("pepper.v1", "c2VjcmV0"));
        Assert.That(secrets.GetOptional("pepper.v1"), Is.EqualTo("c2VjcmV0"));
        Assert.That(secrets.GetRequired("pepper.v1"), Is.EqualTo("c2VjcmV0"), "cached read stays consistent");
    }
}
