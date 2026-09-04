using Microsoft.Extensions.Configuration;
using MindAttic.Authentication.Secrets;
using NUnit.Framework;

namespace MindAttic.Authentication.Tests.Secrets;

/// <summary>
/// Azure App Service on Linux rewrites application-setting names when it injects them as environment
/// variables — dots become underscores and hyphens are dropped. These fixtures reproduce the exact
/// spellings observed on a real Linux App Service worker, where every one of the four Security
/// secrets arrived under a name the library did not recognise and auth fail-closed on secrets the
/// operator had provisioned correctly.
/// </summary>
[TestFixture]
public class ConfigAuthSecretsLinuxNamingTests
{
    private static ConfigAuthSecrets Secrets(params (string Key, string Value)[] entries)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(entries.Select(e =>
                new KeyValuePair<string, string?>($"{ConfigAuthSecrets.SectionPath}:{e.Key}", e.Value)))
            .Build();
        return new ConfigAuthSecrets(config);
    }

    /// <summary>The four names exactly as they appeared inside the Linux container.</summary>
    [TestCase("pepper.v1", "pepper_v1")]
    [TestCase("bootstrap-token", "bootstraptoken")]
    [TestCase("reset-token-key", "resettokenkey")]
    [TestCase("dp-kek", "dpkek")]
    public void MangledLinuxName_StillResolves(string requested, string asDeployed)
    {
        var secrets = Secrets((asDeployed, "s3cret"));

        Assert.That(secrets.GetOptional(requested), Is.EqualTo("s3cret"));
        Assert.That(secrets.GetRequired(requested), Is.EqualTo("s3cret"));
    }

    [Test]
    public void ExactNameStillWins_AndCostsNoScan()
    {
        var secrets = Secrets(("pepper.v1", "exact"), ("pepper_v1", "mangled"));

        Assert.That(secrets.GetRequired("pepper.v1"), Is.EqualTo("exact"));
    }

    [Test]
    public void WindowsStyleNames_AreUnaffected()
    {
        var secrets = Secrets(("pepper.v1", "p"), ("bootstrap-token", "b"));

        Assert.Multiple(() =>
        {
            Assert.That(secrets.GetRequired("pepper.v1"), Is.EqualTo("p"));
            Assert.That(secrets.GetRequired("bootstrap-token"), Is.EqualTo("b"));
        });
    }

    [Test]
    public void GetRequiredBytes_WorksThroughTheRelaxedMatch()
    {
        var expected = new byte[] { 1, 2, 3, 4, 5 };
        var secrets = Secrets(("pepper_v1", Convert.ToBase64String(expected)));

        Assert.That(secrets.GetRequiredBytes("pepper.v1"), Is.EqualTo(expected));
    }

    [Test]
    public void StillMissing_FailsClosedWithTheOriginalName()
    {
        var secrets = Secrets(("something-else", "x"));

        var ex = Assert.Throws<InvalidOperationException>(() => secrets.GetRequired("pepper.v1"));

        Assert.That(ex!.Message, Does.Contain("pepper.v1"));
        Assert.That(secrets.GetOptional("pepper.v1"), Is.Null);
    }

    [Test]
    public void BlankValueDoesNotSatisfyTheRelaxedMatch()
    {
        var secrets = Secrets(("pepper_v1", "   "));

        Assert.That(secrets.GetOptional("pepper.v1"), Is.Null);
        Assert.Throws<InvalidOperationException>(() => secrets.GetRequired("pepper.v1"));
    }

    [Test]
    public void TwoKeysDifferingOnlyByPunctuation_RefuseToGuess()
    {
        var secrets = Secrets(("pepper.v1", "one"), ("pepper-v1", "two"));

        // The exact spelling is present, so it wins outright and no ambiguity arises.
        Assert.That(secrets.GetRequired("pepper.v1"), Is.EqualTo("one"));

        // With only the two ambiguous spellings, guessing would silently pick a pepper -- and the
        // wrong pepper invalidates every stored password hash.
        var ambiguous = Secrets(("pepper_v1", "one"), ("pepper-v1", "two"));
        var ex = Assert.Throws<InvalidOperationException>(() => ambiguous.GetRequired("pepper.v1"));
        Assert.That(ex!.Message, Does.Contain("ambiguous"));
    }

    [Test]
    public void IdenticalValuesUnderTwoSpellings_AreNotAmbiguous()
    {
        var secrets = Secrets(("pepper_v1", "same"), ("pepper-v1", "same"));

        Assert.That(secrets.GetRequired("pepper.v1"), Is.EqualTo("same"));
    }

    [Test]
    public void ResolvedValueIsCached()
    {
        var secrets = Secrets(("pepper_v1", "cached"));

        Assert.That(secrets.GetRequired("pepper.v1"), Is.EqualTo("cached"));
        Assert.That(secrets.GetRequired("pepper.v1"), Is.EqualTo("cached"));
    }
}
