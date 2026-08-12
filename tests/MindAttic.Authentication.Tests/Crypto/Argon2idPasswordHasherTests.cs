using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using MindAttic.Authentication.Crypto;
using MindAttic.Authentication.Options;
using MindAttic.Authentication.Tests.TestSupport;

namespace MindAttic.Authentication.Tests.Crypto;

/// <summary>
/// The Argon2id+pepper hasher is the core of password storage (OWASP PS CS, NIST 800-63B 5.1.1.2). These
/// tests pin: correct verify, salt uniqueness, NFKC equivalence, the DoS length cap, fail-closed pepper
/// resolution, rehash-on-login triggers (params + pepper rotation), transparent legacy bcrypt/SHA-256
/// upgrade, and that a tampered or absent hash never coerces into a success.
/// </summary>
[TestFixture]
public sealed class Argon2idPasswordHasherTests
{
    private const string Password = "correct-horse-battery-staple";

    [Test]
    public void Hash_ThenVerify_Succeeds_AndDoesNotNeedRehashAtCurrentParams()
    {
        using var hasher = Build.Hasher();
        var stored = hasher.Hash(Password);
        var result = hasher.Verify(Password, stored.Phc, stored.PepperKeyId, null);
        Assert.That(result.Succeeded, Is.True);
        Assert.That(result.NeedsRehash, Is.False);
        Assert.That(stored.PepperKeyId, Is.EqualTo("v1"));
        Assert.That(stored.Phc, Does.StartWith("$argon2id$"));
    }

    [Test]
    public void Verify_WrongPassword_Fails()
    {
        using var hasher = Build.Hasher();
        var stored = hasher.Hash(Password);
        Assert.That(hasher.Verify("wrong-password-entirely", stored.Phc, stored.PepperKeyId, null).Succeeded, Is.False);
    }

    [Test]
    public void Hash_UsesRandomSalt_SoSamePasswordHashesDiffer()
    {
        using var hasher = Build.Hasher();
        var first = hasher.Hash(Password).Phc;
        var second = hasher.Hash(Password).Phc;
        Assert.That(second, Is.Not.EqualTo(first), "random per-hash salt must yield distinct PHC strings");
    }

    [Test]
    public void Verify_IsNfkcNormalized_ComposedAndDecomposedMatch()
    {
        using var hasher = Build.Hasher();
        var composed = "café-monkey-99";        // é as the precomposed U+00E9
        var decomposed = "café-monkey-99";     // e + combining acute accent U+0301
        var stored = hasher.Hash(composed);
        Assert.That(hasher.Verify(decomposed, stored.Phc, stored.PepperKeyId, null).Succeeded, Is.True,
            "NFKC-equivalent passwords must verify interchangeably");
    }

    [Test]
    public void Hash_RejectsTooShortAndTooLong()
    {
        using var hasher = Build.Hasher();
        Assert.That(() => hasher.Hash("short"), Throws.ArgumentException);
        Assert.That(() => hasher.Hash(new string('a', 129)), Throws.ArgumentException);
    }

    [Test]
    public void Hash_NullThrowsArgumentNull()
    {
        using var hasher = Build.Hasher();
        Assert.That(() => hasher.Hash(null!), Throws.ArgumentNullException);
    }

    [Test]
    public void Verify_OverlongPassword_FailsWithoutThrowing()
    {
        using var hasher = Build.Hasher();
        var stored = hasher.Hash(Password);
        var overlong = new string('x', 5000);
        Assert.That(hasher.Verify(overlong, stored.Phc, stored.PepperKeyId, null).Succeeded, Is.False);
    }

    [TestCase("")]
    [TestCase(null)]
    public void Verify_EmptyOrNullStoredHash_Fails(string? stored)
    {
        using var hasher = Build.Hasher();
        Assert.That(hasher.Verify(Password, stored!, "v1", null).Succeeded, Is.False);
    }

    [Test]
    public void Verify_TamperedHash_Fails()
    {
        using var hasher = Build.Hasher();
        var stored = hasher.Hash(Password);
        // Flip the last character of the hash segment.
        var tampered = stored.Phc[..^1] + (stored.Phc[^1] == 'A' ? 'B' : 'A');
        Assert.That(hasher.Verify(Password, tampered, stored.PepperKeyId, null).Succeeded, Is.False);
    }

    [Test]
    public void Verify_FailsClosed_WhenRowPepperIsMissing()
    {
        var secrets = new FakeAuthSecrets();
        using var hasher = Build.Hasher(Build.FastCrypto("v1"), secrets);
        var stored = hasher.Hash(Password);
        secrets.MarkMissing("pepper.v9");
        // A row claiming an unresolvable pepper id must fail — never coerce to a match.
        Assert.That(hasher.Verify(Password, stored.Phc, "v9", null).Succeeded, Is.False);
    }

    [Test]
    public void Verify_DifferentPepper_DoesNotMatch_DomainSeparation()
    {
        using var hasher = Build.Hasher();
        var stored = hasher.Hash(Password);
        // Same stored hash, but verified as if peppered with a DIFFERENT key id ⇒ different pre-hash ⇒ no match.
        Assert.That(hasher.Verify(Password, stored.Phc, "v2", null).Succeeded, Is.False);
    }

    [Test]
    public void Verify_NeedsRehash_WhenPepperKeyIdIsStale()
    {
        var secrets = new FakeAuthSecrets();
        using var hasherV1 = Build.Hasher(Build.FastCrypto("v1"), secrets);
        using var hasherV2 = Build.Hasher(Build.FastCrypto("v2"), secrets);
        var stored = hasherV1.Hash(Password);               // peppered with v1
        var result = hasherV2.Verify(Password, stored.Phc, "v1", null); // current pepper is now v2
        Assert.That(result.Succeeded, Is.True, "old-pepper rows must still verify during rotation");
        Assert.That(result.NeedsRehash, Is.True, "stale pepper id must trigger rehash-on-login");
    }

    [Test]
    public void Verify_NeedsRehash_WhenStoredParamsAreWeakerThanCurrent()
    {
        var secrets = new FakeAuthSecrets();
        var weak = Build.FastCrypto("v1");                  // m=19456 (floor)
        var strong = Build.FastCrypto("v1");
        strong.MemoryKiB = 20000;                            // current floor is now higher than the stored hash
        using var weakHasher = Build.Hasher(weak, secrets);
        using var strongHasher = Build.Hasher(strong, secrets);
        var stored = weakHasher.Hash(Password);
        var result = strongHasher.Verify(Password, stored.Phc, "v1", null);
        Assert.That(result.Succeeded, Is.True);
        Assert.That(result.NeedsRehash, Is.True, "weaker-than-current params must trigger rehash");
    }

    [Test]
    public void Verify_LegacyBcrypt_UpgradesOnSuccess()
    {
        using var hasher = Build.Hasher();
        var bcryptHash = BCrypt.Net.BCrypt.HashPassword(Password);
        var ok = hasher.Verify(Password, bcryptHash, null, "bcrypt");
        Assert.That(ok.Succeeded, Is.True);
        Assert.That(ok.NeedsRehash, Is.True, "legacy hashes must be flagged for upgrade");
        Assert.That(hasher.Verify("nope-nope-nope", bcryptHash, null, "bcrypt").Succeeded, Is.False);
    }

    [Test]
    public void Verify_LegacyBcrypt_DetectedByPrefixEvenWithoutSchemeTag()
    {
        using var hasher = Build.Hasher();
        var bcryptHash = BCrypt.Net.BCrypt.HashPassword(Password); // starts with $2a/$2b
        Assert.That(hasher.Verify(Password, bcryptHash, null, null).Succeeded, Is.True);
    }

    [Test]
    public void Verify_LegacySha256_UpgradesOnSuccess()
    {
        using var hasher = Build.Hasher();
        var sha = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(Password)));
        var ok = hasher.Verify(Password, sha, null, "sha256");
        Assert.That(ok.Succeeded, Is.True);
        Assert.That(ok.NeedsRehash, Is.True);
        Assert.That(hasher.Verify("different-pw-here", sha, null, "sha256").Succeeded, Is.False);
    }

    [Test]
    public void VerifyDecoy_DoesNotThrow_ForAbsentUserPath()
    {
        using var hasher = Build.Hasher();
        Assert.DoesNotThrow(() => hasher.VerifyDecoy("anything-at-all-here"));
        Assert.DoesNotThrow(() => hasher.VerifyDecoy(""));
    }

    [Test]
    public void Construction_FailsFast_WhenCurrentPepperMissing()
    {
        var secrets = new FakeAuthSecrets().MarkMissing("pepper.v1");
        Assert.That(() => new Argon2idPasswordHasher(secrets, Microsoft.Extensions.Options.Options.Create(Build.FastCrypto("v1"))),
            Throws.InvalidOperationException, "a missing current pepper must abort startup (fail-closed)");
    }
}
