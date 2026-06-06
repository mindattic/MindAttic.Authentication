using System.Security.Cryptography;
using MindAttic.Authentication.Crypto;

namespace MindAttic.Authentication.Tests.Crypto;

/// <summary>
/// The PHC codec is the on-disk format for every password. It must round-trip losslessly, reject anything
/// malformed (so a corrupt/forged column can't be coerced into a "valid" weak hash), and never throw.
/// </summary>
[TestFixture]
public sealed class PhcArgon2Tests
{
    private static PhcArgon2 Sample(int m = 65536, int t = 3, int p = 4)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = RandomNumberGenerator.GetBytes(32);
        return new PhcArgon2(PhcArgon2.ArgonVersion, m, t, p, salt, hash);
    }

    [Test]
    public void Encode_ProducesCanonicalArgon2idString()
    {
        var phc = Sample().Encode();
        Assert.That(phc, Does.StartWith("$argon2id$v=19$m=65536,t=3,p=4$"));
        Assert.That(phc.Split('$'), Has.Length.EqualTo(6));
    }

    [Test]
    public void Encode_StripsBase64Padding()
    {
        var phc = Sample().Encode();
        // The salt/hash segments must carry no '=' padding (PHC spec).
        var segments = phc.Split('$');
        Assert.That(segments[4], Does.Not.Contain("="));
        Assert.That(segments[5], Does.Not.Contain("="));
    }

    [Test]
    public void RoundTrip_PreservesAllFields()
    {
        var original = Sample(19456, 2, 1);
        Assert.That(PhcArgon2.TryParse(original.Encode(), out var parsed), Is.True);
        Assert.That(parsed.Version, Is.EqualTo(original.Version));
        Assert.That(parsed.MemoryKiB, Is.EqualTo(original.MemoryKiB));
        Assert.That(parsed.Iterations, Is.EqualTo(original.Iterations));
        Assert.That(parsed.Parallelism, Is.EqualTo(original.Parallelism));
        Assert.That(parsed.Salt, Is.EqualTo(original.Salt));
        Assert.That(parsed.Hash, Is.EqualTo(original.Hash));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("not-a-phc")]
    [TestCase("$argon2id$v=19$m=65536,t=3,p=4$onlyfivesegments")]          // too few segments
    [TestCase("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA$extra")]       // too many segments
    [TestCase("$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA")]              // wrong algorithm (argon2i)
    [TestCase("$bcrypt$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA")]               // wrong algorithm
    [TestCase("Xargon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA")]             // non-empty first segment
    [TestCase("$argon2id$x=19$m=65536,t=3,p=4$c2FsdA$aGFzaA")]            // bad version key
    [TestCase("$argon2id$v=19$m=65536,t=3$c2FsdA$aGFzaA")]                 // missing p param
    [TestCase("$argon2id$v=19$m=AA,t=3,p=4$c2FsdA$aGFzaA")]                // non-numeric memory
    [TestCase("$argon2id$v=19$m=65536,t=3,p=4$!!!!$aGFzaA")]               // invalid base64 salt
    public void TryParse_RejectsMalformedInputWithoutThrowing(string? input)
    {
        bool result = false;
        Assert.DoesNotThrow(() => result = PhcArgon2.TryParse(input, out _));
        Assert.That(result, Is.False, input ?? "<null>");
    }

    [Test]
    public void TryParse_AcceptsKnownGoodLiteral()
    {
        // A real-shaped PHC (16-byte salt, 32-byte hash, base64 no padding).
        var salt = Convert.ToBase64String(new byte[16]).TrimEnd('=');
        var hash = Convert.ToBase64String(new byte[32]).TrimEnd('=');
        var literal = $"$argon2id$v=19$m=19456,t=2,p=1${salt}${hash}";
        Assert.That(PhcArgon2.TryParse(literal, out var phc), Is.True);
        Assert.That(phc.Salt, Has.Length.EqualTo(16));
        Assert.That(phc.Hash, Has.Length.EqualTo(32));
    }
}
