using MindAttic.Authentication.Options;

namespace MindAttic.Authentication.Tests.Options;

/// <summary>
/// Fail-closed startup floors (OWASP Password Storage). A misconfiguration that would weaken Argon2 below
/// the floor — or an impossible password-length window — must throw, not silently downgrade security.
/// </summary>
[TestFixture]
public sealed class AuthCryptoOptionsTests
{
    private static AuthCryptoOptions Valid() => new()
    {
        MemoryKiB = 65536, Iterations = 3, Parallelism = 4, SaltBytes = 16, HashBytes = 32,
        MinPasswordChars = 12, MaxPasswordChars = 128, CurrentPepperKeyId = "v1",
    };

    [Test]
    public void Defaults_PassValidation() => Assert.DoesNotThrow(() => new AuthCryptoOptions().ValidateOrThrow());

    [Test]
    public void AtExactFloors_PassesValidation()
    {
        var o = Valid();
        o.MemoryKiB = AuthCryptoOptions.FloorMemoryKiB;
        o.Iterations = AuthCryptoOptions.FloorIterations;
        o.Parallelism = AuthCryptoOptions.FloorParallelism;
        o.SaltBytes = AuthCryptoOptions.FloorSaltBytes;
        o.HashBytes = AuthCryptoOptions.FloorHashBytes;
        Assert.DoesNotThrow(() => o.ValidateOrThrow());
    }

    [Test]
    public void BelowMemoryFloor_Throws()
    {
        var o = Valid(); o.MemoryKiB = AuthCryptoOptions.FloorMemoryKiB - 1;
        Assert.That(() => o.ValidateOrThrow(), Throws.InvalidOperationException);
    }

    [Test]
    public void BelowIterationFloor_Throws()
    {
        var o = Valid(); o.Iterations = AuthCryptoOptions.FloorIterations - 1;
        Assert.That(() => o.ValidateOrThrow(), Throws.InvalidOperationException);
    }

    [Test]
    public void BelowParallelismFloor_Throws()
    {
        var o = Valid(); o.Parallelism = 0;
        Assert.That(() => o.ValidateOrThrow(), Throws.InvalidOperationException);
    }

    [Test]
    public void BelowSaltFloor_Throws()
    {
        var o = Valid(); o.SaltBytes = 15;
        Assert.That(() => o.ValidateOrThrow(), Throws.InvalidOperationException);
    }

    [Test]
    public void BelowHashFloor_Throws()
    {
        var o = Valid(); o.HashBytes = 31;
        Assert.That(() => o.ValidateOrThrow(), Throws.InvalidOperationException);
    }

    [Test]
    public void MinPasswordBelow12_Throws()
    {
        var o = Valid(); o.MinPasswordChars = 11;
        Assert.That(() => o.ValidateOrThrow(), Throws.InvalidOperationException);
    }

    [TestCase(63)]
    [TestCase(4097)]
    public void MaxPasswordOutOfRange_Throws(int max)
    {
        var o = Valid(); o.MaxPasswordChars = max;
        Assert.That(() => o.ValidateOrThrow(), Throws.InvalidOperationException);
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("   ")]
    public void BlankPepperKeyId_Throws(string? id)
    {
        var o = Valid(); o.CurrentPepperKeyId = id!;
        Assert.That(() => o.ValidateOrThrow(), Throws.InvalidOperationException);
    }

    [Test]
    public void EffectiveMaxConcurrentHashes_ZeroFallsBackToProcessorCount()
    {
        var o = Valid(); o.MaxConcurrentHashes = 0;
        Assert.That(o.EffectiveMaxConcurrentHashes, Is.EqualTo(Environment.ProcessorCount));
    }

    [Test]
    public void EffectiveMaxConcurrentHashes_HonorsExplicitPositive()
    {
        var o = Valid(); o.MaxConcurrentHashes = 3;
        Assert.That(o.EffectiveMaxConcurrentHashes, Is.EqualTo(3));
    }
}
