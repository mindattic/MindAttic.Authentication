using System.Text;
using System.Text.RegularExpressions;
using MindAttic.Authentication.Options;
using MindAttic.Authentication.Services;
using MindAttic.Authentication.Tests.TestSupport;

namespace MindAttic.Authentication.Tests.Services;

/// <summary>
/// TOTP (RFC 6238) + recovery codes. Validates against the official RFC test vectors, proves the ±1 step
/// acceptance window, and — critically — the replay guard: a step at or below <c>LastTotpStepUsed</c> must
/// never be accepted again (NIST 800-63B 5.2.8). Recovery codes must be plentiful, formatted, and unique.
/// </summary>
[TestFixture]
public sealed class TotpServiceTests
{
    private static TotpService New(MfaOptions? o = null, FixedClock? clock = null) =>
        new(Build.Opt(o ?? new MfaOptions()), clock ?? FixedClock.AtUtcNow());

    // RFC 6238 Appendix B vectors (HMAC-SHA1, seed = ASCII "12345678901234567890", 8 digits).
    private static readonly byte[] RfcSeed = Encoding.ASCII.GetBytes("12345678901234567890");

    [TestCase(59L, "94287082")]
    [TestCase(1111111109L, "07081804")]
    [TestCase(1111111111L, "14050471")]
    [TestCase(1234567890L, "89005924")]
    [TestCase(2000000000L, "69279037")]
    public void Validate_MatchesRfc6238TestVectors(long unixTime, string expectedCode)
    {
        var clock = FixedClock.At(DateTimeOffset.FromUnixTimeSeconds(unixTime));
        var svc = New(new MfaOptions { Digits = 8, PeriodSeconds = 30, WindowSteps = 1 }, clock);
        var step = unixTime / 30;
        var matched = svc.Validate(RfcSeed, expectedCode, lastStepUsed: step - 1);
        Assert.That(matched, Is.EqualTo(step), "the RFC vector code must validate at its step");
    }

    [Test]
    public void Validate_RejectsReplayedStep()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1111111111);
        var clock = FixedClock.At(now);
        var o = new MfaOptions { Digits = 6, PeriodSeconds = 30, WindowSteps = 1 };
        var svc = New(o, clock);
        var step = now.ToUnixTimeSeconds() / 30;
        var code = TotpReference.Compute(RfcSeed, step, o.Digits);

        // First use: accepted (lastStepUsed is older).
        Assert.That(svc.Validate(RfcSeed, code, lastStepUsed: step - 1), Is.EqualTo(step));
        // Replay: the same step is now consumed ⇒ rejected.
        Assert.That(svc.Validate(RfcSeed, code, lastStepUsed: step), Is.Null);
    }

    [Test]
    public void Validate_AcceptsCodeWithinWindow()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1111111111);
        var o = new MfaOptions { Digits = 6, PeriodSeconds = 30, WindowSteps = 1 };
        var svc = New(o, FixedClock.At(now));
        var step = now.ToUnixTimeSeconds() / 30;
        var prevCode = TotpReference.Compute(RfcSeed, step - 1, o.Digits); // one step early
        Assert.That(svc.Validate(RfcSeed, prevCode, lastStepUsed: step - 3), Is.EqualTo(step - 1));
    }

    [Test]
    public void Validate_RejectsCodeOutsideWindow()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1111111111);
        var o = new MfaOptions { Digits = 6, PeriodSeconds = 30, WindowSteps = 1 };
        var svc = New(o, FixedClock.At(now));
        var step = now.ToUnixTimeSeconds() / 30;
        var farCode = TotpReference.Compute(RfcSeed, step - 2, o.Digits); // two steps early → outside ±1
        Assert.That(svc.Validate(RfcSeed, farCode, lastStepUsed: step - 5), Is.Null);
    }

    [TestCase("")]
    [TestCase("   ")]
    [TestCase(null)]
    public void Validate_BlankCode_ReturnsNull(string? code)
    {
        var svc = New();
        Assert.That(svc.Validate(RfcSeed, code!, 0), Is.Null);
    }

    [Test]
    public void Validate_WrongCode_ReturnsNull()
    {
        var svc = New(new MfaOptions { Digits = 6 }, FixedClock.AtUtcNow());
        Assert.That(svc.Validate(RfcSeed, "000000", lastStepUsed: 0), Is.Null);
    }

    [Test]
    public void GenerateSecret_Is160Bit()
    {
        var svc = New();
        Assert.That(svc.GenerateSecret(), Has.Length.EqualTo(20));
    }

    [Test]
    public void Base32_IsRfc4648AlphabetAndCorrectLength()
    {
        var svc = New();
        var b32 = svc.ToBase32(new byte[20]); // 20 bytes → 32 base32 chars
        Assert.That(b32, Has.Length.EqualTo(32));
        Assert.That(b32, Does.Match("^[A-Z2-7]+$"));
    }

    [Test]
    public void BuildOtpAuthUri_CarriesExplicitAlgorithmParameters()
    {
        var svc = New(new MfaOptions { Issuer = "MindAttic", Digits = 6, PeriodSeconds = 30 });
        var uri = svc.BuildOtpAuthUri(new byte[20], "alice@example.com");
        Assert.That(uri, Does.StartWith("otpauth://totp/"));
        Assert.That(uri, Does.Contain("algorithm=SHA1"));
        Assert.That(uri, Does.Contain("digits=6"));
        Assert.That(uri, Does.Contain("period=30"));
        Assert.That(uri, Does.Contain("issuer=MindAttic"));
        Assert.That(uri, Does.Contain("secret="));
    }

    [Test]
    public void GenerateRecoveryCodes_AreCountedFormattedAndUnique()
    {
        var svc = New(new MfaOptions { RecoveryCodeCount = 10, RecoveryCodeBytes = 10 });
        var codes = svc.GenerateRecoveryCodes();
        Assert.That(codes, Has.Count.EqualTo(10));
        Assert.That(codes.Distinct().Count(), Is.EqualTo(10), "recovery codes must be unique");
        foreach (var c in codes)
            Assert.That(Regex.IsMatch(c, "^[a-z2-7]{4}(-[a-z2-7]{4})+$"), Is.True, c);
    }
}
