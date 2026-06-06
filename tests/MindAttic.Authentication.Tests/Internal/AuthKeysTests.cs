using System.Security.Cryptography;
using System.Text;
using MindAttic.Authentication.Internal;

namespace MindAttic.Authentication.Tests.Internal;

/// <summary>
/// Throttle/audit key canonicalization. Raw accounts/IPs must never be stored; equivalent identities must
/// collapse to the same key (so an attacker can't dodge per-account/per-IP backoff by trivial mutation),
/// and IPv6 must key on the /64 prefix.
/// </summary>
[TestFixture]
public sealed class AuthKeysTests
{
    [Test]
    public void NormalizeAccount_LowercasesAndTrims() =>
        Assert.That(AuthKeys.NormalizeAccount("  Alice@Example.COM "), Is.EqualTo("alice@example.com"));

    [Test]
    public void NormalizeAccount_IsNfkcSoCompatibilityFormsCollapse()
    {
        // Fullwidth 'ＡＤＭＩＮ' (U+FF21…) → NFKC → "admin"
        const string fullwidth = "ＡＤＭＩＮ";
        Assert.That(AuthKeys.NormalizeAccount(fullwidth), Is.EqualTo("admin"));
    }

    [Test]
    public void NormalizeAccount_NullIsEmpty() =>
        Assert.That(AuthKeys.NormalizeAccount(null!), Is.EqualTo(""));

    [Test]
    public void CanonicalizeIp_Ipv4PassesThrough() =>
        Assert.That(AuthKeys.CanonicalizeIp("203.0.113.7"), Is.EqualTo("203.0.113.7"));

    [TestCase("2001:db8:abcd:1234:ffff:ffff:ffff:ffff")]
    [TestCase("2001:db8:abcd:1234::1")]
    [TestCase("2001:db8:abcd:1234:0:0:0:abcd")]
    public void CanonicalizeIp_Ipv6CollapsesToSlash64(string addr)
    {
        // Every address sharing the /64 prefix must map to the same key (defeats trivial host rotation).
        Assert.That(AuthKeys.CanonicalizeIp(addr), Is.EqualTo("2001:db8:abcd:1234::/64"));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("   ")]
    [TestCase("not-an-ip")]
    [TestCase("999.999.999.999")]
    public void CanonicalizeIp_UnparseableBecomesUnknown(string? ip) =>
        Assert.That(AuthKeys.CanonicalizeIp(ip), Is.EqualTo("unknown"));

    [Test]
    public void Hash_IsSha256_DeterministicAnd32Bytes()
    {
        var h = AuthKeys.Hash("alice@example.com");
        var expected = SHA256.HashData(Encoding.UTF8.GetBytes("alice@example.com"));
        Assert.That(h, Has.Length.EqualTo(32));
        Assert.That(h, Is.EqualTo(expected));
        Assert.That(AuthKeys.Hash("alice@example.com"), Is.EqualTo(h), "must be deterministic");
    }

    [Test]
    public void Hash_DiffersForDifferentKeys() =>
        Assert.That(AuthKeys.Hash("a@x.com"), Is.Not.EqualTo(AuthKeys.Hash("b@x.com")));

    [Test]
    public void HashHex_IsLowercase64HexChars()
    {
        var hex = AuthKeys.HashHex("203.0.113.7");
        Assert.That(hex, Has.Length.EqualTo(64));
        Assert.That(hex, Is.EqualTo(hex.ToLowerInvariant()));
        Assert.That(hex, Does.Match("^[0-9a-f]{64}$"));
    }
}
