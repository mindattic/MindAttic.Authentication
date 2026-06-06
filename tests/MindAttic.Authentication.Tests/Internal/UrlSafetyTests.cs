using MindAttic.Authentication.Internal;

namespace MindAttic.Authentication.Tests.Internal;

/// <summary>
/// Open-redirect defense (ASVS 5.1.5). <see cref="UrlSafety.IsLocalUrl"/> must accept only same-site
/// relative paths and reject every flavor of absolute / protocol-relative / scheme / control-char URL an
/// attacker uses to bounce a victim off-site after login.
/// </summary>
[TestFixture]
public sealed class UrlSafetyTests
{
    [TestCase("/")]
    [TestCase("/account/manage")]
    [TestCase("/a/b/c?x=1&y=2#frag")]
    [TestCase("/path-with-dashes_and.dots")]
    [TestCase("~/local")]
    [TestCase("/single")]
    public void IsLocalUrl_AcceptsSameSiteRelativePaths(string url) =>
        Assert.That(UrlSafety.IsLocalUrl(url), Is.True, url);

    // The classic open-redirect bypass corpus.
    [TestCase("//evil.com")]                    // protocol-relative
    [TestCase("/\\evil.com")]                   // backslash trick
    [TestCase("https://evil.com")]              // absolute https
    [TestCase("http://evil.com")]               // absolute http
    [TestCase("HtTpS://evil.com")]              // mixed-case scheme
    [TestCase("javascript:alert(1)")]           // scheme: pseudo-protocol
    [TestCase("data:text/html,<script>")]       // data URI
    [TestCase("ftp://evil.com")]                // other scheme
    [TestCase("mailto:a@b.com")]                // mailto
    [TestCase("//evil.com/path")]               // protocol-relative w/ path
    [TestCase("\\\\evil.com")]                  // UNC-ish
    [TestCase("evil.com")]                       // bare host (no leading /)
    [TestCase("account/manage")]                // relative without leading slash
    [TestCase("@evil.com")]                     // userinfo trick
    public void IsLocalUrl_RejectsOffSiteAndSchemeUrls(string url) =>
        Assert.That(UrlSafety.IsLocalUrl(url), Is.False, url);

    [TestCase(null)]
    [TestCase("")]
    public void IsLocalUrl_RejectsNullAndEmpty(string? url) =>
        Assert.That(UrlSafety.IsLocalUrl(url), Is.False);

    // Control chars (TAB, LF, CR, NUL, unit-separator, DEL) must be rejected wherever they appear —
    // request-smuggling and header-splitting guards. Built from codepoints to keep source clean.
    [TestCase(0x09)]
    [TestCase(0x0A)]
    [TestCase(0x0D)]
    [TestCase(0x00)]
    [TestCase(0x1F)]
    [TestCase(0x7F)]
    public void IsLocalUrl_RejectsEmbeddedControlChar(int code) =>
        Assert.That(UrlSafety.IsLocalUrl($"/path{(char)code}more"), Is.False, $"0x{code:X2}");

    [TestCase(0x09)]
    [TestCase(0x0A)]
    [TestCase(0x0D)]
    public void IsLocalUrl_RejectsLeadingControlCharBeforeProtocolRelative(int code) =>
        Assert.That(UrlSafety.IsLocalUrl($"{(char)code}//evil.com"), Is.False, $"0x{code:X2}");

    [Test]
    public void LocalOrDefault_ReturnsUrlWhenLocal() =>
        Assert.That(UrlSafety.LocalOrDefault("/ok", "/fallback"), Is.EqualTo("/ok"));

    [Test]
    public void LocalOrDefault_ReturnsFallbackWhenNotLocal() =>
        Assert.That(UrlSafety.LocalOrDefault("//evil.com", "/fallback"), Is.EqualTo("/fallback"));

    [Test]
    public void LocalOrDefault_DefaultFallbackIsRoot() =>
        Assert.That(UrlSafety.LocalOrDefault("https://evil.com"), Is.EqualTo("/"));
}
