using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using MindAttic.Authentication.Crypto;
using MindAttic.Authentication.Entities;
using MindAttic.Authentication.Options;
using MindAttic.Authentication.Services;
using MindAttic.Authentication.Tests.TestSupport;

namespace MindAttic.Authentication.Tests.Services;

/// <summary>
/// NIST-aligned password policy (length only, no composition rules) + HIBP breach check that FAILS OPEN +
/// reuse-history rejection. Tests pin the length window, the offline worst-passwords corpus, breached vs
/// not-breached HIBP parsing, the audited fail-open path, and history reuse.
/// </summary>
[TestFixture]
public sealed class PasswordPolicyTests
{
    private static (PasswordPolicy policy, TestAuthDbContext db, FakeAuditWriter audit, Argon2idPasswordHasher hasher)
        New(AuthPolicyOptions o, IHttpClientFactory http)
    {
        var db = TestAuthDbContext.NewInMemory();
        var audit = new FakeAuditWriter();
        var hasher = Build.Hasher();
        var policy = new PasswordPolicy(http, Build.Opt(o), db, hasher, audit, NullLogger<PasswordPolicy>.Instance);
        return (policy, db, audit, hasher);
    }

    private static AuthPolicyOptions Opts(bool hibp = false, int min = 12, int max = 128) =>
        new() { CheckHibp = hibp, MinLength = min, MaxLength = max, HibpFailOpen = true, HistoryDepth = 5 };

    [Test]
    public async Task TooShort_IsRejected()
    {
        var (policy, _, _, _) = New(Opts(), StubHttpClientFactory.ThatReturns(""));
        var r = await policy.ValidateAsync("short11chars"[..5]);
        Assert.That(r.Ok, Is.False);
    }

    [Test]
    public async Task TooLong_IsRejected()
    {
        var (policy, _, _, _) = New(Opts(), StubHttpClientFactory.ThatReturns(""));
        var r = await policy.ValidateAsync(new string('a', 129));
        Assert.That(r.Ok, Is.False);
    }

    [Test]
    public async Task Null_IsRejected()
    {
        var (policy, _, _, _) = New(Opts(), StubHttpClientFactory.ThatReturns(""));
        var r = await policy.ValidateAsync(null!);
        Assert.That(r.Ok, Is.False);
    }

    [Test]
    public async Task OfflineWorstList_IsRejected()
    {
        // Lower the min so a worst-list entry clears the length gate and reaches the corpus check.
        var (policy, _, _, _) = New(Opts(min: 6), StubHttpClientFactory.ThatReturns(""));
        var r = await policy.ValidateAsync("passw0rd");
        Assert.That(r.Ok, Is.False);
        Assert.That(r.Reason, Does.Contain("common"));
    }

    [Test]
    public async Task HibpBreached_IsRejected()
    {
        const string pw = "Zaphod-Beeblebrox-2026";
        var (prefix, suffix) = Sha1PrefixSuffix(pw);
        var http = StubHttpClientFactory.ThatReturns($"{suffix}:42\r\n0000000000000000000000000000000000:1");
        var (policy, _, _, _) = New(Opts(hibp: true), http);
        var r = await policy.ValidateAsync(pw);
        Assert.That(r.Ok, Is.False);
        Assert.That(r.Reason, Does.Contain("breach"));
    }

    [Test]
    public async Task HibpNotBreached_IsAllowed()
    {
        const string pw = "Zaphod-Beeblebrox-2026";
        var http = StubHttpClientFactory.ThatReturns("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:9"); // a suffix that won't match
        var (policy, _, _, _) = New(Opts(hibp: true), http);
        var r = await policy.ValidateAsync(pw);
        Assert.That(r.Ok, Is.True);
    }

    [Test]
    public async Task HibpOutage_FailsOpen_AndAuditsTheSkip()
    {
        const string pw = "Zaphod-Beeblebrox-2026";
        var (policy, _, audit, _) = New(Opts(hibp: true), StubHttpClientFactory.ThatThrows());
        var r = await policy.ValidateAsync(pw);
        Assert.That(r.Ok, Is.True, "HIBP must fail OPEN (never self-DoS password changes)");
        Assert.That(audit.Entries.Any(e => e.EventType == AuthEventType.HibpOnlineSkipped), Is.True,
            "every fail-open skip must be audited");
    }

    [Test]
    public async Task ReusedPassword_IsRejected()
    {
        const string reused = "OldReused-Passphrase-1";
        var (policy, db, _, hasher) = New(Opts(), StubHttpClientFactory.ThatReturns(""));
        var userId = Guid.NewGuid();
        var stored = hasher.Hash(reused);
        db.AuthPasswordHistory.Add(new AuthPasswordHistory
        {
            UserId = userId, PasswordHash = stored.Phc, PepperKeyId = stored.PepperKeyId,
            CreatedUtc = DateTime.UtcNow,
        });
        await db.SaveChangesAsync();

        Assert.That((await policy.ValidateAsync(reused, userId)).Ok, Is.False, "reuse must be rejected");
        Assert.That((await policy.ValidateAsync("A-Totally-New-Passphrase-9", userId)).Ok, Is.True);
    }

    private static (string prefix, string suffix) Sha1PrefixSuffix(string password)
    {
        var hex = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password.Normalize(System.Text.NormalizationForm.FormKC))));
        return (hex[..5], hex[5..]);
    }
}
