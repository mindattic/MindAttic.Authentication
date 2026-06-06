using MindAttic.Authentication.Entities;
using MindAttic.Authentication.Services;
using MindAttic.Authentication.Tests.TestSupport;

namespace MindAttic.Authentication.Tests.Services;

/// <summary>
/// Brute-force backoff (NIST 800-63B 5.2.2). The exponential curve must match spec exactly, per-account and
/// per-IP scopes must not bleed into each other, equivalent keys must collapse (NFKC account / IPv6 /64),
/// and a full reset must clear the counter.
/// </summary>
[TestFixture]
public sealed class AccountLockoutServiceTests
{
    // ── the curve: f<=3 ⇒ 0; then 1,2,4,…s doubling; capped at 900s ──
    [TestCase(0, 0)]
    [TestCase(1, 0)]
    [TestCase(2, 0)]
    [TestCase(3, 0)]
    [TestCase(4, 1)]
    [TestCase(5, 2)]
    [TestCase(6, 4)]
    [TestCase(7, 8)]
    [TestCase(8, 16)]
    [TestCase(13, 512)]
    [TestCase(14, 900)]   // 2^10 = 1024 → capped
    [TestCase(20, 900)]   // stays capped
    [TestCase(100, 900)]
    public void BackoffFor_MatchesSpecCurve(int failures, int expectedSeconds) =>
        Assert.That(AccountLockoutService.BackoffFor(failures), Is.EqualTo(TimeSpan.FromSeconds(expectedSeconds)));

    private static (AccountLockoutService svc, TestAuthDbContext db, FixedClock clock) NewService()
    {
        var db = TestAuthDbContext.NewInMemory();
        var clock = FixedClock.At(new DateTimeOffset(2026, 6, 6, 12, 0, 0, TimeSpan.Zero));
        return (new AccountLockoutService(db, clock), db, clock);
    }

    [Test]
    public async Task Check_OnUnknownKey_IsAllowed()
    {
        var (svc, _, _) = NewService();
        var decision = await svc.CheckAsync(ThrottleScope.Account, "nobody@example.com");
        Assert.That(decision.Allowed, Is.True);
        Assert.That(decision.RetryAfter, Is.EqualTo(TimeSpan.Zero));
    }

    [Test]
    public async Task RecordFailure_BelowThreshold_StaysAllowed()
    {
        var (svc, _, _) = NewService();
        for (var i = 0; i < 3; i++) await svc.RecordFailureAsync(ThrottleScope.Account, "alice@example.com");
        Assert.That((await svc.CheckAsync(ThrottleScope.Account, "alice@example.com")).Allowed, Is.True,
            "first 3 failures incur no backoff");
    }

    [Test]
    public async Task RecordFailure_AboveThreshold_BlocksWithRetryAfter()
    {
        var (svc, _, _) = NewService();
        for (var i = 0; i < 4; i++) await svc.RecordFailureAsync(ThrottleScope.Account, "alice@example.com");
        var decision = await svc.CheckAsync(ThrottleScope.Account, "alice@example.com");
        Assert.That(decision.Allowed, Is.False);
        Assert.That(decision.RetryAfter, Is.GreaterThan(TimeSpan.Zero));
    }

    [Test]
    public async Task Check_AfterBackoffWindowElapses_IsAllowedAgain()
    {
        var (svc, _, clock) = NewService();
        for (var i = 0; i < 4; i++) await svc.RecordFailureAsync(ThrottleScope.Account, "alice@example.com");
        clock.Advance(TimeSpan.FromSeconds(5)); // past BackoffFor(4)=1s
        Assert.That((await svc.CheckAsync(ThrottleScope.Account, "alice@example.com")).Allowed, Is.True);
    }

    [Test]
    public async Task Reset_ClearsTheCounter()
    {
        var (svc, db, _) = NewService();
        for (var i = 0; i < 5; i++) await svc.RecordFailureAsync(ThrottleScope.Account, "alice@example.com");
        await svc.ResetAsync(ThrottleScope.Account, "alice@example.com");
        Assert.That((await svc.CheckAsync(ThrottleScope.Account, "alice@example.com")).Allowed, Is.True);
        Assert.That(db.AuthLoginThrottles, Is.Empty, "reset removes the row (full success only)");
    }

    [Test]
    public async Task AccountAndIpScopes_AreIndependent()
    {
        var (svc, _, _) = NewService();
        for (var i = 0; i < 6; i++) await svc.RecordFailureAsync(ThrottleScope.Account, "alice@example.com");
        // Same raw string, different SCOPE ⇒ different throttle row ⇒ unaffected.
        Assert.That((await svc.CheckAsync(ThrottleScope.Ip, "alice@example.com")).Allowed, Is.True);
    }

    [Test]
    public async Task Account_NormalizesEquivalentKeys()
    {
        var (svc, _, _) = NewService();
        for (var i = 0; i < 4; i++) await svc.RecordFailureAsync(ThrottleScope.Account, "Alice@Example.COM");
        // Case/whitespace-equivalent identity must hit the SAME backoff row.
        Assert.That((await svc.CheckAsync(ThrottleScope.Account, "  alice@example.com ")).Allowed, Is.False);
    }

    [Test]
    public async Task Ip_KeysOnSlash64_SoRotatingTheHostDoesNotEvade()
    {
        var (svc, _, _) = NewService();
        for (var i = 0; i < 4; i++) await svc.RecordFailureAsync(ThrottleScope.Ip, "2001:db8:abcd:1234::1");
        // A different host inside the SAME /64 must remain throttled.
        Assert.That((await svc.CheckAsync(ThrottleScope.Ip, "2001:db8:abcd:1234::99")).Allowed, Is.False);
    }
}
