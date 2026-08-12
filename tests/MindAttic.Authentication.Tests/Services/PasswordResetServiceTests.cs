using MindAttic.Authentication.Crypto;
using MindAttic.Authentication.Entities;
using MindAttic.Authentication.Options;
using MindAttic.Authentication.Services;
using MindAttic.Authentication.Tests.TestSupport;

namespace MindAttic.Authentication.Tests.Services;

/// <summary>
/// Password reset (NIST 800-63B 5.1.3 / ASVS 2.5). Tokens are single-use, short-lived, stored only as an
/// HMAC (never plaintext); requesting is enumeration-safe; confirming rotates the stamp, pushes history,
/// invalidates sibling tokens, and never auto-logs-in. A per-hour cap blocks email amplification.
/// </summary>
[TestFixture]
public sealed class PasswordResetServiceTests
{
    private sealed class Harness
    {
        public required TestAuthDbContext Db { get; init; }
        public required PasswordResetService Svc { get; init; }
        public required FakeEmailSender Email { get; init; }
        public required FakeAuditWriter Audit { get; init; }
        public required Argon2idPasswordHasher Hasher { get; init; }
        public required FixedClock Clock { get; init; }
    }

    private static Harness New(AuthResetOptions? o = null)
    {
        var db = TestAuthDbContext.NewInMemory();
        var hasher = Build.Hasher();
        var email = new FakeEmailSender();
        var audit = new FakeAuditWriter();
        var clock = FixedClock.At(new DateTimeOffset(2026, 6, 6, 12, 0, 0, TimeSpan.Zero));
        var opts = o ?? new AuthResetOptions
        {
            PublicBaseUrl = "https://app.example.com", ResetPath = "/account/reset",
            TokenTtlMinutes = 15, MaxEmailsPerHour = 3,
        };
        var svc = new PasswordResetService(
            new UserStore(db), db, hasher, new FakePasswordPolicy(), new FakeAuthSecrets(),
            email, audit, Build.Opt(opts), clock);
        return new Harness { Db = db, Svc = svc, Email = email, Audit = audit, Hasher = hasher, Clock = clock };
    }

    private static async Task<AuthUser> SeedUser(Harness h, string userName = "alice", string? email = "alice@example.com")
    {
        var stored = h.Hasher.Hash("Initial-Passphrase-1");
        var user = new AuthUser
        {
            UserName = userName, NormalizedUserName = IUserStore.Normalize(userName),
            Email = email, NormalizedEmail = email?.ToUpperInvariant(),
            PasswordHash = stored.Phc, PasswordPepperKeyId = stored.PepperKeyId,
            Role = "User", IsActive = true, CreatedUtc = h.Clock.GetUtcNow().UtcDateTime,
        };
        h.Db.AuthUsers.Add(user);
        await h.Db.SaveChangesAsync();
        return user;
    }

    [Test]
    public async Task Request_UnknownUser_CreatesNoToken_ButStillAudits()
    {
        var h = New();
        await h.Svc.RequestAsync("ghost", "203.0.113.7", "agent");
        Assert.That(h.Db.AuthPasswordResetTokens, Is.Empty);
        Assert.That(h.Email.Resets, Is.Empty);
        Assert.That(h.Audit.Entries.Any(e => e.EventType == AuthEventType.PasswordReset), Is.True,
            "enumeration-safe: unknown requests look identical and are still audited");
    }

    [Test]
    public async Task Request_KnownUser_CreatesHashedToken_AndEmailsLink()
    {
        var h = New();
        await SeedUser(h);
        await h.Svc.RequestAsync("alice", "203.0.113.7", "agent");

        Assert.That(h.Db.AuthPasswordResetTokens.Count(), Is.EqualTo(1));
        var row = h.Db.AuthPasswordResetTokens.Single();
        Assert.That(row.TokenHash, Has.Length.EqualTo(64), "token stored as HMAC-SHA256 hex, never plaintext");
        Assert.That(h.Email.Resets, Has.Count.EqualTo(1));
        var plaintext = h.Email.LastResetToken();
        Assert.That(row.TokenHash, Is.Not.EqualTo(plaintext), "the stored value must not be the plaintext token");
    }

    [Test]
    public async Task Request_UserWithoutEmail_DoesNotCreateTokenOrEmail()
    {
        var h = New();
        await SeedUser(h, email: null);
        await h.Svc.RequestAsync("alice", "203.0.113.7", "agent");
        Assert.That(h.Db.AuthPasswordResetTokens, Is.Empty);
        Assert.That(h.Email.Resets, Is.Empty);
    }

    [Test]
    public async Task Request_HonorsHourlyCap()
    {
        var h = New();
        var user = await SeedUser(h);
        for (var i = 0; i < 3; i++) await h.Svc.RequestAsync("alice", "203.0.113.7", "agent");
        Assert.That(h.Db.AuthPasswordResetTokens.Count(), Is.EqualTo(3));

        await h.Svc.RequestAsync("alice", "203.0.113.7", "agent"); // 4th within the hour
        Assert.That(h.Db.AuthPasswordResetTokens.Count(), Is.EqualTo(3), "capped at MaxEmailsPerHour");
        Assert.That(h.Email.Resets, Has.Count.EqualTo(3));
    }

    [Test]
    public async Task Confirm_InvalidToken_Fails()
    {
        var h = New();
        await SeedUser(h);
        var result = await h.Svc.ConfirmAsync("not-a-real-token", "Brand-New-Passphrase-1");
        Assert.That(result.Ok, Is.False);
    }

    [Test]
    public async Task Confirm_ValidToken_RotatesStamp_PushesHistory_AndDoesNotAutoLogin()
    {
        var h = New();
        var user = await SeedUser(h);
        var originalStamp = user.SecurityStamp;
        var originalHash = user.PasswordHash;
        await h.Svc.RequestAsync("alice", "203.0.113.7", "agent");
        var token = h.Email.LastResetToken();

        var result = await h.Svc.ConfirmAsync(token, "Brand-New-Passphrase-1");

        Assert.That(result.Ok, Is.True);
        var fresh = h.Db.AuthUsers.Single(u => u.Id == user.Id);
        Assert.That(fresh.PasswordHash, Is.Not.EqualTo(originalHash), "password must be re-hashed");
        Assert.That(fresh.SecurityStamp, Is.Not.EqualTo(originalStamp), "stamp must rotate (kills sessions)");
        Assert.That(fresh.MustChangePassword, Is.False);
        Assert.That(h.Db.AuthPasswordHistory.Any(ph => ph.UserId == user.Id && ph.PasswordHash == originalHash),
            Is.True, "the previous hash must be pushed to history");
        var tokenRow = h.Db.AuthPasswordResetTokens.Single();
        Assert.That(tokenRow.ConsumedUtc, Is.Not.Null, "token must be consumed (single-use)");
    }

    [Test]
    public async Task Confirm_IsSingleUse()
    {
        var h = New();
        await SeedUser(h);
        await h.Svc.RequestAsync("alice", "203.0.113.7", "agent");
        var token = h.Email.LastResetToken();
        Assert.That((await h.Svc.ConfirmAsync(token, "Brand-New-Passphrase-1")).Ok, Is.True);
        Assert.That((await h.Svc.ConfirmAsync(token, "Another-New-Passphrase-2")).Ok, Is.False,
            "a consumed token must not work twice");
    }

    [Test]
    public async Task Confirm_ExpiredToken_Fails()
    {
        var h = New();
        await SeedUser(h);
        await h.Svc.RequestAsync("alice", "203.0.113.7", "agent");
        var token = h.Email.LastResetToken();
        h.Clock.Advance(TimeSpan.FromMinutes(16)); // past the 15-minute TTL
        Assert.That((await h.Svc.ConfirmAsync(token, "Brand-New-Passphrase-1")).Ok, Is.False);
    }

    [Test]
    public async Task Confirm_InvalidatesOtherOutstandingTokens()
    {
        var h = New();
        await SeedUser(h);
        await h.Svc.RequestAsync("alice", "203.0.113.7", "agent");
        var firstToken = h.Email.LastResetToken();
        await h.Svc.RequestAsync("alice", "203.0.113.7", "agent");
        var secondToken = h.Email.LastResetToken();

        Assert.That((await h.Svc.ConfirmAsync(secondToken, "Brand-New-Passphrase-1")).Ok, Is.True);
        // The first, unused token must now be invalid too.
        Assert.That((await h.Svc.ConfirmAsync(firstToken, "Yet-Another-Passphrase-3")).Ok, Is.False);
        Assert.That(h.Db.AuthPasswordResetTokens.Count(t => t.ConsumedUtc != null), Is.EqualTo(2));
    }
}
