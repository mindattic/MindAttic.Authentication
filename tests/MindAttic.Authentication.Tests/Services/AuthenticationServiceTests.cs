using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using MindAttic.Authentication.Crypto;
using MindAttic.Authentication.Entities;
using MindAttic.Authentication.Internal;
using MindAttic.Authentication.Options;
using MindAttic.Authentication.Services;
using MindAttic.Authentication.Tests.TestSupport;

namespace MindAttic.Authentication.Tests.Services;

/// <summary>
/// <see cref="AuthenticationService.LoginAsync"/> — the login gate. Covers the throttle pre-filter
/// (no user lookup, uniform decoy cost), the unknown/inactive/bad-password failure paths (decoy cost,
/// correct audit reason), the success path (throttle reset, rehash-on-login, session shape, claims), and
/// the MFA step-up branch (no session, no claims). Alert side effects are covered separately in
/// <see cref="SecurityAlertTests"/>; this suite always passes <c>alerts: null</c> to isolate the pipeline.
/// </summary>
[TestFixture]
public sealed class AuthenticationServiceTests
{
    private const string Password = "Correct-Passphrase-1";
    private const string WrongPassword = "Wrong-Passphrase-99";

    /// <summary>Counts calls so throttle/unknown/inactive paths can assert "decoy ran, real verify did not".</summary>
    private sealed class SpyHasher(IPasswordHasher inner) : IPasswordHasher
    {
        public int DecoyCalls { get; private set; }
        public int VerifyCalls { get; private set; }

        public PasswordHash Hash(string password) => inner.Hash(password);

        public PasswordVerifyResult Verify(string password, string storedHash, string? pepperKeyId, string? legacyScheme)
        {
            VerifyCalls++;
            return inner.Verify(password, storedHash, pepperKeyId, legacyScheme);
        }

        public void VerifyDecoy(string password)
        {
            DecoyCalls++;
            inner.VerifyDecoy(password);
        }
    }

    /// <summary>Counts lookups so the throttle path can assert no user lookup ever happens.</summary>
    private sealed class SpyUserStore(IUserStore inner) : IUserStore
    {
        public int FindByUserNameCalls { get; private set; }
        public int ApplyRehashCalls { get; private set; }

        public Task<AuthUser?> FindByUserNameAsync(string userName, CancellationToken ct = default)
        {
            FindByUserNameCalls++;
            return inner.FindByUserNameAsync(userName, ct);
        }

        public Task<AuthUser?> FindByIdAsync(Guid id, CancellationToken ct = default) => inner.FindByIdAsync(id, ct);
        public Task<AuthUserMfa?> FindMfaAsync(Guid userId, CancellationToken ct = default) => inner.FindMfaAsync(userId, ct);
        public Task<bool> AnyUsersAsync(CancellationToken ct = default) => inner.AnyUsersAsync(ct);
        public Task SaveChangesAsync(CancellationToken ct = default) => inner.SaveChangesAsync(ct);

        public void ApplyRehash(AuthUser user, string phc, string pepperKeyId)
        {
            ApplyRehashCalls++;
            inner.ApplyRehash(user, phc, pepperKeyId);
        }

        public void RecordLogin(AuthUser user, DateTime utcNow) => inner.RecordLogin(user, utcNow);
    }

    private sealed class Harness
    {
        public required TestAuthDbContext Db { get; init; }
        public required FixedClock Clock { get; init; }
        public required SpyHasher Hasher { get; init; }
        public required SpyUserStore UserStore { get; init; }
        public required FakeAuditWriter Audit { get; init; }
        public required AuthSessionOptions SessionOptions { get; init; }
        public IDataProtectionProvider Dp { get; } = new EphemeralDataProtectionProvider();

        public AuthenticationService Auth() => new(UserStore, Hasher, new AccountLockoutService(Db, Clock),
            Audit, new TotpService(Build.Opt(new MfaOptions()), Clock), Dp, Db, Build.Opt(SessionOptions), Clock);
    }

    private static async Task<Harness> NewAsync(AuthSessionOptions? sessionOptions = null)
    {
        var clock = FixedClock.At(new DateTimeOffset(2026, 6, 6, 12, 0, 0, TimeSpan.Zero));
        var db = TestAuthDbContext.NewInMemory();
        var h = new Harness
        {
            Db = db, Clock = clock,
            Hasher = new SpyHasher(Build.Hasher()),
            UserStore = new SpyUserStore(new UserStore(db)),
            Audit = new FakeAuditWriter(),
            SessionOptions = sessionOptions ?? new AuthSessionOptions(),
        };
        return await Task.FromResult(h);
    }

    private static async Task<AuthUser> SeedAsync(Harness h, string userName = "alice", bool isActive = true,
        bool mfaEnabled = false, bool mustChangePassword = false, bool mustEnrollMfa = false,
        string password = Password, string? passwordPepperKeyId = null)
    {
        var stored = passwordPepperKeyId is null
            ? Build.Hasher().Hash(password)
            : Build.Hasher(Build.FastCrypto(passwordPepperKeyId)).Hash(password);
        var user = new AuthUser
        {
            UserName = userName, NormalizedUserName = IUserStore.Normalize(userName),
            Email = $"{userName}@example.com", NormalizedEmail = $"{userName}@example.com".ToUpperInvariant(),
            PasswordHash = stored.Phc, PasswordPepperKeyId = stored.PepperKeyId,
            Role = "User", IsActive = isActive, MfaEnabled = mfaEnabled,
            MustChangePassword = mustChangePassword, MustEnrollMfa = mustEnrollMfa,
            CreatedUtc = h.Clock.GetUtcNow().UtcDateTime,
        };
        h.Db.AuthUsers.Add(user);
        await h.Db.SaveChangesAsync();
        return user;
    }

    // ── throttle pre-filter: no user lookup, uniform decoy cost, generic failure ──

    [Test]
    public async Task AccountThrottled_RunsDecoy_AuditsThrottledLocked_AndNeverLooksUpTheUser()
    {
        var h = await NewAsync();
        await SeedAsync(h);
        var lockout = new AccountLockoutService(h.Db, h.Clock);
        for (var i = 0; i < 4; i++) await lockout.RecordFailureAsync(ThrottleScope.Account, "alice");   // pre-seed backoff
        var auth = h.Auth();

        var result = await auth.LoginAsync("alice", Password, "203.0.113.1", "Browser/1");

        Assert.That(result, Is.SameAs(LoginResult.Failed));
        Assert.That(h.Hasher.DecoyCalls, Is.EqualTo(1));
        Assert.That(h.Hasher.VerifyCalls, Is.EqualTo(0), "throttled login must never reach real Argon2 verify");
        Assert.That(h.UserStore.FindByUserNameCalls, Is.EqualTo(0), "throttled login must never look up the user");
        var entry = h.Audit.Entries.Single();
        Assert.That(entry.EventType, Is.EqualTo(AuthEventType.Login));
        Assert.That(entry.Outcome, Is.EqualTo(AuthOutcome.Throttled));
        Assert.That(entry.Reason, Is.EqualTo(AuthReasonCode.Locked));
        Assert.That(entry.UserId, Is.Null);
    }

    [Test]
    public async Task IpThrottled_RunsDecoy_AuditsThrottledLocked_AndNeverLooksUpTheUser()
    {
        var h = await NewAsync();
        await SeedAsync(h);
        var lockout = new AccountLockoutService(h.Db, h.Clock);
        for (var i = 0; i < 4; i++) await lockout.RecordFailureAsync(ThrottleScope.Ip, "203.0.113.1");   // pre-seed backoff
        var auth = h.Auth();

        var result = await auth.LoginAsync("alice", Password, "203.0.113.1", "Browser/1");

        Assert.That(result, Is.SameAs(LoginResult.Failed));
        Assert.That(h.Hasher.DecoyCalls, Is.EqualTo(1));
        Assert.That(h.Hasher.VerifyCalls, Is.EqualTo(0), "throttled login must never reach real Argon2 verify");
        Assert.That(h.UserStore.FindByUserNameCalls, Is.EqualTo(0), "IP-throttled login must never look up the user");
        var entry = h.Audit.Entries.Single();
        Assert.That(entry.Outcome, Is.EqualTo(AuthOutcome.Throttled));
        Assert.That(entry.Reason, Is.EqualTo(AuthReasonCode.Locked));
    }

    // ── unknown / inactive user: decoy runs, no username oracle, correct audit reason ──

    [Test]
    public async Task UnknownUser_RunsDecoy_AndAuditsUnknownUser()
    {
        var h = await NewAsync();
        var auth = h.Auth();

        var result = await auth.LoginAsync("ghost", Password, "203.0.113.1", "Browser/1");

        Assert.That(result, Is.SameAs(LoginResult.Failed));
        Assert.That(h.Hasher.DecoyCalls, Is.EqualTo(1));
        Assert.That(h.Hasher.VerifyCalls, Is.EqualTo(0));
        var entry = h.Audit.Entries.Single();
        Assert.That(entry.Outcome, Is.EqualTo(AuthOutcome.Failure));
        Assert.That(entry.Reason, Is.EqualTo(AuthReasonCode.UnknownUser));
        Assert.That(entry.UserId, Is.Null);
    }

    [Test]
    public async Task InactiveUser_RunsDecoy_AndAuditsDisabled()
    {
        var h = await NewAsync();
        var user = await SeedAsync(h, isActive: false);
        var auth = h.Auth();

        var result = await auth.LoginAsync("alice", Password, "203.0.113.1", "Browser/1");

        Assert.That(result, Is.SameAs(LoginResult.Failed));
        Assert.That(h.Hasher.DecoyCalls, Is.EqualTo(1));
        Assert.That(h.Hasher.VerifyCalls, Is.EqualTo(0), "inactive users must take the decoy path, not the real verify");
        var entry = h.Audit.Entries.Single();
        Assert.That(entry.Outcome, Is.EqualTo(AuthOutcome.Failure));
        Assert.That(entry.Reason, Is.EqualTo(AuthReasonCode.Disabled));
        Assert.That(entry.UserId, Is.EqualTo(user.Id));
    }

    // ── bad password: records failures on BOTH scopes, audits BadPassword ──

    [Test]
    public async Task BadPassword_RecordsFailureOnBothAccountAndIpScopes_AndAuditsBadPassword()
    {
        var h = await NewAsync();
        var user = await SeedAsync(h);
        var auth = h.Auth();

        var result = await auth.LoginAsync("alice", WrongPassword, "203.0.113.1", "Browser/1");

        Assert.That(result, Is.SameAs(LoginResult.Failed));
        Assert.That(h.Hasher.VerifyCalls, Is.EqualTo(1), "a known, active user takes the real verify path");
        var accountThrottle = h.Db.AuthLoginThrottles.Single(t => t.Scope == ThrottleScope.Account);
        var ipThrottle = h.Db.AuthLoginThrottles.Single(t => t.Scope == ThrottleScope.Ip);
        Assert.That(accountThrottle.ConsecutiveFailures, Is.EqualTo(1));
        Assert.That(ipThrottle.ConsecutiveFailures, Is.EqualTo(1));
        var entry = h.Audit.Entries.Single();
        Assert.That(entry.Outcome, Is.EqualTo(AuthOutcome.Failure));
        Assert.That(entry.Reason, Is.EqualTo(AuthReasonCode.BadPassword));
        Assert.That(entry.UserId, Is.EqualTo(user.Id));
    }

    // ── success path ──

    [Test]
    public async Task Success_ResetsBothThrottles_AndDoesNotRehashWhenNotNeeded()
    {
        var h = await NewAsync();
        var user = await SeedAsync(h);
        var auth = h.Auth();
        await auth.LoginAsync("alice", WrongPassword, "203.0.113.1", "Browser/1");   // seed both throttle rows

        var result = await auth.LoginAsync("alice", Password, "203.0.113.1", "Browser/1");

        Assert.That(result.Status, Is.EqualTo(LoginStatus.Success));
        Assert.That(h.Db.AuthLoginThrottles, Is.Empty, "success resets (removes) both throttle rows");
        Assert.That(h.UserStore.ApplyRehashCalls, Is.EqualTo(0), "a hash at current params must not be rehashed");
    }

    [Test]
    public async Task Success_AppliesRehash_OnlyWhenVerifyReportsNeedsRehash()
    {
        var h = await NewAsync();
        // Hashed under a pepper id ("v0") that is no longer the hasher's current pepper ("v1") ⇒ NeedsRehash.
        var user = await SeedAsync(h, passwordPepperKeyId: "v0");
        var originalHash = user.PasswordHash;   // `user` is the same tracked entity ApplyRehash mutates in place
        var auth = h.Auth();

        var result = await auth.LoginAsync("alice", Password, "203.0.113.1", "Browser/1");

        Assert.That(result.Status, Is.EqualTo(LoginStatus.Success));
        Assert.That(h.UserStore.ApplyRehashCalls, Is.EqualTo(1));
        var stored = h.Db.AuthUsers.Single(u => u.Id == user.Id);
        Assert.That(stored.PasswordPepperKeyId, Is.EqualTo("v1"), "rehash must move the user onto the current pepper");
        Assert.That(stored.PasswordHash, Is.Not.EqualTo(originalHash));
    }

    [Test]
    public async Task Success_StampsLastLoginUtc()
    {
        var h = await NewAsync();
        var user = await SeedAsync(h);
        var auth = h.Auth();

        await auth.LoginAsync("alice", Password, "203.0.113.1", "Browser/1");

        var stored = h.Db.AuthUsers.Single(u => u.Id == user.Id);
        Assert.That(stored.LastLoginUtc, Is.EqualTo(h.Clock.GetUtcNow().UtcDateTime));
    }

    [Test]
    public async Task Success_CreatesASessionWithHashedIp_TruncatedUserAgent_AndAbsoluteExpiry()
    {
        var sessionOptions = new AuthSessionOptions { AbsoluteTimeout = TimeSpan.FromHours(3) };
        var h = await NewAsync(sessionOptions);
        var user = await SeedAsync(h);
        var auth = h.Auth();
        var longUserAgent = new string('x', 600);

        var result = await auth.LoginAsync("alice", Password, "203.0.113.1", longUserAgent);

        var sessionId = result.Claims!.Single(c => c.Type == MaClaims.SessionId).Value;
        var session = h.Db.AuthSessions.Single(s => s.Id == Guid.Parse(sessionId));
        Assert.That(session.AuthUserId, Is.EqualTo(user.Id));
        Assert.That(session.IpHash, Is.EqualTo(AuthKeys.HashHex(AuthKeys.CanonicalizeIp("203.0.113.1"))));
        Assert.That(session.IpHash, Does.Not.Contain("203.0.113.1"));
        Assert.That(session.UserAgent, Has.Length.EqualTo(512));
        Assert.That(session.UserAgent, Is.EqualTo(longUserAgent[..512]));
        Assert.That(session.CreatedUtc, Is.EqualTo(h.Clock.GetUtcNow().UtcDateTime));
        Assert.That(session.AbsoluteExpiryUtc, Is.EqualTo(h.Clock.GetUtcNow().UtcDateTime + sessionOptions.AbsoluteTimeout));
    }

    [Test]
    public async Task Success_AuditsSuccessWithOkReason()
    {
        var h = await NewAsync();
        var user = await SeedAsync(h);
        var auth = h.Auth();

        await auth.LoginAsync("alice", Password, "203.0.113.1", "Browser/1");

        var entry = h.Audit.Entries.Single();
        Assert.That(entry.Outcome, Is.EqualTo(AuthOutcome.Success));
        Assert.That(entry.Reason, Is.EqualTo(AuthReasonCode.Ok));
        Assert.That(entry.UserId, Is.EqualTo(user.Id));
    }

    // ── MFA step-up: no session, no claims ──

    [Test]
    public async Task MfaEnabledUser_ReturnsMfaRequired_WithNoSessionAndNoClaims()
    {
        var h = await NewAsync();
        var user = await SeedAsync(h, mfaEnabled: true);
        var auth = h.Auth();

        var result = await auth.LoginAsync("alice", Password, "203.0.113.1", "Browser/1");

        Assert.That(result.Status, Is.EqualTo(LoginStatus.MfaRequired));
        Assert.That(result.UserId, Is.EqualTo(user.Id));
        Assert.That(result.Claims, Is.Null);
        Assert.That(h.Db.AuthSessions, Is.Empty, "no session is created before MFA step-up");
        var entry = h.Audit.Entries.Single();
        Assert.That(entry.Outcome, Is.EqualTo(AuthOutcome.StepUpRequired));
        Assert.That(entry.Reason, Is.EqualTo(AuthReasonCode.MfaRequired));
    }

    [Test]
    public async Task MfaEnabledUser_StillResetsThrottles_AndStampsLastLogin_BeforeTheStepUp()
    {
        var h = await NewAsync();
        var user = await SeedAsync(h, mfaEnabled: true);
        var auth = h.Auth();
        await auth.LoginAsync("alice", WrongPassword, "203.0.113.1", "Browser/1");

        await auth.LoginAsync("alice", Password, "203.0.113.1", "Browser/1");

        Assert.That(h.Db.AuthLoginThrottles, Is.Empty);
        Assert.That(h.Db.AuthUsers.Single(u => u.Id == user.Id).LastLoginUtc, Is.EqualTo(h.Clock.GetUtcNow().UtcDateTime));
    }

    // ── claims shape ──

    [Test]
    public async Task Claims_IncludeIdentityRoleStampSessionAndPwdAmr_ButNoOptionalFlagsWhenUnset()
    {
        var h = await NewAsync();
        var user = await SeedAsync(h);
        var auth = h.Auth();

        var result = await auth.LoginAsync("alice", Password, "203.0.113.1", "Browser/1");

        var claims = result.Claims!;
        Assert.That(claims.Single(c => c.Type == ClaimTypes.NameIdentifier).Value, Is.EqualTo(user.Id.ToString()));
        Assert.That(claims.Single(c => c.Type == MaClaims.UserId).Value, Is.EqualTo(user.Id.ToString()));
        Assert.That(claims.Single(c => c.Type == ClaimTypes.Name).Value, Is.EqualTo("alice"));
        Assert.That(claims.Single(c => c.Type == ClaimTypes.Role).Value, Is.EqualTo("User"));
        Assert.That(claims.Single(c => c.Type == MaClaims.SecurityStamp).Value, Is.EqualTo(user.SecurityStamp));
        Assert.That(claims.Single(c => c.Type == MaClaims.SessionId).Value, Is.Not.Empty);
        Assert.That(claims.Where(c => c.Type == MaClaims.Amr).Select(c => c.Value), Is.EqualTo(new[] { "pwd" }));
        Assert.That(claims.Any(c => c.Type == MaClaims.MustChangePassword), Is.False);
        Assert.That(claims.Any(c => c.Type == MaClaims.MustEnrollMfa), Is.False);
    }

    [Test]
    public async Task Claims_IncludeMustChangePassword_OnlyWhenSet()
    {
        var h = await NewAsync();
        await SeedAsync(h, mustChangePassword: true);
        var auth = h.Auth();

        var result = await auth.LoginAsync("alice", Password, "203.0.113.1", "Browser/1");

        Assert.That(result.Claims!.Single(c => c.Type == MaClaims.MustChangePassword).Value, Is.EqualTo("1"));
        Assert.That(result.Claims!.Any(c => c.Type == MaClaims.MustEnrollMfa), Is.False);
    }

    [Test]
    public async Task Claims_IncludeMustEnrollMfa_OnlyWhenSet()
    {
        var h = await NewAsync();
        await SeedAsync(h, mustEnrollMfa: true);
        var auth = h.Auth();

        var result = await auth.LoginAsync("alice", Password, "203.0.113.1", "Browser/1");

        Assert.That(result.Claims!.Single(c => c.Type == MaClaims.MustEnrollMfa).Value, Is.EqualTo("1"));
        Assert.That(result.Claims!.Any(c => c.Type == MaClaims.MustChangePassword), Is.False);
    }
}
