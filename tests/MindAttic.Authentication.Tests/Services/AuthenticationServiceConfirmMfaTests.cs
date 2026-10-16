using Microsoft.AspNetCore.DataProtection;
using MindAttic.Authentication.Crypto;
using MindAttic.Authentication.Data;
using MindAttic.Authentication.Entities;
using MindAttic.Authentication.Options;
using MindAttic.Authentication.Services;
using MindAttic.Authentication.Tests.TestSupport;

namespace MindAttic.Authentication.Tests.Services;

/// <summary>
/// <see cref="AuthenticationService.ConfirmMfaAsync"/> — second-factor correctness and replay protection.
/// A TOTP step is single-use (NIST 800-63B 5.2.8), a recovery code is single-use and matched only against
/// unused rows, both factors feed the same account+IP backoff on failure, and success resets throttles,
/// opens a session, and audits the right event type (<c>MfaChallenge</c> vs <c>RecoveryUsed</c>) with the
/// step-up <c>amr=[pwd,mfa]</c> claim set.
/// </summary>
[TestFixture]
public sealed class AuthenticationServiceConfirmMfaTests
{
    private const string Password = "Initial-Passphrase-1";
    private const string Ip = "203.0.113.7";
    private const string UserAgent = "Browser/1";

    private sealed class Harness
    {
        public required TestAuthDbContext Db { get; init; }
        public required Argon2idPasswordHasher Hasher { get; init; }
        public required FixedClock Clock { get; init; }
        public required FakeAuditWriter Audit { get; init; }
        public required AccountLockoutService Lockout { get; init; }
        public IDataProtectionProvider Dp { get; } = new EphemeralDataProtectionProvider();

        public AuthenticationService Svc() => new(new UserStore(Db), Hasher, Lockout, Audit,
            new TotpService(Build.Opt(new MfaOptions()), Clock), Dp, Db, Build.Opt(new AuthSessionOptions()), Clock);
    }

    private static Harness New()
    {
        var db = TestAuthDbContext.NewInMemory();
        var clock = FixedClock.At(new DateTimeOffset(2026, 6, 6, 12, 0, 0, TimeSpan.Zero));
        return new Harness { Db = db, Hasher = Build.Hasher(), Clock = clock, Audit = new FakeAuditWriter(), Lockout = new AccountLockoutService(db, clock) };
    }

    private static async Task<AuthUser> SeedUserAsync(Harness h, string userName = "alice", bool isActive = true, bool mfaEnabled = true)
    {
        var stored = h.Hasher.Hash(Password);
        var user = new AuthUser
        {
            UserName = userName, NormalizedUserName = IUserStore.Normalize(userName),
            PasswordHash = stored.Phc, PasswordPepperKeyId = stored.PepperKeyId,
            Role = "User", IsActive = isActive, MfaEnabled = mfaEnabled, CreatedUtc = h.Clock.GetUtcNow().UtcDateTime,
        };
        h.Db.AuthUsers.Add(user);
        await h.Db.SaveChangesAsync();
        return user;
    }

    /// <summary>Enrolls a real TOTP secret (DP-protected, as production stores it) and returns the raw bytes.</summary>
    private static async Task<byte[]> EnableTotpAsync(Harness h, AuthUser user, long lastStepUsed = 0, byte[]? secretOverride = null)
    {
        var secret = secretOverride ?? System.Security.Cryptography.RandomNumberGenerator.GetBytes(20);
        var enc = h.Dp.CreateProtector("MindAttic.Authentication.Totp.v1").Protect(secret);
        h.Db.AuthUserMfa.Add(new AuthUserMfa { UserId = user.Id, Enabled = true, SecretEncrypted = enc, LastTotpStepUsed = lastStepUsed, ActivatedUtc = h.Clock.GetUtcNow().UtcDateTime });
        await h.Db.SaveChangesAsync();
        return secret;
    }

    private static async Task AddRecoveryCodeAsync(Harness h, AuthUser user, string plaintext, DateTime? usedUtc = null)
    {
        var stored = h.Hasher.Hash(plaintext);
        h.Db.AuthRecoveryCodes.Add(new AuthRecoveryCode
        {
            UserId = user.Id, CodeHash = stored.Phc, CodePepperKeyId = stored.PepperKeyId,
            BatchId = Guid.NewGuid(), UsedUtc = usedUtc, CreatedUtc = h.Clock.GetUtcNow().UtcDateTime,
        });
        await h.Db.SaveChangesAsync();
    }

    // ── gate: missing / inactive / non-MFA user ──────────────────────────────────────────────

    [Test]
    public async Task UnknownUser_ReturnsFailed()
    {
        var h = New();
        var result = await h.Svc().ConfirmMfaAsync(Guid.NewGuid(), "123456", false, Ip, UserAgent);
        Assert.That(result.Status, Is.EqualTo(LoginStatus.Failed));
        Assert.That(h.Audit.Entries, Is.Empty, "an unknown id must not even be audited (no account to key on)");
    }

    [Test]
    public async Task InactiveUser_ReturnsFailed()
    {
        var h = New();
        var user = await SeedUserAsync(h, isActive: false);
        var result = await h.Svc().ConfirmMfaAsync(user.Id, "123456", false, Ip, UserAgent);
        Assert.That(result.Status, Is.EqualTo(LoginStatus.Failed));
        Assert.That(h.Audit.Entries, Is.Empty);
    }

    [Test]
    public async Task NonMfaUser_ReturnsFailed()
    {
        var h = New();
        var user = await SeedUserAsync(h, mfaEnabled: false);
        var result = await h.Svc().ConfirmMfaAsync(user.Id, "123456", false, Ip, UserAgent);
        Assert.That(result.Status, Is.EqualTo(LoginStatus.Failed));
        Assert.That(h.Audit.Entries, Is.Empty);
    }

    // ── throttle ──────────────────────────────────────────────────────────────────────────────

    [Test]
    public async Task LockedAccount_ReturnsFailed_AndAuditsMfaChallengeThrottled()
    {
        var h = New();
        var user = await SeedUserAsync(h);
        var secret = await EnableTotpAsync(h, user);
        for (var i = 0; i < 4; i++) await h.Lockout.RecordFailureAsync(ThrottleScope.Account, user.UserName); // 4th starts back-off

        var code = TotpReference.Compute(secret, TotpReference.StepFor(h.Clock.GetUtcNow()));
        var result = await h.Svc().ConfirmMfaAsync(user.Id, code, false, Ip, UserAgent);

        Assert.That(result.Status, Is.EqualTo(LoginStatus.Failed), "throttled even with a valid code");
        var entry = h.Audit.Entries.Single();
        Assert.That(entry.EventType, Is.EqualTo(AuthEventType.MfaChallenge));
        Assert.That(entry.Outcome, Is.EqualTo(AuthOutcome.Throttled));
        Assert.That(entry.Reason, Is.EqualTo(AuthReasonCode.Locked));
    }

    // ── TOTP: success + replay guard ─────────────────────────────────────────────────────────

    [Test]
    public async Task ValidTotp_Succeeds_PersistsLastStepUsed_AndReplayOfSameCodeFails()
    {
        var h = New();
        var user = await SeedUserAsync(h);
        var secret = await EnableTotpAsync(h, user);
        var step = TotpReference.StepFor(h.Clock.GetUtcNow());
        var code = TotpReference.Compute(secret, step);

        var result = await h.Svc().ConfirmMfaAsync(user.Id, code, false, Ip, UserAgent);

        Assert.That(result.Status, Is.EqualTo(LoginStatus.Success));
        Assert.That(h.Db.AuthUserMfa.Single(m => m.UserId == user.Id).LastTotpStepUsed, Is.EqualTo(step));

        // Replay: the exact same code at the same (now-consumed) step must be rejected.
        var replay = await h.Svc().ConfirmMfaAsync(user.Id, code, false, Ip, UserAgent);
        Assert.That(replay.Status, Is.EqualTo(LoginStatus.Failed), "a consumed TOTP step must never validate again");
    }

    // ── TOTP: no usable secret / tampering ───────────────────────────────────────────────────

    [Test]
    public async Task NoMfaRow_FailsWithoutThrowing()
    {
        var h = New();
        var user = await SeedUserAsync(h);
        Assert.DoesNotThrowAsync(async () =>
        {
            var result = await h.Svc().ConfirmMfaAsync(user.Id, "123456", false, Ip, UserAgent);
            Assert.That(result.Status, Is.EqualTo(LoginStatus.Failed));
        });
    }

    [Test]
    public async Task MfaRowDisabled_FailsWithoutThrowing()
    {
        var h = New();
        var user = await SeedUserAsync(h);
        var secret = await EnableTotpAsync(h, user);
        h.Db.AuthUserMfa.Single(m => m.UserId == user.Id).Enabled = false;
        await h.Db.SaveChangesAsync();

        var code = TotpReference.Compute(secret, TotpReference.StepFor(h.Clock.GetUtcNow()));
        var result = await h.Svc().ConfirmMfaAsync(user.Id, code, false, Ip, UserAgent);
        Assert.That(result.Status, Is.EqualTo(LoginStatus.Failed));
    }

    [Test]
    public async Task MfaRowWithEmptySecret_FailsWithoutThrowing()
    {
        var h = New();
        var user = await SeedUserAsync(h);
        h.Db.AuthUserMfa.Add(new AuthUserMfa { UserId = user.Id, Enabled = true, SecretEncrypted = [], LastTotpStepUsed = 0 });
        await h.Db.SaveChangesAsync();

        var result = await h.Svc().ConfirmMfaAsync(user.Id, "123456", false, Ip, UserAgent);
        Assert.That(result.Status, Is.EqualTo(LoginStatus.Failed));
    }

    [Test]
    public async Task TamperedSecretEncrypted_FailsWithoutThrowing()
    {
        var h = New();
        var user = await SeedUserAsync(h);
        await EnableTotpAsync(h, user);
        var mfa = h.Db.AuthUserMfa.Single(m => m.UserId == user.Id);
        mfa.SecretEncrypted![^1] ^= 0xFF; // flip a byte: Data Protection must now refuse to unprotect
        await h.Db.SaveChangesAsync();

        LoginResult? result = null;
        Assert.DoesNotThrowAsync(async () => result = await h.Svc().ConfirmMfaAsync(user.Id, "123456", false, Ip, UserAgent));
        Assert.That(result!.Status, Is.EqualTo(LoginStatus.Failed));
    }

    // ── recovery code: trim, single-use, unused-only match ───────────────────────────────────

    [Test]
    public async Task RecoveryCode_IsTrimmedBeforeMatching()
    {
        var h = New();
        var user = await SeedUserAsync(h);
        await AddRecoveryCodeAsync(h, user, "correct-horse-battery");

        var result = await h.Svc().ConfirmMfaAsync(user.Id, "  correct-horse-battery  ", true, Ip, UserAgent);
        Assert.That(result.Status, Is.EqualTo(LoginStatus.Success));
    }

    [Test]
    public async Task RecoveryCode_MarksUsedUtc_AndCannotBeReused()
    {
        var h = New();
        var user = await SeedUserAsync(h);
        await AddRecoveryCodeAsync(h, user, "correct-horse-battery");

        var first = await h.Svc().ConfirmMfaAsync(user.Id, "correct-horse-battery", true, Ip, UserAgent);
        Assert.That(first.Status, Is.EqualTo(LoginStatus.Success));
        var row = h.Db.AuthRecoveryCodes.Single(c => c.UserId == user.Id);
        Assert.That(row.UsedUtc, Is.EqualTo(h.Clock.GetUtcNow().UtcDateTime));

        var second = await h.Svc().ConfirmMfaAsync(user.Id, "correct-horse-battery", true, Ip, UserAgent);
        Assert.That(second.Status, Is.EqualTo(LoginStatus.Failed), "a used recovery code must never work twice");
    }

    [Test]
    public async Task RecoveryCode_AlreadyUsedRow_IsNotMatched_EvenThoughItsHashIsStillValid()
    {
        var h = New();
        var user = await SeedUserAsync(h);
        // Seed the row as already-used (simulates a prior redemption) — the query must exclude it outright.
        await AddRecoveryCodeAsync(h, user, "correct-horse-battery", usedUtc: h.Clock.GetUtcNow().UtcDateTime.AddDays(-1));

        var result = await h.Svc().ConfirmMfaAsync(user.Id, "correct-horse-battery", true, Ip, UserAgent);
        Assert.That(result.Status, Is.EqualTo(LoginStatus.Failed));
    }

    [Test]
    public async Task RecoveryCode_WrongCode_Fails()
    {
        var h = New();
        var user = await SeedUserAsync(h);
        await AddRecoveryCodeAsync(h, user, "correct-horse-battery");

        var result = await h.Svc().ConfirmMfaAsync(user.Id, "wrong-horse-battery-x", true, Ip, UserAgent);
        Assert.That(result.Status, Is.EqualTo(LoginStatus.Failed));
    }

    // ── failure path: throttle + audit ───────────────────────────────────────────────────────

    [Test]
    public async Task Failure_RecordsAccountAndIpFailures_AndAuditsMfaBad()
    {
        var h = New();
        var user = await SeedUserAsync(h);
        await EnableTotpAsync(h, user);

        var result = await h.Svc().ConfirmMfaAsync(user.Id, "000000", false, Ip, UserAgent);

        Assert.That(result.Status, Is.EqualTo(LoginStatus.Failed));
        Assert.That((await h.Lockout.CheckAsync(ThrottleScope.Account, user.UserName)).Allowed, Is.True, "one failure alone is below the back-off threshold");
        for (var i = 0; i < 3; i++) await h.Svc().ConfirmMfaAsync(user.Id, "000000", false, Ip, UserAgent); // 4 total

        Assert.That((await h.Lockout.CheckAsync(ThrottleScope.Account, user.UserName)).Allowed, Is.False, "account scope must accumulate MFA failures");
        Assert.That((await h.Lockout.CheckAsync(ThrottleScope.Ip, Ip)).Allowed, Is.False, "IP scope must accumulate MFA failures too");

        var entry = h.Audit.Entries.Last();
        Assert.That(entry.EventType, Is.EqualTo(AuthEventType.MfaChallenge));
        Assert.That(entry.Outcome, Is.EqualTo(AuthOutcome.Failure));
        Assert.That(entry.Reason, Is.EqualTo(AuthReasonCode.MfaBad));
    }

    // ── success path: throttle reset, session, audit event type, claims ─────────────────────

    [Test]
    public async Task TotpSuccess_ResetsThrottles_CreatesSession_AuditsMfaChallengeSuccess_AndReturnsAmrPwdMfaClaims()
    {
        var h = New();
        var user = await SeedUserAsync(h);
        var secret = await EnableTotpAsync(h, user);
        await h.Lockout.RecordFailureAsync(ThrottleScope.Account, user.UserName);
        await h.Lockout.RecordFailureAsync(ThrottleScope.Ip, Ip);

        var code = TotpReference.Compute(secret, TotpReference.StepFor(h.Clock.GetUtcNow()));
        var result = await h.Svc().ConfirmMfaAsync(user.Id, code, false, Ip, UserAgent);

        Assert.That(result.Status, Is.EqualTo(LoginStatus.Success));
        Assert.That((await h.Lockout.CheckAsync(ThrottleScope.Account, user.UserName)).Allowed, Is.True, "success must reset the account throttle");
        Assert.That((await h.Lockout.CheckAsync(ThrottleScope.Ip, Ip)).Allowed, Is.True, "success must reset the IP throttle");
        Assert.That(h.Db.AuthSessions.Count(s => s.AuthUserId == user.Id), Is.EqualTo(1));

        var entry = h.Audit.Entries.Single();
        Assert.That(entry.EventType, Is.EqualTo(AuthEventType.MfaChallenge));
        Assert.That(entry.Outcome, Is.EqualTo(AuthOutcome.Success));

        var amr = result.Claims!.Where(c => c.Type == MaClaims.Amr).Select(c => c.Value).ToArray();
        Assert.That(amr, Is.EqualTo(new[] { "pwd", "mfa" }));
    }

    [Test]
    public async Task RecoveryCodeSuccess_AuditsRecoveryUsed_NotMfaChallenge()
    {
        var h = New();
        var user = await SeedUserAsync(h);
        await AddRecoveryCodeAsync(h, user, "correct-horse-battery");

        var result = await h.Svc().ConfirmMfaAsync(user.Id, "correct-horse-battery", true, Ip, UserAgent);

        Assert.That(result.Status, Is.EqualTo(LoginStatus.Success));
        var entry = h.Audit.Entries.Single();
        Assert.That(entry.EventType, Is.EqualTo(AuthEventType.RecoveryUsed));
        Assert.That(entry.Outcome, Is.EqualTo(AuthOutcome.Success));

        var amr = result.Claims!.Where(c => c.Type == MaClaims.Amr).Select(c => c.Value).ToArray();
        Assert.That(amr, Is.EqualTo(new[] { "pwd", "mfa" }));
    }
}
