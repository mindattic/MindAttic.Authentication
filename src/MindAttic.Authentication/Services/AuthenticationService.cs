using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MindAttic.Authentication.Crypto;
using MindAttic.Authentication.Data;
using MindAttic.Authentication.Entities;
using MindAttic.Authentication.Internal;
using MindAttic.Authentication.Options;

namespace MindAttic.Authentication.Services;

public enum LoginStatus { Success, MfaRequired, Failed }

/// <summary>
/// Result of a login step. On <see cref="LoginStatus.Success"/> the endpoint signs <see cref="Claims"/>
/// into the real cookie; on <see cref="LoginStatus.MfaRequired"/> it signs a short-lived pending principal
/// carrying only the user id and exchanges it after <c>ConfirmMfaAsync</c>.
/// </summary>
public sealed record LoginResult(LoginStatus Status, Guid? UserId = null, IReadOnlyList<Claim>? Claims = null)
{
    public static readonly LoginResult Failed = new(LoginStatus.Failed);
}

public interface IAuthenticationService
{
    Task<LoginResult> LoginAsync(string userName, string password, string sourceIp, string userAgent, CancellationToken ct = default);
    Task<LoginResult> ConfirmMfaAsync(Guid userId, string code, bool isRecoveryCode, string sourceIp, string userAgent, CancellationToken ct = default);
}

/// <summary>
/// The login pipeline: throttle pre-filter (cheap, before any Argon2) → real/decoy verify → reset lockout
/// + rehash-on-success → MFA step-up → session creation → audit. Uniform failure (generic, decoy-costed)
/// so timing/responses never reveal which factor failed. The HTTP endpoint owns SignInAsync + the timing
/// floor; this service never touches HttpContext.
/// </summary>
public sealed class AuthenticationService(
    IUserStore users,
    IPasswordHasher hasher,
    IAccountLockoutService lockout,
    IAuthAuditWriter audit,
    ITotpService totp,
    IDataProtectionProvider dpProvider,
    IAuthDataContext db,
    IOptions<AuthSessionOptions> sessionOptions,
    TimeProvider clock) : IAuthenticationService
{
    private readonly IDataProtector _totpProtector = dpProvider.CreateProtector("MindAttic.Authentication.Totp.v1");
    private readonly AuthSessionOptions _session = sessionOptions.Value;

    public async Task<LoginResult> LoginAsync(string userName, string password, string sourceIp, string userAgent, CancellationToken ct = default)
    {
        var now = clock.GetUtcNow().UtcDateTime;

        // Cheap throttle pre-filter BEFORE any Argon2 (so a flood never pays hashing cost).
        var accountBlocked = !(await lockout.CheckAsync(ThrottleScope.Account, userName, ct)).Allowed;
        var ipBlocked = !(await lockout.CheckAsync(ThrottleScope.Ip, sourceIp, ct)).Allowed;
        if (accountBlocked || ipBlocked)
        {
            hasher.VerifyDecoy(password);  // uniform cost
            await audit.WriteAsync(new AuthAuditEntry(AuthEventType.Login, AuthOutcome.Throttled, AuthReasonCode.Locked,
                UserNameAttempted: userName, AccountKeyRaw: userName, SourceIpRaw: sourceIp, UserAgent: userAgent), ct);
            return LoginResult.Failed;
        }

        var user = await users.FindByUserNameAsync(userName, ct);

        bool verified;
        bool needsRehash = false;
        if (user is null || !user.IsActive)
        {
            hasher.VerifyDecoy(password);   // no username oracle
            verified = false;
        }
        else
        {
            var r = hasher.Verify(password, user.PasswordHash, user.PasswordPepperKeyId, user.LegacyHashScheme);
            verified = r.Succeeded;
            needsRehash = r.NeedsRehash;
        }

        if (!verified)
        {
            await lockout.RecordFailureAsync(ThrottleScope.Account, userName, ct);
            await lockout.RecordFailureAsync(ThrottleScope.Ip, sourceIp, ct);
            await audit.WriteAsync(new AuthAuditEntry(AuthEventType.Login, AuthOutcome.Failure,
                user is null ? AuthReasonCode.UnknownUser : (user.IsActive ? AuthReasonCode.BadPassword : AuthReasonCode.Disabled),
                user?.Id, userName, userName, sourceIp, userAgent), ct);
            return LoginResult.Failed;
        }

        // Success on the password factor.
        await lockout.ResetAsync(ThrottleScope.Account, userName, ct);
        await lockout.ResetAsync(ThrottleScope.Ip, sourceIp, ct);
        if (needsRehash)
        {
            var rehashed = hasher.Hash(password);
            users.ApplyRehash(user!, rehashed.Phc, rehashed.PepperKeyId);
        }
        users.RecordLogin(user!, now);
        await users.SaveChangesAsync(ct);

        if (user!.MfaEnabled)
        {
            await audit.WriteAsync(new AuthAuditEntry(AuthEventType.Login, AuthOutcome.StepUpRequired, AuthReasonCode.MfaRequired,
                user.Id, userName, userName, sourceIp, userAgent), ct);
            return new LoginResult(LoginStatus.MfaRequired, user.Id);
        }

        var sid = await CreateSessionAsync(user, sourceIp, userAgent, now, ct);
        await audit.WriteAsync(new AuthAuditEntry(AuthEventType.Login, AuthOutcome.Success, AuthReasonCode.Ok,
            user.Id, userName, userName, sourceIp, userAgent), ct);
        return new LoginResult(LoginStatus.Success, user.Id, BuildClaims(user, sid, ["pwd"]));
    }

    public async Task<LoginResult> ConfirmMfaAsync(Guid userId, string code, bool isRecoveryCode, string sourceIp, string userAgent, CancellationToken ct = default)
    {
        var now = clock.GetUtcNow().UtcDateTime;

        // MFA attempts feed the same account backoff.
        var user = await users.FindByIdAsync(userId, ct);
        if (user is null || !user.IsActive || !user.MfaEnabled)
            return LoginResult.Failed;

        if (!(await lockout.CheckAsync(ThrottleScope.Account, user.UserName, ct)).Allowed)
        {
            await audit.WriteAsync(new AuthAuditEntry(AuthEventType.MfaChallenge, AuthOutcome.Throttled, AuthReasonCode.Locked,
                user.Id, user.UserName, user.UserName, sourceIp, userAgent), ct);
            return LoginResult.Failed;
        }

        var ok = isRecoveryCode
            ? await TryConsumeRecoveryCodeAsync(user, code, ct)
            : await TryConsumeTotpAsync(user, code, ct);

        if (!ok)
        {
            await lockout.RecordFailureAsync(ThrottleScope.Account, user.UserName, ct);
            await lockout.RecordFailureAsync(ThrottleScope.Ip, sourceIp, ct);
            await audit.WriteAsync(new AuthAuditEntry(AuthEventType.MfaChallenge, AuthOutcome.Failure, AuthReasonCode.MfaBad,
                user.Id, user.UserName, user.UserName, sourceIp, userAgent), ct);
            return LoginResult.Failed;
        }

        await lockout.ResetAsync(ThrottleScope.Account, user.UserName, ct);
        await lockout.ResetAsync(ThrottleScope.Ip, sourceIp, ct);
        var sid = await CreateSessionAsync(user, sourceIp, userAgent, now, ct);
        await audit.WriteAsync(new AuthAuditEntry(
            isRecoveryCode ? AuthEventType.RecoveryUsed : AuthEventType.MfaChallenge,
            AuthOutcome.Success, AuthReasonCode.Ok, user.Id, user.UserName, user.UserName, sourceIp, userAgent), ct);
        return new LoginResult(LoginStatus.Success, user.Id, BuildClaims(user, sid, ["pwd", "mfa"]));
    }

    private async Task<bool> TryConsumeTotpAsync(AuthUser user, string code, CancellationToken ct)
    {
        var mfa = await users.FindMfaAsync(user.Id, ct);
        if (mfa is not { Enabled: true, SecretEncrypted: { Length: > 0 } enc }) return false;
        byte[] secret;
        try { secret = _totpProtector.Unprotect(enc); } catch { return false; }
        var step = totp.Validate(secret, code, mfa.LastTotpStepUsed);
        if (step is null) return false;
        mfa.LastTotpStepUsed = step.Value;   // replay guard, under RowVersion concurrency
        await db.SaveChangesAsync(ct);
        return true;
    }

    private async Task<bool> TryConsumeRecoveryCodeAsync(AuthUser user, string code, CancellationToken ct)
    {
        var candidates = await db.AuthRecoveryCodes
            .Where(c => c.UserId == user.Id && c.UsedUtc == null)
            .ToListAsync(ct);
        foreach (var rc in candidates)
        {
            if (hasher.Verify(code.Trim(), rc.CodeHash, rc.CodePepperKeyId, null).Succeeded)
            {
                rc.UsedUtc = clock.GetUtcNow().UtcDateTime;
                await db.SaveChangesAsync(ct);
                return true;
            }
        }
        return false;
    }

    private async Task<Guid> CreateSessionAsync(AuthUser user, string sourceIp, string userAgent, DateTime now, CancellationToken ct)
    {
        var session = new AuthSession
        {
            AuthUserId = user.Id,
            CreatedUtc = now,
            LastSeenUtc = now,
            AbsoluteExpiryUtc = now + _session.AbsoluteTimeout,
            IpHash = AuthKeys.HashHex(AuthKeys.CanonicalizeIp(sourceIp)),
            UserAgent = Trunc(userAgent, 512),
        };
        db.AuthSessions.Add(session);
        await db.SaveChangesAsync(ct);
        return session.Id;
    }

    private static string Trunc(string? s, int max) => string.IsNullOrEmpty(s) ? "" : (s.Length <= max ? s : s[..max]);

    private static IReadOnlyList<Claim> BuildClaims(AuthUser user, Guid sessionId, string[] amr)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(MaClaims.UserId, user.Id.ToString()),
            new(ClaimTypes.Name, user.UserName),
            new(ClaimTypes.Role, user.Role),
            new(MaClaims.SecurityStamp, user.SecurityStamp),
            new(MaClaims.SessionId, sessionId.ToString()),
        };
        if (user.MustChangePassword) claims.Add(new Claim(MaClaims.MustChangePassword, "1"));
        if (user.MustEnrollMfa) claims.Add(new Claim(MaClaims.MustEnrollMfa, "1"));
        foreach (var a in amr) claims.Add(new Claim(MaClaims.Amr, a));
        return claims;
    }
}
