using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MindAttic.Authentication.Crypto;
using MindAttic.Authentication.Data;
using MindAttic.Authentication.Entities;
using MindAttic.Authentication.Options;

namespace MindAttic.Authentication.Services;

public readonly record struct EnrollmentBeginResult(string SecretBase32, string OtpAuthUri);
public readonly record struct EnrollmentConfirmResult(bool Ok, IReadOnlyList<string>? RecoveryCodes, string? Error);

public interface IMfaEnrollmentService
{
    Task<EnrollmentBeginResult> BeginAsync(Guid userId, CancellationToken ct = default);
    /// <summary>Confirms a pending TOTP secret (with password reauth), enables MFA, returns recovery codes ONCE.</summary>
    Task<EnrollmentConfirmResult> ConfirmAsync(Guid userId, string code, string currentPassword, CancellationToken ct = default);
}

/// <summary>
/// TOTP enrollment: verify-before-enable. The pending secret is Data-Protection-encrypted and only
/// promoted to active after a valid code AND a fresh password reauth. Enabling rotates the SecurityStamp
/// and issues single-use recovery codes (stored only as Argon2id+pepper hashes).
/// </summary>
public sealed class MfaEnrollmentService(
    IUserStore users,
    IAuthDataContext db,
    ITotpService totp,
    IPasswordHasher hasher,
    IDataProtectionProvider dpProvider,
    IAuthAuditWriter audit,
    IOptions<MfaOptions> mfaOptions,
    TimeProvider clock) : IMfaEnrollmentService
{
    private readonly IDataProtector _totpProtector = dpProvider.CreateProtector("MindAttic.Authentication.Totp.v1");
    private readonly MfaOptions _mfa = mfaOptions.Value;

    public async Task<EnrollmentBeginResult> BeginAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await users.FindByIdAsync(userId, ct) ?? throw new InvalidOperationException("User not found.");
        var secret = totp.GenerateSecret();
        var now = clock.GetUtcNow().UtcDateTime;

        var mfa = await users.FindMfaAsync(userId, ct);
        if (mfa is null)
        {
            mfa = new AuthUserMfa { UserId = userId };
            db.AuthUserMfa.Add(mfa);
        }
        mfa.PendingSecretEncrypted = _totpProtector.Protect(secret);
        mfa.PendingExpiresUtc = now.AddMinutes(_mfa.PendingEnrollmentMinutes);
        await db.SaveChangesAsync(ct);

        return new EnrollmentBeginResult(totp.ToBase32(secret), totp.BuildOtpAuthUri(secret, user.UserName));
    }

    public async Task<EnrollmentConfirmResult> ConfirmAsync(Guid userId, string code, string currentPassword, CancellationToken ct = default)
    {
        var user = await users.FindByIdAsync(userId, ct);
        if (user is null || !user.IsActive) return new(false, null, "Enrollment failed.");

        // Fresh password reauth (sensitive operation).
        if (!hasher.Verify(currentPassword, user.PasswordHash, user.PasswordPepperKeyId, user.LegacyHashScheme).Succeeded)
            return new(false, null, "Enrollment failed.");

        var mfa = await users.FindMfaAsync(userId, ct);
        var now = clock.GetUtcNow().UtcDateTime;
        if (mfa?.PendingSecretEncrypted is not { Length: > 0 } pending || mfa.PendingExpiresUtc is null || mfa.PendingExpiresUtc < now)
            return new(false, null, "Enrollment expired. Start again.");

        byte[] secret;
        try { secret = _totpProtector.Unprotect(pending); } catch { return new(false, null, "Enrollment failed."); }

        var step = totp.Validate(secret, code, 0);
        if (step is null) return new(false, null, "That code was not accepted.");

        // Promote pending → active.
        mfa.SecretEncrypted = pending;
        mfa.PendingSecretEncrypted = null;
        mfa.PendingExpiresUtc = null;
        mfa.Enabled = true;
        mfa.ActivatedUtc = now;
        mfa.LastTotpStepUsed = step.Value;

        user.MfaEnabled = true;
        user.MustEnrollMfa = false;
        user.SecurityStamp = Guid.NewGuid().ToString("N");   // rotate → live sessions revalidate

        var codes = await RegenerateRecoveryCodesAsync(userId, ct);
        await db.SaveChangesAsync(ct);

        await audit.WriteAsync(new AuthAuditEntry(AuthEventType.MfaEnroll, AuthOutcome.Success, AuthReasonCode.Ok,
            user.Id, user.UserName), ct);
        return new(true, codes, null);
    }

    private async Task<IReadOnlyList<string>> RegenerateRecoveryCodesAsync(Guid userId, CancellationToken ct)
    {
        var existing = await db.AuthRecoveryCodes.Where(c => c.UserId == userId).ToListAsync(ct);
        db.AuthRecoveryCodes.RemoveRange(existing);

        var batch = Guid.NewGuid();
        var now = clock.GetUtcNow().UtcDateTime;
        var plaintext = totp.GenerateRecoveryCodes();
        foreach (var code in plaintext)
        {
            var hash = hasher.Hash(code);
            db.AuthRecoveryCodes.Add(new AuthRecoveryCode
            {
                UserId = userId, CodeHash = hash.Phc, CodePepperKeyId = hash.PepperKeyId,
                BatchId = batch, CreatedUtc = now,
            });
        }
        return plaintext;
    }
}
