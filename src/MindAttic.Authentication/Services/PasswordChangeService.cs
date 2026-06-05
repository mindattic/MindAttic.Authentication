using MindAttic.Authentication.Crypto;
using MindAttic.Authentication.Data;
using MindAttic.Authentication.Entities;

namespace MindAttic.Authentication.Services;

public readonly record struct PasswordChangeResult(bool Ok, string? Error);

public interface IPasswordChangeService
{
    Task<PasswordChangeResult> ChangeAsync(Guid userId, string currentPassword, string newPassword, CancellationToken ct = default);
}

/// <summary>
/// Self-service password change: verify current password (constant-time) → policy check (HIBP + history)
/// → rehash → push old hash to history → rotate SecurityStamp (revokes other sessions on next revalidate).
/// </summary>
public sealed class PasswordChangeService(
    IUserStore users,
    IAuthDataContext db,
    IPasswordHasher hasher,
    IPasswordPolicy policy,
    IAuthAuditWriter audit,
    TimeProvider clock) : IPasswordChangeService
{
    public async Task<PasswordChangeResult> ChangeAsync(Guid userId, string currentPassword, string newPassword, CancellationToken ct = default)
    {
        var user = await users.FindByIdAsync(userId, ct);
        if (user is null || !user.IsActive) return new(false, "Password change failed.");

        if (!hasher.Verify(currentPassword, user.PasswordHash, user.PasswordPepperKeyId, user.LegacyHashScheme).Succeeded)
        {
            await audit.WriteAsync(new AuthAuditEntry(AuthEventType.ChangePassword, AuthOutcome.Failure, AuthReasonCode.BadPassword,
                user.Id, user.UserName), ct);
            return new(false, "Your current password is incorrect.");
        }

        var policyResult = await policy.ValidateAsync(newPassword, userId, ct);
        if (!policyResult.Ok) return new(false, policyResult.Reason);

        var now = clock.GetUtcNow().UtcDateTime;

        // Keep the old hash in history before overwriting (reuse prevention).
        db.AuthPasswordHistory.Add(new AuthPasswordHistory
        {
            UserId = user.Id, PasswordHash = user.PasswordHash, PepperKeyId = user.PasswordPepperKeyId, CreatedUtc = now,
        });

        var hash = hasher.Hash(newPassword);
        user.PasswordHash = hash.Phc;
        user.PasswordPepperKeyId = hash.PepperKeyId;
        user.LegacyHashScheme = null;
        user.PasswordUpdatedUtc = now;
        user.MustChangePassword = false;
        user.SecurityStamp = Guid.NewGuid().ToString("N");   // rotate → other sessions die on next revalidate

        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuthAuditEntry(AuthEventType.ChangePassword, AuthOutcome.Success, AuthReasonCode.Ok,
            user.Id, user.UserName), ct);
        return new(true, null);
    }
}
