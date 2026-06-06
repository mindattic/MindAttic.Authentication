using Microsoft.EntityFrameworkCore;
using MindAttic.Authentication.Crypto;
using MindAttic.Authentication.Data;
using MindAttic.Authentication.Entities;

namespace MindAttic.Authentication.Services;

/// <summary>A user as shown in an admin list (never exposes the password hash).</summary>
public sealed record AuthUserSummary(
    Guid Id, string UserName, string? Email, string Role, bool IsActive, bool MfaEnabled,
    bool MustChangePassword, DateTime? LastLoginUtc, DateTime CreatedUtc);

public sealed record CreateUserResult(bool Ok, Guid? UserId, string? Error);
public sealed record AdminActionResult(bool Ok, string? Error)
{
    public static readonly AdminActionResult Success = new(true, null);
    public static AdminActionResult Fail(string error) => new(false, error);
}

/// <summary>
/// Administrative user management over the canonical <see cref="AuthUser"/> table — the capability the
/// library's authentication side doesn't cover. Lets each app's admin UI create/list users, change roles,
/// (de)activate, update profiles, and operator-reset passwords WITHOUT a second user store. Role and
/// active-state changes rotate the SecurityStamp (so affected sessions revalidate within ~1 min), and a
/// guard prevents removing the last active Admin.
/// </summary>
public interface IUserAdminService
{
    Task<IReadOnlyList<AuthUserSummary>> ListAsync(CancellationToken ct = default);
    Task<AuthUserSummary?> GetAsync(Guid id, CancellationToken ct = default);
    Task<int> CountAsync(CancellationToken ct = default);
    Task<CreateUserResult> CreateAsync(string userName, string? email, string role, string password, bool mustChangePassword = true, CancellationToken ct = default);
    Task<AdminActionResult> SetRoleAsync(Guid id, string role, CancellationToken ct = default);
    Task<AdminActionResult> SetActiveAsync(Guid id, bool active, CancellationToken ct = default);
    Task<AdminActionResult> UpdateProfileAsync(Guid id, string? email, CancellationToken ct = default);
    /// <summary>Operator reset (e.g. lost MFA / forgotten password). Rotates the stamp; forces change by default.</summary>
    Task<AdminActionResult> ResetPasswordAsync(Guid id, string newPassword, bool requireChange = true, CancellationToken ct = default);
}

public sealed class UserAdminService(
    IAuthDataContext db, IPasswordHasher hasher, IPasswordPolicy policy, IAuthAuditWriter audit, TimeProvider clock)
    : IUserAdminService
{
    public async Task<IReadOnlyList<AuthUserSummary>> ListAsync(CancellationToken ct = default) =>
        await db.AuthUsers.AsNoTracking().OrderBy(u => u.UserName).Select(Project).ToListAsync(ct);

    public async Task<AuthUserSummary?> GetAsync(Guid id, CancellationToken ct = default) =>
        await db.AuthUsers.AsNoTracking().Where(u => u.Id == id).Select(Project).FirstOrDefaultAsync(ct);

    public Task<int> CountAsync(CancellationToken ct = default) => db.AuthUsers.CountAsync(ct);

    public async Task<CreateUserResult> CreateAsync(string userName, string? email, string role, string password, bool mustChangePassword = true, CancellationToken ct = default)
    {
        var normalized = IUserStore.Normalize(userName);
        if (string.IsNullOrWhiteSpace(normalized)) return new(false, null, "Username is required.");
        if (await db.AuthUsers.AnyAsync(u => u.NormalizedUserName == normalized, ct))
            return new(false, null, "A user with that name already exists.");

        var policyResult = await policy.ValidateAsync(password, null, ct);
        if (!policyResult.Ok) return new(false, null, policyResult.Reason);

        var hash = hasher.Hash(password);
        var now = clock.GetUtcNow().UtcDateTime;
        var user = new AuthUser
        {
            UserName = userName, NormalizedUserName = normalized,
            Email = email, NormalizedEmail = NormalizeEmail(email), EmailVerified = false,
            PasswordHash = hash.Phc, PasswordPepperKeyId = hash.PepperKeyId, PasswordUpdatedUtc = now,
            Role = role, MustChangePassword = mustChangePassword, IsActive = true, CreatedUtc = now,
        };
        db.AuthUsers.Add(user);
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuthAuditEntry(AuthEventType.Register, AuthOutcome.Success, AuthReasonCode.Ok, user.Id, userName), ct);
        return new(true, user.Id, null);
    }

    public async Task<AdminActionResult> SetRoleAsync(Guid id, string role, CancellationToken ct = default)
    {
        var user = await db.AuthUsers.FirstOrDefaultAsync(u => u.Id == id, ct);
        if (user is null) return AdminActionResult.Fail("User not found.");
        if (IsDemotingLastAdmin(user, role) || await WouldRemoveLastAdminAsync(user, role, user.IsActive, ct))
            return AdminActionResult.Fail("Can't remove the last active administrator.");
        user.Role = role;
        Rotate(user);
        await db.SaveChangesAsync(ct);
        return AdminActionResult.Success;
    }

    public async Task<AdminActionResult> SetActiveAsync(Guid id, bool active, CancellationToken ct = default)
    {
        var user = await db.AuthUsers.FirstOrDefaultAsync(u => u.Id == id, ct);
        if (user is null) return AdminActionResult.Fail("User not found.");
        if (!active && await WouldRemoveLastAdminAsync(user, user.Role, active: false, ct))
            return AdminActionResult.Fail("Can't deactivate the last active administrator.");
        user.IsActive = active;
        Rotate(user);   // active=false kills sessions on next revalidate
        await db.SaveChangesAsync(ct);
        return AdminActionResult.Success;
    }

    public async Task<AdminActionResult> UpdateProfileAsync(Guid id, string? email, CancellationToken ct = default)
    {
        var user = await db.AuthUsers.FirstOrDefaultAsync(u => u.Id == id, ct);
        if (user is null) return AdminActionResult.Fail("User not found.");
        user.Email = email;
        user.NormalizedEmail = NormalizeEmail(email);
        await db.SaveChangesAsync(ct);
        return AdminActionResult.Success;
    }

    public async Task<AdminActionResult> ResetPasswordAsync(Guid id, string newPassword, bool requireChange = true, CancellationToken ct = default)
    {
        var user = await db.AuthUsers.FirstOrDefaultAsync(u => u.Id == id, ct);
        if (user is null) return AdminActionResult.Fail("User not found.");
        var policyResult = await policy.ValidateAsync(newPassword, id, ct);
        if (!policyResult.Ok) return AdminActionResult.Fail(policyResult.Reason ?? "Password rejected.");

        var now = clock.GetUtcNow().UtcDateTime;
        db.AuthPasswordHistory.Add(new AuthPasswordHistory { UserId = user.Id, PasswordHash = user.PasswordHash, PepperKeyId = user.PasswordPepperKeyId, CreatedUtc = now });
        var hash = hasher.Hash(newPassword);
        user.PasswordHash = hash.Phc; user.PasswordPepperKeyId = hash.PepperKeyId; user.LegacyHashScheme = null;
        user.PasswordUpdatedUtc = now; user.MustChangePassword = requireChange;
        Rotate(user);
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuthAuditEntry(AuthEventType.ChangePassword, AuthOutcome.Success, AuthReasonCode.Ok, user.Id, user.UserName), ct);
        return AdminActionResult.Success;
    }

    private void Rotate(AuthUser u) => u.SecurityStamp = Guid.NewGuid().ToString("N");

    private static bool IsDemotingLastAdmin(AuthUser user, string newRole) =>
        false; // handled by WouldRemoveLastAdminAsync; kept for readability of intent

    private async Task<bool> WouldRemoveLastAdminAsync(AuthUser user, string newRole, bool active, CancellationToken ct)
    {
        var wasAdmin = string.Equals(user.Role, MaRoles.Admin, StringComparison.Ordinal) && user.IsActive;
        var staysAdmin = string.Equals(newRole, MaRoles.Admin, StringComparison.Ordinal) && active;
        if (!wasAdmin || staysAdmin) return false;
        var otherActiveAdmins = await db.AuthUsers.CountAsync(
            u => u.Id != user.Id && u.IsActive && u.Role == MaRoles.Admin, ct);
        return otherActiveAdmins == 0;
    }

    private static string? NormalizeEmail(string? email) =>
        string.IsNullOrWhiteSpace(email) ? null : email.Trim().ToUpperInvariant();

    private static readonly System.Linq.Expressions.Expression<Func<AuthUser, AuthUserSummary>> Project =
        u => new AuthUserSummary(u.Id, u.UserName, u.Email, u.Role, u.IsActive, u.MfaEnabled, u.MustChangePassword, u.LastLoginUtc, u.CreatedUtc);
}
