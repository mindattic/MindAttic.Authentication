using System.Text;
using Microsoft.EntityFrameworkCore;
using MindAttic.Authentication.Data;
using MindAttic.Authentication.Entities;

namespace MindAttic.Authentication.Services;

public interface IUserStore
{
    Task<AuthUser?> FindByUserNameAsync(string userName, CancellationToken ct = default);
    Task<AuthUser?> FindByIdAsync(Guid id, CancellationToken ct = default);
    Task<AuthUserMfa?> FindMfaAsync(Guid userId, CancellationToken ct = default);
    Task<bool> AnyUsersAsync(CancellationToken ct = default);
    Task SaveChangesAsync(CancellationToken ct = default);

    /// <summary>Apply a transparently-upgraded password hash (rehash-on-login). Does NOT rotate the stamp.</summary>
    void ApplyRehash(AuthUser user, string phc, string pepperKeyId);
    /// <summary>Stamp a successful login.</summary>
    void RecordLogin(AuthUser user, DateTime utcNow);

    static string Normalize(string userName) => (userName ?? "").Normalize(NormalizationForm.FormKC).Trim().ToUpperInvariant();
}

/// <summary>EF-backed user lookup/update over the app's <see cref="IAuthDataContext"/>.</summary>
public sealed class UserStore(IAuthDataContext db) : IUserStore
{
    public Task<AuthUser?> FindByUserNameAsync(string userName, CancellationToken ct = default)
    {
        var normalized = IUserStore.Normalize(userName);
        return db.AuthUsers.FirstOrDefaultAsync(u => u.NormalizedUserName == normalized, ct);
    }

    public Task<AuthUser?> FindByIdAsync(Guid id, CancellationToken ct = default) =>
        db.AuthUsers.FirstOrDefaultAsync(u => u.Id == id, ct);

    public Task<AuthUserMfa?> FindMfaAsync(Guid userId, CancellationToken ct = default) =>
        db.AuthUserMfa.FirstOrDefaultAsync(m => m.UserId == userId, ct);

    public Task<bool> AnyUsersAsync(CancellationToken ct = default) => db.AuthUsers.AnyAsync(ct);

    public Task SaveChangesAsync(CancellationToken ct = default) => db.SaveChangesAsync(ct);

    public void ApplyRehash(AuthUser user, string phc, string pepperKeyId)
    {
        user.PasswordHash = phc;
        user.PasswordPepperKeyId = pepperKeyId;
        user.LegacyHashScheme = null;
    }

    public void RecordLogin(AuthUser user, DateTime utcNow) => user.LastLoginUtc = utcNow;
}
