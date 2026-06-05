using Microsoft.EntityFrameworkCore;
using MindAttic.Authentication.Entities;

namespace MindAttic.Authentication.Data;

/// <summary>
/// The data seam the library's services operate over. A consuming app's <c>DbContext</c> implements this
/// (it already applies <c>ApplyMindAtticAuthConfiguration</c>), so the library never owns a DbContext or
/// connection string — the app keeps full control of those.
/// </summary>
public interface IAuthDataContext
{
    DbSet<AuthUser> AuthUsers { get; }
    DbSet<AuthUserMfa> AuthUserMfa { get; }
    DbSet<AuthRecoveryCode> AuthRecoveryCodes { get; }
    DbSet<AuthSession> AuthSessions { get; }
    DbSet<AuthLoginThrottle> AuthLoginThrottles { get; }
    DbSet<AuthAuditLog> AuthAuditLog { get; }
    DbSet<AuthPasswordHistory> AuthPasswordHistory { get; }
    DbSet<AuthPasswordResetToken> AuthPasswordResetTokens { get; }

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}
