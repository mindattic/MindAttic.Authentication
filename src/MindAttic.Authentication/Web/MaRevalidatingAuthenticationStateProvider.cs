using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MindAttic.Authentication.Data;
using MindAttic.Authentication.Options;
using MindAttic.Authentication.Services;

namespace MindAttic.Authentication.Web;

/// <summary>
/// Revalidates the Blazor Server circuit's principal every <see cref="AuthSessionOptions.RevalidationInterval"/>
/// (default 1 min): reloads the user and rejects if the account is gone/inactive, the SecurityStamp changed
/// (password/role/MFA/global-logout), or the session was revoked/expired — so a revoked admin loses a live
/// circuit within ≤ the interval.
/// </summary>
public sealed class MaRevalidatingAuthenticationStateProvider(
    ILoggerFactory loggerFactory,
    IServiceScopeFactory scopeFactory,
    IOptions<AuthSessionOptions> sessionOptions)
    : RevalidatingServerAuthenticationStateProvider(loggerFactory)
{
    protected override TimeSpan RevalidationInterval => sessionOptions.Value.RevalidationInterval;

    protected override async Task<bool> ValidateAuthenticationStateAsync(AuthenticationState authenticationState, CancellationToken cancellationToken)
    {
        var principal = authenticationState.User;
        if (principal.Identity?.IsAuthenticated != true) return false;

        var uid = principal.FindFirst(MaClaims.UserId)?.Value;
        var stamp = principal.FindFirst(MaClaims.SecurityStamp)?.Value;
        var sid = principal.FindFirst(MaClaims.SessionId)?.Value;
        if (!Guid.TryParse(uid, out var userId) || string.IsNullOrEmpty(stamp)) return false;

        using var scope = scopeFactory.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<IUserStore>();
        var user = await users.FindByIdAsync(userId, cancellationToken);
        if (user is null || !user.IsActive || !string.Equals(user.SecurityStamp, stamp, StringComparison.Ordinal))
            return false;

        if (Guid.TryParse(sid, out var sessionId))
        {
            var db = scope.ServiceProvider.GetRequiredService<IAuthDataContext>();
            var clock = scope.ServiceProvider.GetRequiredService<TimeProvider>();
            var session = await db.AuthSessions.AsNoTracking().FirstOrDefaultAsync(s => s.Id == sessionId, cancellationToken);
            if (session is null || session.RevokedUtc is not null || session.AbsoluteExpiryUtc <= clock.GetUtcNow().UtcDateTime)
                return false;
        }
        return true;
    }
}
