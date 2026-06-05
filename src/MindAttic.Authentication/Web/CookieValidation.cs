using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using MindAttic.Authentication.Options;
using MindAttic.Authentication.Services;

namespace MindAttic.Authentication.Web;

/// <summary>
/// Cookie <c>OnValidatePrincipal</c>: enforces the idle timeout and re-checks the SecurityStamp on the
/// HTTP path (throttled to the revalidation interval). A revoked/disabled user or rotated stamp is
/// rejected and signed out. Complements the per-circuit revalidation for Blazor Server.
/// </summary>
internal static class CookieValidation
{
    public static async Task ValidateAsync(CookieValidatePrincipalContext ctx)
    {
        var uid = ctx.Principal?.FindFirst(MaClaims.UserId)?.Value;
        var stamp = ctx.Principal?.FindFirst(MaClaims.SecurityStamp)?.Value;
        if (!Guid.TryParse(uid, out var userId) || string.IsNullOrEmpty(stamp))
        {
            ctx.RejectPrincipal();
            return;
        }

        var sp = ctx.HttpContext.RequestServices;
        var clock = sp.GetRequiredService<TimeProvider>();
        var session = sp.GetRequiredService<IOptions<AuthSessionOptions>>().Value;
        var now = clock.GetUtcNow();

        // Idle timeout.
        if (ctx.Properties.Items.TryGetValue("la", out var laStr)
            && DateTimeOffset.TryParse(laStr, out var lastActivity)
            && now - lastActivity > session.IdleTimeout)
        {
            ctx.RejectPrincipal();
            await ctx.HttpContext.SignOutAsync(MaSchemes.Cookie);
            return;
        }

        // SecurityStamp recheck, throttled to the revalidation interval.
        var needsRecheck = !(ctx.Properties.Items.TryGetValue("sc", out var scStr)
                             && DateTimeOffset.TryParse(scStr, out var lastCheck)
                             && now - lastCheck < session.RevalidationInterval);
        if (needsRecheck)
        {
            using var scope = sp.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<IUserStore>();
            var user = await users.FindByIdAsync(userId, ctx.HttpContext.RequestAborted);
            if (user is null || !user.IsActive || !string.Equals(user.SecurityStamp, stamp, StringComparison.Ordinal))
            {
                ctx.RejectPrincipal();
                await ctx.HttpContext.SignOutAsync(MaSchemes.Cookie);
                return;
            }
            ctx.Properties.Items["sc"] = now.ToString("O");
        }

        ctx.Properties.Items["la"] = now.ToString("O");
        ctx.ShouldRenew = true;
    }
}
