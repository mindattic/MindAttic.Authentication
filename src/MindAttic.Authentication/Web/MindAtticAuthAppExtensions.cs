using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using MindAttic.Authentication.Options;

namespace MindAttic.Authentication.Web;

public static class MindAtticAuthAppExtensions
{
    /// <summary>Key under which the per-request CSP nonce is stashed for the auth components.</summary>
    public const string CspNonceItem = "ma-csp-nonce";

    /// <summary>
    /// Wires the auth middleware in the correct order (authentication → authorization) and applies a
    /// strict per-request CSP nonce ONLY to the auth surface (/login, /mfa, /account, /_ma-auth) — so it
    /// never clobbers a host app's own pages (e.g. MindAttic.Ideas' trusted inline-JS author pages).
    /// Call AFTER UseForwardedHeaders and BEFORE mapping component/endpoint routes.
    /// </summary>
    public static IApplicationBuilder UseMindAtticAuthentication(this IApplicationBuilder app)
    {
        app.UseAuthentication();

#if MA_DEV_AUTH
        // DEV ONLY (Debug-built packages only; compiled out of Release). Auto-signs-in
        // the .env dev user on a loopback request in Development — gated again at runtime
        // by Enabled + IsDevelopment + loopback. MUST run AFTER authentication and BEFORE
        // authorization, so the signed-in principal is in place when an [Authorize]
        // endpoint is evaluated (otherwise UseAuthorization challenges first and redirects
        // to /login before the bypass ever runs).
        app.UseDevAuthBypass();
#endif

        app.UseAuthorization();

        // Forced-step: an authenticated user who must enroll MFA (or is an Admin without amr=mfa) or must
        // change their password is funneled to the right page before reaching anything else. Reads claims
        // baked at sign-in (no DB hit). Excludes the auth surface + framework/static paths.
        app.Use(async (ctx, next) =>
        {
            var u = ctx.User;
            if (u.Identity?.IsAuthenticated == true && !IsExcludedFromForcedStep(ctx.Request.Path))
            {
                var mfaRequired = ctx.RequestServices.GetRequiredService<IOptions<MfaOptions>>().Value.RequireForAdmin;
                var mustEnrollMfa = mfaRequired
                    && (u.HasClaim(MaClaims.MustEnrollMfa, "1")
                        || (u.IsInRole(MaRoles.Admin) && !u.HasClaim(MaClaims.Amr, "mfa")));
                if (mustEnrollMfa) { ctx.Response.Redirect("/account/mfa/setup"); return; }
                if (u.HasClaim(MaClaims.MustChangePassword, "1")) { ctx.Response.Redirect("/account/change-password"); return; }
            }
            await next();
        });

        app.Use(async (ctx, next) =>
        {
            if (IsAuthSurface(ctx.Request.Path))
            {
                var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
                ctx.Items[CspNonceItem] = nonce;
                ctx.Response.Headers["Content-Security-Policy"] =
                    $"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'nonce-{nonce}'; " +
                    "object-src 'none'; base-uri 'self'; frame-ancestors 'none'";
            }
            await next();
        });

        return app;
    }

    private static bool IsExcludedFromForcedStep(PathString path) =>
        path.StartsWithSegments("/_ma-auth") || path.StartsWithSegments("/login")
        || path.StartsWithSegments("/mfa") || path.StartsWithSegments("/account")
        || path.StartsWithSegments("/_framework") || path.StartsWithSegments("/_blazor")
        || path.StartsWithSegments("/_content") || (path.Value?.Contains('.') ?? false);

    private static bool IsAuthSurface(PathString path) =>
        path.StartsWithSegments("/login") || path.StartsWithSegments("/mfa")
        || path.StartsWithSegments("/account") || path.StartsWithSegments("/_ma-auth");
}
