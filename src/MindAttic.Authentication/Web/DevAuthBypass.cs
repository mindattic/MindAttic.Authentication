// =============================================================================
//  DEV-ONLY AUTH BYPASS  —  COMPILED OUT OF RELEASE BUILDS ENTIRELY.
//
//  Every line in this file is wrapped in `#if MA_DEV_AUTH`. That symbol is
//  defined ONLY in the Debug configuration (see MindAttic.Authentication.csproj).
//  A Release pack of this library therefore contains NONE of this code — not the
//  middleware, not the options type, not even the dormant branches. There is
//  nothing to disable in production because there is nothing there.
//
//  On top of that compile-time guarantee, the middleware is gated at RUNTIME by
//  THREE independent conditions, ALL required:
//      1. an explicit Enabled flag from the app's .env       (off unless opted in)
//      2. IHostEnvironment.IsDevelopment()                   (env)
//      3. the request arrives on a loopback address          (localhost only)
//
//  It performs NO privileged shortcut: it simply replays the operator's stored
//  dev credentials through the normal IAuthenticationService.LoginAsync — the
//  exact same path the /login form uses. If the credentials are wrong, nothing
//  happens. It never fabricates an identity out of thin air.
// =============================================================================
#if MA_DEV_AUTH
using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MindAttic.Authentication.Options;
using MaSvc = MindAttic.Authentication.Services;

namespace MindAttic.Authentication.Web;

/// <summary>Dev-bypass knobs, populated from the app's <c>.env</c> file. Dev-only.</summary>
public sealed class DevAuthBypassOptions
{
    public bool Enabled { get; set; }
    public string UserName { get; set; } = "admin";
    public string Password { get; set; } = "";
}

/// <summary>
/// Wires the dev-only auto-login. Both methods are invoked automatically from the
/// library's own <c>AddMindAtticAuthentication</c> / <c>UseMindAtticAuthentication</c>,
/// so a consuming app needs ZERO code — it only drops a <c>.env</c> in its content
/// root. Present only in Debug-built packages (<c>MA_DEV_AUTH</c>).
/// </summary>
public static class DevAuthBypass
{
    /// <summary>Reads <c>.env</c> from the content root and registers <see cref="DevAuthBypassOptions"/>.</summary>
    public static IServiceCollection AddDevAuthBypass(this IServiceCollection services)
    {
        var env = ReadDotEnv(Path.Combine(Directory.GetCurrentDirectory(), ".env"));
        services.Configure<DevAuthBypassOptions>(o =>
        {
            o.Enabled  = ParseBool(env.GetValueOrDefault("MA_DEV_AUTH_ENABLED"));
            o.UserName = env.GetValueOrDefault("MA_DEV_AUTH_USERNAME") is { Length: > 0 } u ? u : "admin";
            o.Password = env.GetValueOrDefault("MA_DEV_AUTH_PASSWORD") ?? "";
        });
        return services;
    }

    /// <summary>
    /// Auto-signs-in the configured dev user on a loopback request in Development,
    /// by replaying the stored credentials through the real login path. No-op unless
    /// all three gates pass. Insert AFTER UseAuthentication and BEFORE any forced-step.
    /// </summary>
    public static IApplicationBuilder UseDevAuthBypass(this IApplicationBuilder app)
    {
        // Gate (env): only ever active under the Development environment.
        var hostEnv = app.ApplicationServices.GetRequiredService<IHostEnvironment>();
        if (!hostEnv.IsDevelopment()) return app;

        app.Use(async (ctx, next) =>
        {
            var opts = ctx.RequestServices.GetRequiredService<IOptions<DevAuthBypassOptions>>().Value;

            // Gate (flag) + (localhost) + only when anonymous, on a GET, off the auth/framework surface.
            var loopback = ctx.Connection.RemoteIpAddress is { } ip && IPAddress.IsLoopback(ip);
            var anonymous = ctx.User?.Identity?.IsAuthenticated != true;
            if (opts.Enabled && loopback && anonymous
                && HttpMethods.IsGet(ctx.Request.Method)
                && !IsBypassExcludedPath(ctx.Request.Path))
            {
                var log  = ctx.RequestServices.GetService<ILoggerFactory>()?.CreateLogger("MindAttic.DevAuthBypass");
                var auth = ctx.RequestServices.GetRequiredService<MaSvc.IAuthenticationService>();

                var result = await auth.LoginAsync(opts.UserName, opts.Password, "127.0.0.1", "dev-auth-bypass", ctx.RequestAborted);
                if (result.Status == MaSvc.LoginStatus.Success && result.Claims is not null)
                {
                    // Dev frictionless: drop the must-change-password / must-enroll-mfa gates and assert mfa
                    // so the forced-step middleware lets us straight through. Localhost-dev only.
                    var claims = result.Claims
                        .Where(c => c.Type != MaClaims.MustChangePassword && c.Type != MaClaims.MustEnrollMfa)
                        .ToList();
                    if (!claims.Any(c => c.Type == MaClaims.Amr && c.Value == "mfa"))
                        claims.Add(new Claim(MaClaims.Amr, "mfa"));

                    var identity = new ClaimsIdentity(claims, MaSchemes.Cookie);
                    foreach (var augmentor in ctx.RequestServices.GetServices<IMaClaimsAugmentor>())
                        await augmentor.AugmentAsync(identity, ctx.RequestServices, ctx.RequestAborted);

                    // Mirror AuthEndpoints.SignInCookieAsync so CookieValidation is happy.
                    var session = ctx.RequestServices.GetRequiredService<IOptions<AuthSessionOptions>>().Value;
                    var clock   = ctx.RequestServices.GetRequiredService<TimeProvider>();
                    var now     = clock.GetUtcNow();
                    var props   = new AuthenticationProperties { IsPersistent = false, ExpiresUtc = now + session.AbsoluteTimeout };
                    props.Items["la"] = now.ToString("O");
                    props.Items["sc"] = now.ToString("O");

                    await ctx.SignInAsync(MaSchemes.Cookie, new ClaimsPrincipal(identity), props);
                    log?.LogWarning("[MA-DEV-AUTH-BYPASS] Auto-signed-in '{User}' on loopback (Development). " +
                                    "This code is compiled out of release builds.", opts.UserName);
                    // Redirect to self so the freshly-set cookie is in play on the next pass.
                    ctx.Response.Redirect(ctx.Request.GetEncodedPathAndQuery());
                    return;
                }

                log?.LogWarning("[MA-DEV-AUTH-BYPASS] Enabled but login did not succeed (status {Status}) for '{User}' — " +
                                "check MA_DEV_AUTH_USERNAME / MA_DEV_AUTH_PASSWORD in .env.", result.Status, opts.UserName);
            }

            await next();
        });
        return app;
    }

    private static bool IsBypassExcludedPath(PathString path) =>
        path.StartsWithSegments("/_ma-auth") || path.StartsWithSegments("/login")
        || path.StartsWithSegments("/mfa") || path.StartsWithSegments("/account")
        || path.StartsWithSegments("/_framework") || path.StartsWithSegments("/_blazor")
        || path.StartsWithSegments("/_content") || (path.Value?.Contains('.') ?? false);

    private static bool ParseBool(string? v) =>
        v is not null && (v.Equals("true", StringComparison.OrdinalIgnoreCase) || v == "1" || v.Equals("yes", StringComparison.OrdinalIgnoreCase));

    /// <summary>Minimal .env reader: KEY=VALUE per line, '#' comments, optional surrounding quotes. Missing file → empty.</summary>
    private static Dictionary<string, string> ReadDotEnv(string path)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!File.Exists(path)) return map;
        foreach (var raw in File.ReadAllLines(path))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            var eq = line.IndexOf('=');
            if (eq <= 0) continue;
            var key = line[..eq].Trim();
            var val = line[(eq + 1)..].Trim().Trim('"', '\'');
            map[key] = val;
        }
        return map;
    }
}
#endif
