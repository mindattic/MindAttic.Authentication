using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using MindAttic.Authentication.Data;
using MindAttic.Authentication.Internal;
using MindAttic.Authentication.Options;
using MaSvc = MindAttic.Authentication.Services;   // MindAttic's IAuthenticationService wins the bare name

namespace MindAttic.Authentication.Web;

/// <summary>
/// The HTTP endpoints that OWN sign-in (components never call SignInAsync). All POSTs validate
/// antiforgery and apply the uniform timing floor before responding.
/// </summary>
public static class AuthEndpoints
{
    public static IEndpointRouteBuilder MapMindAtticAuthEndpoints(
        this IEndpointRouteBuilder endpoints,
        Action<RouteGroupBuilder>? configureGroup = null)
    {
        var group = endpoints.MapGroup("/_ma-auth");
        configureGroup?.Invoke(group);
        group.MapPost("/login", LoginAsync);
        group.MapPost("/mfa-challenge", MfaChallengeAsync);
        group.MapPost("/logout", LogoutAsync);
        group.MapPost("/change-password", ChangePasswordAsync).RequireAuthorization();
        group.MapPost("/reset/request", ResetRequestAsync);
        group.MapPost("/reset/confirm", ResetConfirmAsync);
        return endpoints;
    }

    private static async Task<IResult> LoginAsync(
        HttpContext http, IAntiforgery antiforgery, MaSvc.IAuthenticationService auth,
        IOptions<AuthSessionOptions> sessionOptions, TimeProvider clock)
    {
        var start = Stopwatch.GetTimestamp();
        if (!await ValidateAntiforgeryAsync(http, antiforgery)) return Results.BadRequest();

        var form = await http.Request.ReadFormAsync(http.RequestAborted);
        var userName = form["userName"].ToString();
        var password = form["password"].ToString();
        var returnUrl = UrlSafety.LocalOrDefault(form["returnUrl"].ToString());
        var (ip, ua) = ClientInfo(http);

        var result = await auth.LoginAsync(userName, password, ip, ua, http.RequestAborted);
        await TimingFloor.EnforceAsync(start);

        switch (result.Status)
        {
            case MaSvc.LoginStatus.Success:
                await SignInCookieAsync(http, result, sessionOptions.Value, clock);
                return Results.Redirect(returnUrl);
            case MaSvc.LoginStatus.MfaRequired:
                await SignInMfaPendingAsync(http, result.UserId!.Value, clock);
                return Results.Redirect(WithReturn("/mfa", returnUrl));
            default:
                return Results.Redirect(WithReturn("/login?error=1", returnUrl, '&'));
        }
    }

    private static async Task<IResult> MfaChallengeAsync(
        HttpContext http, IAntiforgery antiforgery, MaSvc.IAuthenticationService auth,
        IOptions<AuthSessionOptions> sessionOptions, TimeProvider clock)
    {
        var start = Stopwatch.GetTimestamp();
        if (!await ValidateAntiforgeryAsync(http, antiforgery)) return Results.BadRequest();

        var pending = await http.AuthenticateAsync(MaSchemes.MfaPending);
        var form = await http.Request.ReadFormAsync(http.RequestAborted);
        var code = form["code"].ToString();
        var isRecovery = form["recovery"].ToString() is "true" or "on";
        var returnUrl = UrlSafety.LocalOrDefault(form["returnUrl"].ToString());
        var (ip, ua) = ClientInfo(http);

        if (!pending.Succeeded || !Guid.TryParse(pending.Principal?.FindFirst(MaClaims.UserId)?.Value, out var uid))
        {
            await TimingFloor.EnforceAsync(start);
            return Results.Redirect("/login?error=1");
        }

        var result = await auth.ConfirmMfaAsync(uid, code, isRecovery, ip, ua, http.RequestAborted);
        await TimingFloor.EnforceAsync(start);

        if (result.Status == MaSvc.LoginStatus.Success)
        {
            await http.SignOutAsync(MaSchemes.MfaPending);
            await SignInCookieAsync(http, result, sessionOptions.Value, clock);
            return Results.Redirect(returnUrl);
        }
        return Results.Redirect(WithReturn("/mfa?error=1", returnUrl, '&'));
    }

    private static async Task<IResult> LogoutAsync(
        HttpContext http, IAntiforgery antiforgery, IAuthDataContext db, TimeProvider clock)
    {
        if (!await ValidateAntiforgeryAsync(http, antiforgery)) return Results.BadRequest();

        if (Guid.TryParse(http.User.FindFirst(MaClaims.SessionId)?.Value, out var sessionId))
        {
            var session = await db.AuthSessions.FirstOrDefaultAsync(s => s.Id == sessionId, http.RequestAborted);
            if (session is { RevokedUtc: null })
            {
                session.RevokedUtc = clock.GetUtcNow().UtcDateTime;
                session.RevokedReason = "logout";
                await db.SaveChangesAsync(http.RequestAborted);
            }
        }
        await http.SignOutAsync(MaSchemes.Cookie);
        return Results.Redirect("/");
    }

    private static async Task<IResult> ChangePasswordAsync(
        HttpContext http, IAntiforgery antiforgery, MaSvc.IPasswordChangeService changer)
    {
        if (!await ValidateAntiforgeryAsync(http, antiforgery)) return Results.BadRequest();
        if (!Guid.TryParse(http.User.FindFirst(MaClaims.UserId)?.Value, out var uid))
            return Results.Redirect("/login");

        var form = await http.Request.ReadFormAsync(http.RequestAborted);
        var current = form["currentPassword"].ToString();
        var next = form["newPassword"].ToString();
        var result = await changer.ChangeAsync(uid, current, next, http.RequestAborted);
        return Results.Redirect(result.Ok ? "/account?changed=1" : "/account/change-password?error=1");
    }

    private static async Task<IResult> ResetRequestAsync(
        HttpContext http, IAntiforgery antiforgery, MaSvc.IPasswordResetService reset)
    {
        var start = Stopwatch.GetTimestamp();
        if (!await ValidateAntiforgeryAsync(http, antiforgery)) return Results.BadRequest();
        var form = await http.Request.ReadFormAsync(http.RequestAborted);
        var (ip, ua) = ClientInfo(http);
        await reset.RequestAsync(form["userNameOrEmail"].ToString(), ip, ua, http.RequestAborted);
        await TimingFloor.EnforceAsync(start);          // uniform timing — never reveal account existence
        return Results.Redirect("/login?reset=sent");
    }

    private static async Task<IResult> ResetConfirmAsync(
        HttpContext http, IAntiforgery antiforgery, MaSvc.IPasswordResetService reset)
    {
        if (!await ValidateAntiforgeryAsync(http, antiforgery)) return Results.BadRequest();
        var form = await http.Request.ReadFormAsync(http.RequestAborted);
        var token = form["token"].ToString();
        var result = await reset.ConfirmAsync(token, form["newPassword"].ToString(), http.RequestAborted);
        return Results.Redirect(result.Ok
            ? "/login?reset=ok"
            : $"/account/reset?error=1&token={Uri.EscapeDataString(token)}");
    }

    private static async Task<bool> ValidateAntiforgeryAsync(HttpContext http, IAntiforgery antiforgery)
    {
        try { await antiforgery.ValidateRequestAsync(http); return true; }
        catch (AntiforgeryValidationException) { return false; }
    }

    private static (string ip, string ua) ClientInfo(HttpContext http) =>
        (http.Connection.RemoteIpAddress?.ToString() ?? "", http.Request.Headers.UserAgent.ToString());

    private static async Task SignInCookieAsync(HttpContext http, MaSvc.LoginResult result, AuthSessionOptions session, TimeProvider clock)
    {
        var now = clock.GetUtcNow();
        var identity = new ClaimsIdentity(result.Claims!, MaSchemes.Cookie);
        // App claims (e.g. Ideas AuthorRawMarkup) baked in once, here, before the ticket is issued.
        foreach (var augmentor in http.RequestServices.GetServices<IMaClaimsAugmentor>())
            await augmentor.AugmentAsync(identity, http.RequestServices, http.RequestAborted);
        var principal = new ClaimsPrincipal(identity);
        var props = new AuthenticationProperties { IsPersistent = false, ExpiresUtc = now + session.AbsoluteTimeout };
        props.Items["la"] = now.ToString("O");
        props.Items["sc"] = now.ToString("O");
        await http.SignInAsync(MaSchemes.Cookie, principal, props);
    }

    private static async Task SignInMfaPendingAsync(HttpContext http, Guid userId, TimeProvider clock)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim(MaClaims.UserId, userId.ToString())], MaSchemes.MfaPending));
        var props = new AuthenticationProperties { IsPersistent = false, ExpiresUtc = clock.GetUtcNow().AddMinutes(5) };
        await http.SignInAsync(MaSchemes.MfaPending, principal, props);
    }

    private static string WithReturn(string path, string returnUrl, char sep = '?') =>
        returnUrl == "/" ? path : $"{path}{sep}returnUrl={Uri.EscapeDataString(returnUrl)}";
}
