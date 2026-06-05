using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using MindAttic.Authentication.Crypto;
using MindAttic.Authentication.Data;
using MindAttic.Authentication.Options;
using MindAttic.Authentication.Secrets;
using MindAttic.Authentication.Services;

namespace MindAttic.Authentication.Web;

/// <summary>Host-supplied wiring knobs for <see cref="MindAtticAuthExtensions.AddMindAtticAuthentication{TContext}"/>.</summary>
public sealed class MindAtticAuthOptions
{
    /// <summary>Per-app trust boundary: scopes the Data Protection app name so a cookie can't cross apps.</summary>
    public string AppName { get; set; } = "App";
    /// <summary>Extra app policies (never redefine the canonical ones).</summary>
    public Action<AuthorizationBuilder>? ConfigureAdditionalPolicies { get; set; }
    /// <summary>PROD persistence + at-rest protection of the DP key ring (Azure Blob + Key Vault). Required in prod.</summary>
    public Action<IDataProtectionBuilder>? ConfigureDataProtection { get; set; }
    /// <summary>Dev-only key-ring directory. Default %APPDATA%\MindAttic\DataProtection\{AppName}.</summary>
    public string? DevKeyRingPath { get; set; }
    /// <summary>True in production → fail-closed if <see cref="ConfigureDataProtection"/> wasn't supplied.</summary>
    public bool IsProduction { get; set; }
}

public static class MindAtticAuthExtensions
{
    /// <summary>
    /// Registers the full MindAttic.Authentication stack over the app's <typeparamref name="TContext"/>
    /// (which implements <see cref="IAuthDataContext"/>). Secure-by-default: options are floor-validated
    /// at startup (fail-closed), the cookie is <c>__Host-</c> prefixed, and Admin requires MFA.
    /// </summary>
    public static IServiceCollection AddMindAtticAuthentication<TContext>(
        this IServiceCollection services, IConfiguration config, Action<MindAtticAuthOptions> configure)
        where TContext : DbContext, IAuthDataContext
    {
        var o = new MindAtticAuthOptions();
        configure(o);
        services.AddSingleton(o);

        // The app's DbContext is the auth data seam.
        services.AddScoped<IAuthDataContext>(sp => sp.GetRequiredService<TContext>());

        // Options (non-secret) — floor-validated at startup, fail-closed.
        services.AddOptions<AuthCryptoOptions>().Bind(config.GetSection("MindAttic:Auth:Crypto"))
            .Validate(c => { c.ValidateOrThrow(); return true; }, "Invalid AuthCryptoOptions").ValidateOnStart();
        services.AddOptions<AuthPolicyOptions>().Bind(config.GetSection("MindAttic:Auth:Policy"));
        services.AddOptions<MfaOptions>().Bind(config.GetSection("MindAttic:Auth:Mfa"));
        services.AddOptions<AuthSessionOptions>().Bind(config.GetSection("MindAttic:Auth:Session"));
        services.AddOptions<AuthResetOptions>().Bind(config.GetSection("MindAttic:Auth:Reset"));
        var session = config.GetSection("MindAttic:Auth:Session").Get<AuthSessionOptions>() ?? new AuthSessionOptions();
        var mfaOptions = config.GetSection("MindAttic:Auth:Mfa").Get<MfaOptions>() ?? new MfaOptions();

        services.TryAddSingleton(TimeProvider.System);

        // Crypto + secrets (fail-closed; hasher precomputes a decoy at construction).
        services.TryAddSingleton<IAuthSecrets, ConfigAuthSecrets>();
        services.TryAddSingleton<IPasswordHasher, Argon2idPasswordHasher>();
        services.TryAddSingleton<ITotpService, TotpService>();
        services.TryAddSingleton<IAuthAuditWriter, AuthAuditWriter>();
        // Dev/fallback email sender; a Windows host overrides this with a MindAttic.Psst adapter.
        services.TryAddSingleton<IAuthEmailSender, LoggingAuthEmailSender>();

        // Per-request services.
        services.AddScoped<IUserStore, UserStore>();
        services.AddScoped<IAccountLockoutService, AccountLockoutService>();
        services.AddScoped<IPasswordPolicy, PasswordPolicy>();
        services.AddScoped<IAuthenticationService, AuthenticationService>();
        services.AddScoped<IMfaEnrollmentService, MfaEnrollmentService>();
        services.AddScoped<IPasswordChangeService, PasswordChangeService>();
        services.AddScoped<IPasswordResetService, PasswordResetService>();
        services.AddScoped<AuthBootstrapper>();

        services.AddHttpClient(AuthPolicyOptions.HibpHttpClient, c =>
        {
            c.DefaultRequestHeaders.UserAgent.ParseAdd("MindAttic.Authentication");
            c.Timeout = TimeSpan.FromSeconds(10);
        });

        services.AddHttpContextAccessor();

        // Data Protection — per-app isolated key ring. Dev → file system; prod → host-supplied (Blob+KV),
        // fail-closed if absent so cookies are never protected with an ephemeral in-memory key.
        var dp = services.AddDataProtection()
            .SetApplicationName($"MindAttic.Auth:{o.AppName}")
            .SetDefaultKeyLifetime(TimeSpan.FromDays(90));
        if (o.IsProduction)
        {
            if (o.ConfigureDataProtection is null)
                throw new InvalidOperationException(
                    "MindAttic.Authentication: in production you must supply ConfigureDataProtection " +
                    "(persist + protect the Data Protection key ring via Azure Blob + Key Vault). Fail-closed.");
            o.ConfigureDataProtection(dp);
        }
        else
        {
            var path = o.DevKeyRingPath ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "MindAttic", "DataProtection", o.AppName);
            Directory.CreateDirectory(path);
            dp.PersistKeysToFileSystem(new DirectoryInfo(path));
            o.ConfigureDataProtection?.Invoke(dp);
        }

        // Cookie schemes.
        services.AddAuthentication(MaSchemes.Cookie)
            .AddCookie(MaSchemes.Cookie, c =>
            {
                c.Cookie.Name = "__Host-MindAttic.Auth";
                c.Cookie.HttpOnly = true;
                c.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                c.Cookie.SameSite = SameSiteMode.Lax;
                c.Cookie.Path = "/";
                c.ExpireTimeSpan = session.AbsoluteTimeout;
                c.SlidingExpiration = false;
                c.LoginPath = "/login";
                c.LogoutPath = "/_ma-auth/logout";
                c.AccessDeniedPath = "/";
                c.Events.OnValidatePrincipal = CookieValidation.ValidateAsync;
            })
            .AddCookie(MaSchemes.MfaPending, c =>
            {
                c.Cookie.Name = "__Host-MindAttic.MfaPending";
                c.Cookie.HttpOnly = true;
                c.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                c.Cookie.SameSite = SameSiteMode.Lax;
                c.Cookie.Path = "/";
                c.ExpireTimeSpan = TimeSpan.FromMinutes(5);
                c.SlidingExpiration = false;
            });

        // Authorization — canonical Admin policy (role + MFA), plus app extensions.
        // Admin policy: role + (MFA step-up, only when MFA is required). With MFA off, Admin = role only.
        var authz = services.AddAuthorizationBuilder()
            .AddPolicy(MaPolicies.Admin, p =>
            {
                p.RequireRole(MaRoles.Admin);
                if (mfaOptions.RequireForAdmin) p.RequireClaim(MaClaims.Amr, "mfa");
            });
        o.ConfigureAdditionalPolicies?.Invoke(authz);

        // Blazor Server auth state with 1-minute revalidation.
        services.AddCascadingAuthenticationState();
        services.AddScoped<AuthenticationStateProvider, MaRevalidatingAuthenticationStateProvider>();

        return services;
    }
}
