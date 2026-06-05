# Integrating MindAttic.Authentication into an app

A consuming app keeps its own `DbContext`, connection string, and deployment. It gains hardened auth by
(1) referencing the package, (2) implementing `IAuthDataContext` on its `DbContext`, (3) wiring DI +
middleware + endpoints, (4) adding login/MFA/account pages, and (5) provisioning Vault secrets.

> The three apps remain **separate trust boundaries** — each picks a unique `AppName`, so a cookie from
> one app can never authenticate to another.

---

## 1. Reference the package

`nuget.config` must include the local feed:

```xml
<add key="LocalNuGet" value="C:\LocalNuGet" />
```
```xml
<PackageReference Include="MindAttic.Authentication" Version="1.0.0" />
<PackageReference Include="MindAttic.Vault" Version="1.0.0" />
```

## 2. Implement `IAuthDataContext` on your DbContext

```csharp
using MindAttic.Authentication.Data;
using MindAttic.Authentication.Entities;

public sealed class AppDbContext(DbContextOptions<AppDbContext> o) : DbContext(o), IAuthDataContext
{
    // ... your app's DbSets ...
    public DbSet<AuthUser> AuthUsers => Set<AuthUser>();
    public DbSet<AuthUserMfa> AuthUserMfa => Set<AuthUserMfa>();
    public DbSet<AuthRecoveryCode> AuthRecoveryCodes => Set<AuthRecoveryCode>();
    public DbSet<AuthSession> AuthSessions => Set<AuthSession>();
    public DbSet<AuthLoginThrottle> AuthLoginThrottles => Set<AuthLoginThrottle>();
    public DbSet<AuthAuditLog> AuthAuditLog => Set<AuthAuditLog>();
    public DbSet<AuthPasswordHistory> AuthPasswordHistory => Set<AuthPasswordHistory>();
    public DbSet<AuthPasswordResetToken> AuthPasswordResetTokens => Set<AuthPasswordResetToken>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        base.OnModelCreating(b);
        // ... your app's config ...
        b.ApplyMindAtticAuthConfiguration();   // tables in the isolated `auth` schema
    }
}
```
Then `dotnet ef migrations add AddMindAtticAuth` and deploy the migration (the `auth` schema is created
alongside your existing tables; no FKs cross into app tables).

## 3. Wire DI + middleware + endpoints (`Program.cs`)

```csharp
builder.Configuration.AddMindAtticVaultFiles().AddEnvironmentVariables();
builder.Services.AddMindAtticVault(builder.Configuration);

builder.Services.AddDbContextFactory<AppDbContext>(o => o.UseSqlServer(conn));   // your existing setup
builder.Services.AddScoped<AppDbContext>(sp => sp.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext());

builder.Services.AddMindAtticAuthentication<AppDbContext>(builder.Configuration, o =>
{
    o.AppName       = "Ideas";                       // per-app trust boundary
    o.IsProduction  = !builder.Environment.IsDevelopment();
    o.ConfigureDataProtection = dp =>                // PROD only — fail-closed if omitted in prod
    {
        dp.PersistKeysToAzureBlobStorage(blobUri, cred)
          .ProtectKeysWithAzureKeyVault(kvKeyUri, cred);
    };
    // o.ConfigureAdditionalPolicies = ab => ab.AddPolicy("MyPolicy", p => ...);
});

builder.Services.AddRazorComponents().AddInteractiveServerComponents();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await db.Database.MigrateAsync();
    await scope.ServiceProvider.GetRequiredService<AuthBootstrapper>().SeedAdminAsync();   // needs Vault bootstrap-token
}

app.UseForwardedHeaders();                 // configure KnownProxies/KnownNetworks (security-critical)
app.UseMindAtticAuthentication();          // authn → authz → scoped CSP nonce
app.UseAntiforgery();
app.MapMindAtticAuthEndpoints();           // /_ma-auth/*
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
app.Run();
```

## 4. Add the pages

```razor
@* /login *@
@page "/login"
@inject NavigationManager Nav
<MaLogin ReturnUrl="@_returnUrl" Error="@_error" />
@code {
    string? _returnUrl; bool _error;
    protected override void OnParametersSet() {
        var q = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(new Uri(Nav.Uri).Query);
        _returnUrl = q.TryGetValue("returnUrl", out var r) ? r.ToString() : null;
        _error = q.ContainsKey("error");
    }
}
```
Add `/mfa` (`<MaMfaChallenge/>`), `/account/change-password` (`<MaChangePassword/>`), and
`/account/mfa/setup` (`<MaMfaSetup/>`, rendered `@rendermode InteractiveServer`). Protect admin pages with
`@attribute [Authorize(Policy = MaPolicies.Admin)]` (role **+** MFA).

## 5. Email channel (Windows hosts)

Password-reset/security-alert emails go through an `IAuthEmailSender` the host registers — on Windows via a
`MindAttic.Psst`-backed adapter (email channel; SMS off). See [`OPERATIONS.md`](OPERATIONS.md).

## 6. Provision secrets

Before first run, provision the Vault `Security` bucket: `pepper.v1`, `bootstrap-token` (and prod
`dp-kek`/`reset-token-key`). See [`OPERATIONS.md`](OPERATIONS.md). The hasher and bootstrap are
**fail-closed** — the app will not start without them.

## 7. Migrating existing users

Run a one-time data migration mapping your old user rows → `AuthUser`, carrying the old hash with
`LegacyHashScheme = "bcrypt"` (or `"sha256"`), so they upgrade to Argon2id+pepper on next login. Force a
reset for any known-bad/hardcoded/dormant accounts. Map your old admin role onto `MaRoles.Admin`. See the
adoption playbook for per-app specifics.
