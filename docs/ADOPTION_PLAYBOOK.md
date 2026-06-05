# MindAttic.Authentication — Adoption Playbook (Legion-decided)

> Cross-app adoption strategy for Ideas, StreetSamurai, Tutor. Legion made the technical hard calls; owner decisions are noted inline.

## Owner decisions (locked)
- **Tutor:** multi-user web → gets its first SQL DB + full Vault/MFA auth stack.
- **MFA:** OFF for now (each app sets MindAttic:Auth:Mfa:RequireForAdmin=false; library default stays secure). Flip on later.

## Role-name reconciliation
DECIDED: Reconcile at DATA MIGRATION, not via a library option. Keep the library's canonical role name 'Admin' (MaRoles.Admin) as the single cross-app contract; MaPolicies.Admin keys on it. In StreetSamurai's one-time data migration, map UserRoles.Administrator -> 'Admin' (and pass User/Contributor through unchanged), then switch StreetSamurai app code from UserRoles.Administrator to MaRoles.Admin. Mechanism: `Role = (u.Role == UserRoles.Administrator ? MaRoles.Admin : u.Role)`. Rationale: a configurable Admin-role-name option would fragment the cross-app policy contract (the whole point of a shared library is one Admin policy shape); remapping touches one app, costs one line in migration plus app-code role-constant swaps, and keeps Ideas (already 'Admin') and Tutor (enum Admin -> 'Admin') aligned with zero divergence. Do NOT add a configurable Admin role name. Tutor's dual-role [Admin,Student] collapses to single-string 'Admin' (max-privilege wins); the app-defined 'ma:student' policy admits Admin so admins still see student surfaces.

## Claims augmentation (Ideas AuthorRawMarkup)
DECIDED two-part: (1) Library adds `IMaClaimsAugmentor { ValueTask AugmentAsync(ClaimsIdentity identity, AuthUser user, IReadOnlyList<string> amr, CancellationToken ct); }`, resolved via GetServices<IMaClaimsAugmentor>() inside AuthEndpoints.SignInCookieAsync just before SignInAsync, so app claims are baked into the cookie ONCE at sign-in. This is the canonical, supported hook (it can see the AuthUser row, unlike a transform). (2) BUT because MaRevalidatingAuthenticationStateProvider only revalidates (returns bool) and CookieValidation never rebuilds claims, claims baked at sign-in survive the cookie's life but NOT a fresh ClaimsPrincipal materialized from the cookie on circuit reconstruction IF anything strips them â€” so for defense the app ALSO registers an idempotent IClaimsTransformation that re-adds the deterministic claim. CONCRETE for Ideas: `IdeasClaimsAugmentor : IMaClaimsAugmentor` adds `new Claim(CmsClaims.AuthorRawMarkup, \"true\")` to the identity IFF `user.Role == MaRoles.Admin && amr.Contains(\"mfa\")`. Plus app-side `IdeasClaimsTransformation : IClaimsTransformation` that, if `principal.IsInRole(MaRoles.Admin) && principal.HasClaim(MaClaims.Amr,\"mfa\") && !principal.HasClaim(CmsClaims.AuthorRawMarkup)`, clones the identity and adds the claim (idempotent guard mandatory â€” runs every request + on circuit rebuild). The claim MUST require amr=mfa to match MaPolicies.Admin; it gates raw inline-JS authoring (stored-XSS-by-design), so issuing it on a password-only session would be a vuln. The AuthorRawMarkup authorization policy moves from the deleted AddAuthorization block into `o.ConfigureAdditionalPolicies` as RequireRole(Admin)+RequireClaim(amr,mfa)+RequireClaim(AuthorRawMarkup). Tutor/StreetSamurai register NO augmentor (no app claim).

## Email vs username
DECIDED: BOTH â€” map at migration now, AND add first-class email-login to the library (it is a genuine, low-risk shared gap). Immediate, unblocking: StreetSamurai's migration sets UserName=email and NormalizedUserName=Normalize(email), so login works through the existing userName field with ZERO library changes â€” this is the safety net and must be done regardless. Library addition (ship in 1.1.0): MindAtticAuthOptions.LoginIdentifier = UserName|Email|Either + IUserStore.FindByLoginAsync (resolve NormalizedUserName then fall back to NormalizedEmail), with NormalizedEmail made UNIQUE when Email/Either is selected. StreetSamurai sets LoginIdentifier=Either so a future email change doesn't strand a stale UserName; Ideas and Tutor keep the UserName default (both are username-based, only metadata email). Rationale: UserName=email alone is brittle (Email becomes a second source of truth on email change); the option is clean, benefits all apps, and the migration mapping remains valid either way (NormalizedUserName uniqueness still holds).

## Tutor storage
DECIDED: Tutor gains its FIRST database â€” SQL Server (LocalDB dev / Azure SQL prod), NOT SQLite. The library's IEntityTypeConfigurations emit SQL-Server-shaped types (rowversion concurrency tokens via IsRowVersion, char(64)/binary(32) fixed-length, the 'auth' schema) so SQL Server avoids provider quirks and matches Ideas/StreetSamurai. Concrete steps: (1) Add to Tutor.Core.csproj: Microsoft.EntityFrameworkCore.SqlServer + .Design + .Relational, plus a reference to MindAttic.Authentication (NuGet from C:\\LocalNuGet). (2) New `Tutor.Core/Data/TutorAuthDbContext.cs : DbContext, IAuthDataContext` declaring the 8 DbSets, OnModelCreating calls `modelBuilder.ApplyMindAtticAuthConfiguration()`. AUTH-ONLY: course/progress stays in JSON; only identity moves to SQL. (3) Add an IDesignTimeDbContextFactory<TutorAuthDbContext> reading a dev connection string so `dotnet ef migrations add MindAtticAuth_Initial --context TutorAuthDbContext` works. (4) Register `AddDbContext<TutorAuthDbContext>(o => o.UseSqlServer(config.GetConnectionString(\"TutorAuth\")))` (cs from Vault/App Service Key Vault ref, never source). JSON SHA256 migration: idempotent IHostedService (TutorIdentityImportHostedService) reads %LOCALAPPDATA%\\Tutor\\Users\\Users.json, inserts AuthUser per user with PasswordHash=stored SHA256 base64 AS-IS, LegacyHashScheme=\"sha256\", PasswordPepperKeyId=null (transparent upgrade-on-login), Role = (Roles contains Admin ? \"Admin\" : \"Student\"), NormalizedUserName=Normalize(username), SecurityStamp=new GUID. FORCED RESET of hardcoded 'aaa' accounts: compare stored hash to precomputed SHA256(\"aaa\") base64 (covers ryan/erin and any 'aaa' account â€” do NOT trust usernames) -> set MustChangePassword=true; Admins also get MustEnrollMfa=true. Idempotency key = NormalizedUserName (skip if present). Re-key per-user data services (UserStorageService/UserProgressService) onto UserName/ma:uid via a scoped CurrentUserAccessor since AuthUser.Id is a fresh GUID (old profile.Id cannot be carried). If the JSON store holds only ryan/erin, the importer is effectively trivial and AuthBootstrapper seeds a clean admin on an empty DB.

## Required library changes (Legion list)

- IMaClaimsAugmentor (sign-in claims seam). Add: `public interface IMaClaimsAugmentor { ValueTask AugmentAsync(ClaimsIdentity identity, AuthUser user, IReadOnlyList<string> amr, CancellationToken ct); }`. In AuthEndpoints.SignInCookieAsync, resolve `http.RequestServices.GetServices<IMaClaimsAugmentor>()` and await each against the ClaimsIdentity BEFORE `SignInAsync`, so app claims (e.g. Ideas CmsClaims.AuthorRawMarkup) are baked into the cookie once at sign-in. Augmentors must be DETERMINISTIC from (role, amr, user) because claims are NOT rebuilt on revalidation. Register via `services.AddScoped<IMaClaimsAugmentor, T>()` (GetServices = zero-or-many, opt-in). This is the canonical hook; the IClaimsTransformation path stays as the interim/no-rebuild safety net but the augmentor is the supported way.

- IAuthEmailSender (host-implemented email seam). Add: `public interface IAuthEmailSender { Task SendPasswordResetAsync(string toEmail, string resetUrl, CancellationToken ct = default); Task SendSecurityAlertAsync(string toEmail, string subject, string body, CancellationToken ct = default); }`. The library declares it; hosts wire an implementation. Provide a no-op/log-only default registered via TryAdd so the host boot doesn't fail when reset isn't configured, but require a real one before mapping reset endpoints.

- IPasswordResetService + /_ma-auth/forgot and /_ma-auth/reset endpoints. Implement `IPasswordResetService { Task InitiateAsync(string emailOrUserName, string sourceIp, string userAgent, CancellationToken ct); Task<ResetResult> CompleteAsync(string token, string newPassword, CancellationToken ct); }` over the existing AuthPasswordResetToken entity: 256-bit CSPRNG token, stored only as HMAC-SHA256 (Vault `reset-token-key`), single-use, <=15m TTL, per-account+per-IP throttle (reuse AuthLoginThrottle), <=3 emails/addr/hr, enumeration-safe generic responses, no auto-login, does NOT bypass MFA. Map `group.MapPost("/forgot", ...)` and `group.MapPost("/reset", ...)` in MapMindAtticAuthEndpoints. Ship MaForgotPassword/MaResetPassword components.

- MFA enrollment endpoints. MfaEnrollmentService.BeginAsync/ConfirmAsync exist but are unreachable. Add `group.MapPost("/mfa/enroll/begin", ...)` and `group.MapPost("/mfa/enroll/confirm", ...).RequireAuthorization()` to MapMindAtticAuthEndpoints, posting from MaMfaSetup. Without this, forced Admin MFA enrollment cannot complete and every migrated Admin is soft-locked out of MaPolicies.Admin.

- Forced-step middleware in UseMindAtticAuthentication. After UseAuthentication/UseAuthorization, add a redirect step: if authenticated AND (user has MustEnrollMfa OR Admin role without amr=mfa) -> redirect to /account/mfa/setup; if MustChangePassword -> redirect to /account/change-password (excluding the /_ma-auth, /login, /mfa, /account/* and static-asset paths). Source MustChangePassword/MustEnrollMfa from a claim baked at sign-in (add `ma:mcp` / `ma:mem` boolean claims in BuildClaims) so the middleware needs no DB hit. This closes the Ideas/StreetSamurai/Tutor soft-lockout HARD blocker.

- Email-login option. Add `MindAtticAuthOptions.LoginIdentifier { UserName | Email | Either }` (default UserName) and `IUserStore.FindByLoginAsync(string identifier, ...)` that resolves NormalizedUserName, then (if Email/Either) falls back to NormalizedEmail. Make AuthEndpoints.LoginAsync call FindByLoginAsync. Requires making NormalizedEmail UNIQUE in AuthModel when LoginIdentifier != UserName (bump ModelFingerprint to auth-v2 if the index changes). Lets StreetSamurai log in by email first-class; Ideas/Tutor keep the UserName default.

- MindAtticAuthOptions surface additions: `string PublicBaseUrl` (reset links â€” never Request.Host), `string[] AllowedReturnUrlPrefixes` (feed UrlSafety.LocalOrDefault), and optionally `Action<ForwardedHeadersOptions> ConfigureForwardedHeaders` since UseMindAtticAuthentication's comment says 'call AFTER UseForwardedHeaders' but it neither calls nor configures it. Document that the host wires UseForwardedHeaders with KnownProxies.

- Scoped-TContext startup guard. AddMindAtticAuthentication does `services.AddScoped<IAuthDataContext>(sp => sp.GetRequiredService<TContext>())` but never registers TContext. Add a ValidateOnStart hosted check that fails fast with a clear message if TContext is not registered as scoped (Ideas registers only AddDbContextFactory today, so this would throw at first login otherwise).

- Startup fail-closed pepper check. Add a ValidateOnStart that resolves IAuthSecrets and asserts `Security:pepper.v1` is present/non-blank at boot (the hasher precomputes a decoy at construction, but make it explicit) so a misprovisioned deploy fails in the pipeline, not at first login.

- Provisioning tool (`dotnet run --provision`). Ship the operator tool that emits CSPRNG `pepper.v1`, `dp-kek`, `reset-token-key`, and `bootstrap-token` to the dev file CredentialStore (%APPDATA%\MindAttic\Security) and prints prod values for Key Vault seeding. Referenced everywhere but not in the source tree.

- Import helper on IUserStore. Add `Task<AuthUser> ImportAsync(AuthUser user, CancellationToken ct)` (or document AuthUsers.Add with IUserStore.Normalize semantics) so per-app one-time migrations don't hand-roll Normalize() incorrectly. Today only AuthBootstrapper writes AuthUsers.

- Re-pack as MindAttic.Authentication 1.1.0 to C:\LocalNuGet after the above. Keep ModelFingerprint at auth-v1 unless the email-login UNIQUE-index change lands, in which case bump to auth-v2 and require hosts to re-migrate.

## Adoption order

- 1) FINISH THE LIBRARY FIRST (1.1.0): IMaClaimsAugmentor, IAuthEmailSender, IPasswordResetService + /forgot,/reset, MFA enroll endpoints, forced-step middleware, email-login option, options surface (PublicBaseUrl/return-url), scoped-TContext + pepper ValidateOnStart guards, provisioning tool. RATIONALE: forced-MFA-enroll + enroll endpoint + reset flow are HARD blockers for ALL THREE apps (a carried Admin is soft-locked-out of MaPolicies.Admin with no enrollment path, and no app can offer self-service reset). Re-pack to C:\LocalNuGet. Build the Psst IAuthEmailSender adapter pattern once here so all apps share it.

- 2) StreetSamurai â€” adopt FIRST (cleanest donor). It already has a real SQL DB, an EF DbContext, a deploy pipeline, and a build->migrate->deploy CI. Highest security urgency too: it carries a DevAutoLoginMiddleware backdoor and a hardcoded admin password that MUST die. Frictions are contained (users-as-JSON-blob -> one read; raw-SQL/temporal schema -> author create_auth_schema_*.sql by scripting EF's auth model so it can't drift from ModelFingerprint). Proves the email-login option, reset flow, and the prod Azure Data Protection path end-to-end.

- 3) Ideas â€” adopt SECOND. Clean schema adopter (one BCrypt admin carries cleanly, role already 'Admin'), but mid-refactor and the login/author surfaces are UNBUILT, so adoption BUILDS the flow rather than replacing a working one â€” lower regression risk but more new UI. Exercises the IMaClaimsAugmentor hook (AuthorRawMarkup) that StreetSamurai doesn't need. Requires the dual DbContext registration (add scoped AddDbContext alongside the existing AddDbContextFactory). Ship AddMindAtticAuth + data-migration in release N, DropLegacyUsers in N+1 (one overlap release for rollback).

- 4) Tutor â€” adopt LAST (largest structural lift). It is gaining its FIRST database, FIRST EF DbContext, FIRST real ASP.NET auth pipeline, must move SignIn OUT of the Blazor circuit, replace the singleton CurrentUser (a multi-user correctness bug) with per-circuit ClaimsPrincipal, re-key per-user data services, and add net-new Azure SQL infra. Do it after the pattern is proven twice and the library is stable. Confirm with the owner it is truly a multi-user web deployment before imposing the full fail-closed Vault+SQL+MFA stack.

## Open owner questions (remaining)

- Tutor reality check: is Tutor truly a MULTI-USER WEB deployment (then full SQL+Vault+MFA+Azure-SQL infra is justified), or a single-user local/desktop tool (then the fail-closed Vault+SQL+MFA stack is heavier than the product needs)? This gates the entire Tutor plan and net-new Azure SQL cost.

- Prod Data Protection hosting per app: confirm each app's prod target so ConfigureDataProtection can be filled (Ideas has no Azure wiring shown; StreetSamurai/Tutor are Azure App Service Windows -> ProtectKeysWithAzureKeyVault + PersistKeysToAzureBlobStorage). The library is fail-closed in prod â€” no DP config = no boot.

- Decommission well-known accounts: confirm OK to deactivate admin@streetsamurai.local (StreetSamurai) and force-reset all 'aaa' accounts (Tutor) and let AuthBootstrapper mint a clean admin. Verify no runbook/automation depends on those exact identities.

- PublicBaseUrl per app (canonical https origin) for password-reset links â€” must be config, never Request.Host. Needed before the reset flow goes live.

- MFA scope beyond Admin: should StreetSamurai Contributors and/or Tutor Students be forced to enroll MFA? Current plan: MFA forced for Admin only; others password-only.

- Self-registration: should Tutor keep open self-service registration (now under NIST min-12 policy) or move to admin-provisioned accounts only? (Old controller allowed 3-char passwords.)

- Dormancy forced-reset threshold: ratified policy is carry+upgrade-on-login+forced-reset-for-dormant. Define the dormancy window (e.g. >12 months no LastLoginUtc -> MustChangePassword) per app, and whether to force-reset ALL migrated Ideas admins proactively (recommended; single admin).

- Tutor email collection: most JSON profiles likely have no Email; password reset requires a verified email. Prompt users to add/verify email at first login, or accept reset unavailable for email-less accounts?

- Where does Psst run in Azure App Service Windows prod â€” is the Psst email channel reachable/credentialed there, or should prod fall back to SMTP (StreetSamurai's existing EmailService) while Psst is used only on local Windows dev hosts?


---

# Unified playbook

## Unified Adoption Playbook â€” MindAttic.Authentication across Ideas, StreetSamurai, Tutor

### Phase 0 â€” Finish the library (MindAttic.Authentication 1.1.0)
These are shared blockers; do them once, re-pack to C:\\LocalNuGet.
1. **IMaClaimsAugmentor** seam in `AuthEndpoints.SignInCookieAsync` (GetServices, await each, bake into cookie pre-SignInAsync). Add `ma:mcp`/`ma:mem` claims in `BuildClaims` for the forced-step middleware.
2. **Forced-step middleware** inside `UseMindAtticAuthentication`: redirect MustEnrollMfa/Admin-without-amr=mfa -> `/account/mfa/setup`; MustChangePassword -> `/account/change-password` (exclude `/_ma-auth`,`/login`,`/mfa`,`/account/*`,static).
3. **MFA enroll endpoints** `/_ma-auth/mfa/enroll/begin|confirm` over the existing `MfaEnrollmentService`.
4. **IAuthEmailSender** interface + **IPasswordResetService** + `/_ma-auth/forgot|reset` + MaForgotPassword/MaResetPassword.
5. **Email-login**: `MindAtticAuthOptions.LoginIdentifier`, `IUserStore.FindByLoginAsync`, NormalizedEmail UNIQUE when enabled.
6. **Options**: `PublicBaseUrl`, `AllowedReturnUrlPrefixes`; doc UseForwardedHeaders host wiring.
7. **ValidateOnStart guards**: TContext-registered-as-scoped; `Security:pepper.v1` present.
8. **Provisioning tool** `dotnet run --provision` (pepper.v1, dp-kek, reset-token-key, bootstrap-token).
9. **Psst adapter pattern**: `PsstAuthEmailSender : IAuthEmailSender` (email channel ON, Twilio OFF) â€” one reference impl all three apps copy.

### Per-app invariant wiring (all three)
- DbContext implements `IAuthDataContext` (8 DbSets) and calls `b.ApplyMindAtticAuthConfiguration()` in OnModelCreating (auth schema, no FKs).
- `AddMindAtticAuthentication<TContext>(config, o => { o.AppName=<App>; o.IsProduction=!env.IsDevelopment(); o.ConfigureDataProtection=<Blob+KV in prod>; o.ConfigureAdditionalPolicies=<app policies>; })`.
- `app.UseMindAtticAuthentication()` after UseForwardedHeaders, before mapping; `endpoints.MapMindAtticAuthEndpoints()`.
- Pages: `/login`(MaLogin), `/mfa`(MaMfaChallenge), `/account`(MaLogout), `/account/change-password`(MaChangePassword), `/account/mfa/setup`(MaMfaSetup), `/account/forgot|reset`.
- Register `IAuthEmailSender` -> PsstAuthEmailSender BEFORE AddMindAtticAuthentication.
- Provision Vault `Security:pepper.v1` (>=32B, fail-closed), `bootstrap-token` (>=12), `reset-token-key`, `dp-kek` (dev). Prod: Key Vault refs + ConfigureDataProtection.
- Startup order: `MigrateAsync` -> one-time idempotent data migration -> `AuthBootstrapper.SeedAdminAsync` (no-op once any AuthUser exists) -> app seed/discovery. ROTATE bootstrap-token after first seed.
- Data-migration idempotency key = `NormalizedUserName`. Carry legacy hash verbatim + set LegacyHashScheme (bcrypt|sha256); AuthUser.Id is a FRESH GUID (never reuse legacy string Id) â€” re-key any app data that referenced the old user id onto UserName/ma:uid.

### Phase 1 â€” StreetSamurai (FIRST)
- Add package; ensure CI restore finds C:\\LocalNuGet (add NuGet source or drop .nupkg into ./lib/local-packages).
- StreetSamuraiDbContext : IAuthDataContext (8 DbSets + ApplyMindAtticAuthConfiguration at top of OnModelCreating).
- Schema via RAW SQL (no EF migrations): `Data/Sql/create_auth_schema_20260605.sql` â€” GENERATE it by scripting EF's auth model (throwaway design-time migration -> Script-Migration) so it can't drift from ModelFingerprint; auth tables NON-temporal (omit from EnableSystemVersioningAsync). Append to ApplyMigrations.
- Data migration MoveUsersToAuthUsers from `users.accounts` JSON blob: UserName=Email, NormalizedUserName/Email/NormalizedEmail set, EmailVerified=true, Role Administrator->Admin, LegacyHashScheme=bcrypt, new SecurityStamp; Admin rows MustEnrollMfa=true. DECOMMISSION admin@streetsamurai.local: deactivate it and let AuthBootstrapper mint a clean admin from bootstrap-token. Run from ApplyMigrations (rides the OIDC db_ddladmin job); GRANT INSERT/UPDATE/SELECT on schema auth to the runtime managed identity.
- Set `o.LoginIdentifier = Either`; `o.ConfigureAdditionalPolicies`: `ss:writer = RequireRole(\"Contributor\", MaRoles.Admin)`.
- DELETE: DevAutoLoginMiddleware (+config+ss-dev-logout), AuthService, PasswordResetService, hand-rolled AddCookie/AddAuthorization, MustChangePassword middleware, /api/auth/login+logout. Keep the edge rate limiter as coarse defense-in-depth (optional). UserRepository/UserAccount: read-only for one release, then delete.
- Keep blob read-only one release for rollback; all users logged out on deploy (expected).

### Phase 2 â€” Ideas (SECOND)
- Add package to Web (and Core â€” DbContext needs ApplyMindAtticAuthConfiguration). Keep BCrypt.Net-Next in Core for migration verify only.
- CmsDbContext : IAuthDataContext (8 DbSets + ApplyMindAtticAuthConfiguration at END of OnModelCreating; leave temporal Pages + legacy User mapping intact for now).
- **Register scoped `AddDbContext<CmsDbContext>` alongside the existing AddDbContextFactory** (factory = CMS read paths; scoped backs auth) â€” required or IAuthDataContext resolution throws.
- EF migration `AddMindAtticAuth` (auth.* only â€” review it emits NO temporal churn). Later release: `DropLegacyUsers`.
- Data migration IdeasAuthDataMigration: copy Core.Entities.User -> AuthUser, BCrypt verbatim + LegacyHashScheme=bcrypt, Role Admin->Admin, Admin -> MustEnrollMfa=true; force MustChangePassword on the row whose hash verifies 'ChangeMe!2026' (recommend force-reset ALL admins). Idempotent skip on NormalizedUserName.
- AuthorRawMarkup: register `IdeasClaimsAugmentor : IMaClaimsAugmentor` AND idempotent `IdeasClaimsTransformation : IClaimsTransformation`; move the AuthorRawMarkup policy into `o.ConfigureAdditionalPolicies` (RequireRole(Admin)+RequireClaim(amr,mfa)+RequireClaim(AuthorRawMarkup)).
- DELETE: AddCookie('Ideas.Auth')/AddAuthorization blocks, hardcoded 'ChangeMe!2026' seed args, Core.Services.AuthService, AuthService DI + SeedService auth args. KEEP CmsClaims (move to own file when User/UserRoles deleted). Verify nothing joins Page.AuthoredByUserId to the old User.Id before DropLegacyUsers.
- Build /login,/mfa,/account/* pages hosting library components. Confirm CSP nonce scope (auth surface only) does NOT touch '/' or '/frontpage' (Author inline JS).

### Phase 3 â€” Tutor (LAST)
- Add EF SqlServer/.Design/.Relational + library ref. New TutorAuthDbContext : IAuthDataContext (+ IDesignTimeDbContextFactory). `AddDbContext<TutorAuthDbContext>(UseSqlServer(GetConnectionString(\"TutorAuth\")))`.
- `dotnet ef migrations add MindAtticAuth_Initial --context TutorAuthDbContext`; apply in dev + deploy.
- TutorIdentityImportHostedService (idempotent) from Users.json: SHA256 carried verbatim + LegacyHashScheme=sha256; Role = Admin if Roles contains Admin else Student; force MustChangePassword where stored hash == SHA256('aaa'); Admins MustEnrollMfa=true. Rename Users.json -> Users.migrated.json after import.
- `o.ConfigureAdditionalPolicies`: `ma:student = RequireRole(\"Student\", MaRoles.Admin)`.
- Replace AuthGuard/CurrentUser singleton: convert pages to `[Authorize(Policy=MaPolicies.Admin)]` / `[Authorize(\"ma:student\")]`; Routes.razor -> AuthorizeRouteView; add scoped CurrentUserAccessor (ma:uid/name) and re-key UserStorageService/UserProgressService/QuizService/FinalExamService off it.
- DELETE LocalAuthController, AuthenticationService (singleton), IAuthController, AuthGuard, Home.razor inline login form + their DI; update Tutor.Tests/DependencyInjectionTests.cs.
- Move SignIn OUT of the circuit (Home @onsubmit -> MaLogin static-SSR form). Add forwarded-headers KnownProxies for App Service.

### Cross-cutting verification (each app)
clean DB -> bootstrap seeds admin from Vault token (MustChangePassword+MustEnrollMfa); existing DB -> users migrated, legacy hash carried, known-bad accounts force-reset; legacy login -> transparent upgrade to Argon2id+pepper (LegacyHashScheme cleared); Admin pushed through forced MFA enroll before MaPolicies.Admin grants; password reset email arrives via Psst.

