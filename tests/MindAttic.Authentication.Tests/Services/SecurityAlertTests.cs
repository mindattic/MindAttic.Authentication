using System.Collections.Concurrent;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using MimeKit;
using MindAttic.Authentication.Crypto;
using MindAttic.Authentication.Data;
using MindAttic.Authentication.Entities;
using MindAttic.Authentication.Options;
using MindAttic.Authentication.Services;
using MindAttic.Authentication.Tests.TestSupport;
using MindAttic.Authentication.Web;

namespace MindAttic.Authentication.Tests.Services;

/// <summary>
/// Security-alert emails (AUTH-US-E5). Each account event runs through the real services, the real
/// <see cref="AuthSecurityAlerts"/> and the real <see cref="SmtpAuthEmailSender"/>, ending at a fake
/// transport — no socket is opened and no mail is sent.
/// </summary>
[TestFixture]
public sealed class SecurityAlertTests
{
    private const string Password = "Initial-Passphrase-1";

    private sealed class Transport : IAuthMailTransport
    {
        public ConcurrentQueue<MimeMessage> Sent { get; } = new();
        public Task SendAsync(MimeMessage message, CancellationToken ct) { Sent.Enqueue(message); return Task.CompletedTask; }
    }

    private sealed class Harness
    {
        public required TestAuthDbContext Db { get; init; }
        public required FixedClock Clock { get; init; }
        public required Argon2idPasswordHasher Hasher { get; init; }
        public required Transport Transport { get; init; }
        public required SmtpAuthEmailSender Smtp { get; init; }
        public required AuthSecurityAlerts Alerts { get; init; }
        public IDataProtectionProvider Dp { get; } = new EphemeralDataProtectionProvider();

        /// <summary>Drains the queue and returns every delivered message.</summary>
        public async Task<List<MimeMessage>> DeliveredAsync()
        {
            await Smtp.StopAsync(CancellationToken.None);
            return Transport.Sent.ToList();
        }

        public AuthenticationService Auth() => new(new UserStore(Db), Hasher, new AccountLockoutService(Db, Clock),
            new FakeAuditWriter(), new TotpService(Build.Opt(new MfaOptions()), Clock), Dp, Db,
            Build.Opt(new AuthSessionOptions()), Clock, Alerts);

        public MfaEnrollmentService Mfa() => new(new UserStore(Db), Db, new TotpService(Build.Opt(new MfaOptions()), Clock),
            Hasher, Dp, new FakeAuditWriter(), Build.Opt(new MfaOptions()), Clock, Alerts);

        public UserAdminService Admin() => new(Db, Hasher, new FakePasswordPolicy(), new FakeAuditWriter(), Clock, Alerts);
    }

    private static async Task<Harness> NewAsync()
    {
        var clock = FixedClock.At(new DateTimeOffset(2026, 6, 6, 12, 0, 0, TimeSpan.Zero));
        var transport = new Transport();
        var smtp = new SmtpAuthEmailSender(transport,
            new AuthEmailSettings("smtp.example.com", 587, "mailer@example.com", "pw", "mailer@example.com"),
            Build.Opt(new AuthResetOptions { PublicBaseUrl = "https://app.example.com" }),
            NullLogger<SmtpAuthEmailSender>.Instance, "Ideas") { RetryDelay = TimeSpan.Zero };
        await smtp.StartAsync(CancellationToken.None);
        return new Harness
        {
            Db = TestAuthDbContext.NewInMemory(), Clock = clock, Hasher = Build.Hasher(), Transport = transport, Smtp = smtp,
            Alerts = new AuthSecurityAlerts(smtp, clock, NullLogger<AuthSecurityAlerts>.Instance),
        };
    }

    private static async Task<AuthUser> SeedAsync(Harness h, string userName = "alice", string? email = "alice@example.com")
    {
        var stored = h.Hasher.Hash(Password);
        var user = new AuthUser
        {
            UserName = userName, NormalizedUserName = IUserStore.Normalize(userName),
            Email = email, NormalizedEmail = email?.ToUpperInvariant(),
            PasswordHash = stored.Phc, PasswordPepperKeyId = stored.PepperKeyId,
            Role = "User", IsActive = true, CreatedUtc = h.Clock.GetUtcNow().UtcDateTime,
        };
        h.Db.AuthUsers.Add(user);
        await h.Db.SaveChangesAsync();
        return user;
    }

    private static string[] Subjects(IEnumerable<MimeMessage> mail) => mail.Select(m => m.Subject).ToArray();

    [Test]
    public async Task PasswordChange_AlertsTheOwner_AndAFailedChangeDoesNot()
    {
        var h = await NewAsync();
        var user = await SeedAsync(h);
        var svc = new PasswordChangeService(new UserStore(h.Db), h.Db, h.Hasher, new FakePasswordPolicy(), new FakeAuditWriter(), h.Clock, h.Alerts);

        await svc.ChangeAsync(user.Id, "wrong-password-entirely", "Another-Passphrase-22");
        await svc.ChangeAsync(user.Id, Password, "Another-Passphrase-22");

        var mail = (await h.DeliveredAsync()).Single();
        Assert.That(mail.Subject, Is.EqualTo("Ideas: Your password was changed"));
        Assert.That(mail.To.Mailboxes.Single().Address, Is.EqualTo("alice@example.com"));
        Assert.That(mail.TextBody, Does.Contain("2026-06-06 12:00 UTC").And.Not.Contain("Another-Passphrase-22"));
    }

    [Test]
    public async Task PasswordResetConfirmed_Alerts()
    {
        var h = await NewAsync();
        await SeedAsync(h);
        var links = new FakeEmailSender();
        var svc = new PasswordResetService(new UserStore(h.Db), h.Db, h.Hasher, new FakePasswordPolicy(), new FakeAuthSecrets(),
            links, new FakeAuditWriter(), Build.Opt(new AuthResetOptions { PublicBaseUrl = "https://app.example.com" }), h.Clock, h.Alerts);

        await svc.RequestAsync("alice", "203.0.113.7", "agent");
        var result = await svc.ConfirmAsync(links.LastResetToken(), "Brand-New-Passphrase-42");

        Assert.That(result.Ok, Is.True);
        Assert.That(Subjects(await h.DeliveredAsync()), Is.EqualTo(new[] { "Ideas: Your password was reset" }));
    }

    [Test]
    public async Task AdminActions_Alert_PasswordReset_Deactivation_AndEmailChangeGoesToTheOldAddress()
    {
        var h = await NewAsync();
        var user = await SeedAsync(h);
        var admin = h.Admin();

        await admin.ResetPasswordAsync(user.Id, "Operator-Set-Passphrase-9");
        await admin.UpdateProfileAsync(user.Id, "alice.new@example.com");
        await admin.UpdateProfileAsync(user.Id, "alice.new@example.com", "Alice");   // email unchanged: no alert
        await admin.SetActiveAsync(user.Id, false);
        await admin.SetActiveAsync(user.Id, false);                                   // already inactive: no alert
        await admin.SetActiveAsync(user.Id, true);                                    // reactivation: no alert

        var mail = await h.DeliveredAsync();
        Assert.That(Subjects(mail), Is.EqualTo(new[]
        {
            "Ideas: Your password was reset by an administrator",
            "Ideas: Your email address was changed",
            "Ideas: Your account was deactivated",
        }));
        Assert.That(mail[1].To.Mailboxes.Single().Address, Is.EqualTo("alice@example.com"), "email-change alert goes to the OLD address");
        Assert.That(mail[2].To.Mailboxes.Single().Address, Is.EqualTo("alice.new@example.com"));
    }

    [Test]
    public async Task MfaEnabled_Alerts_AndSigningInWithARecoveryCode_Alerts()
    {
        var h = await NewAsync();
        var user = await SeedAsync(h);
        var mfa = h.Mfa();

        await mfa.BeginAsync(user.Id);
        var pending = h.Db.AuthUserMfa.Single(m => m.UserId == user.Id).PendingSecretEncrypted!;
        var secret = h.Dp.CreateProtector("MindAttic.Authentication.Totp.v1").Unprotect(pending);
        var enrolled = await mfa.ConfirmAsync(user.Id, TotpReference.Compute(secret, TotpReference.StepFor(h.Clock.GetUtcNow())), Password);
        Assert.That(enrolled.Ok, Is.True, enrolled.Error);

        var auth = h.Auth();
        var step1 = await auth.LoginAsync("alice", Password, "203.0.113.7", "Browser/1");
        Assert.That(step1.Status, Is.EqualTo(LoginStatus.MfaRequired));
        var step2 = await auth.ConfirmMfaAsync(user.Id, enrolled.RecoveryCodes![0], isRecoveryCode: true, "203.0.113.7", "Browser/1");
        Assert.That(step2.Status, Is.EqualTo(LoginStatus.Success));

        var mail = await h.DeliveredAsync();
        Assert.That(Subjects(mail), Is.EqualTo(new[] { "Ideas: Two-step verification was turned on", "Ideas: A recovery code was used to sign in" }));
        Assert.That(mail[1].TextBody, Does.Contain("Browser/1").And.Not.Contain(enrolled.RecoveryCodes[0]));
    }

    [Test]
    public async Task Lockout_AlertsOncePerRunOfFailures_AndNeverForUnknownAccounts()
    {
        var h = await NewAsync();
        await SeedAsync(h);
        var auth = h.Auth();

        for (var i = 0; i < 4; i++) await auth.LoginAsync("alice", "wrong-password-" + i, "203.0.113.7", "Browser/1");   // 4th starts back-off
        h.Clock.Advance(TimeSpan.FromMinutes(1));
        await auth.LoginAsync("alice", "wrong-password-again", "203.0.113.8", "Browser/1");                                // 5th: same run, no new alert
        for (var i = 0; i < 4; i++) await auth.LoginAsync("ghost", "wrong-password-" + i, "203.0.113.9", "Browser/1");   // no account, no mail

        Assert.That(Subjects(await h.DeliveredAsync()), Is.EqualTo(new[] { "Ideas: Repeated failed sign-ins" }));
    }

    [Test]
    public async Task NewDeviceSignIn_AlertsOnlyWhenBothBrowserAndNetworkAreNew()
    {
        var h = await NewAsync();
        await SeedAsync(h);
        var auth = h.Auth();

        await auth.LoginAsync("alice", Password, "203.0.113.7", "Browser/1");    // first ever sign-in: no alert
        await auth.LoginAsync("alice", Password, "203.0.113.7", "Browser/2");    // known network: no alert
        await auth.LoginAsync("alice", Password, "198.51.100.4", "Browser/1");   // known browser: no alert
        await auth.LoginAsync("alice", Password, "198.51.100.99", "Phone/7");    // both new: alert

        var mail = (await h.DeliveredAsync()).Single();
        Assert.That(mail.Subject, Is.EqualTo("Ideas: New sign-in to your account"));
        Assert.That(mail.TextBody, Does.Contain("Phone/7").And.Not.Contain("198.51.100.99"));
    }

    [Test]
    public async Task AccountWithoutEmail_GetsNoAlert()
    {
        var h = await NewAsync();
        var user = await SeedAsync(h, email: null);
        await h.Admin().ResetPasswordAsync(user.Id, "Operator-Set-Passphrase-9");
        Assert.That(await h.DeliveredAsync(), Is.Empty);
    }

    private sealed class ThrowingSender : IAuthEmailSender
    {
        public Task SendPasswordResetAsync(string toEmail, string resetLink, CancellationToken ct = default) => throw new IOException("boom");
        public Task SendSecurityAlertAsync(string toEmail, string subject, string body, CancellationToken ct = default) => throw new IOException("boom");
    }

    [Test]
    public async Task AFailingSender_NeverFailsTheAccountChange()
    {
        var h = await NewAsync();
        var user = await SeedAsync(h);
        var alerts = new AuthSecurityAlerts(new ThrowingSender(), h.Clock, NullLogger<AuthSecurityAlerts>.Instance);
        var svc = new PasswordChangeService(new UserStore(h.Db), h.Db, h.Hasher, new FakePasswordPolicy(), new FakeAuditWriter(), h.Clock, alerts);

        var result = await svc.ChangeAsync(user.Id, Password, "Another-Passphrase-22");

        Assert.That(result.Ok, Is.True);
        Assert.That(h.Hasher.Verify("Another-Passphrase-22", h.Db.AuthUsers.Single().PasswordHash, h.Db.AuthUsers.Single().PasswordPepperKeyId, null).Succeeded);
    }

    [Test]
    public async Task Registration_WiresAlertsIntoTheServices_ThroughDependencyInjection()
    {
        var transport = new Transport();
        var db = TestAuthDbContext.NewInMemory();
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{AuthEmailSettings.SectionPath}:smtpHost"] = "smtp.example.com",
            [$"{AuthEmailSettings.SectionPath}:username"] = "mailer@example.com",
            [$"{AuthEmailSettings.SectionPath}:password"] = "pw",
            [$"{AuthEmailSettings.SectionPath}:from"] = "mailer@example.com",
        }).Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions<AuthResetOptions>();
        services.AddSingleton<IAuthMailTransport>(transport);
        services.AddSingleton<TimeProvider>(FixedClock.At(new DateTimeOffset(2026, 6, 6, 12, 0, 0, TimeSpan.Zero)));
        services.AddSingleton<IAuthDataContext>(db);
        services.AddSingleton<IPasswordHasher>(Build.Hasher());
        services.AddSingleton<IPasswordPolicy>(new FakePasswordPolicy());
        services.AddSingleton<IAuthAuditWriter>(new FakeAuditWriter());
        services.AddScoped<IUserStore>(_ => new UserStore(db));
        services.AddScoped<IPasswordChangeService, PasswordChangeService>();
        services.AddMindAtticAuthEmail(config, "Ideas");
        await using var sp = services.BuildServiceProvider();

        var hasher = sp.GetRequiredService<IPasswordHasher>();
        var stored = hasher.Hash(Password);
        db.AuthUsers.Add(new AuthUser
        {
            UserName = "alice", NormalizedUserName = "ALICE", Email = "alice@example.com", NormalizedEmail = "ALICE@EXAMPLE.COM",
            PasswordHash = stored.Phc, PasswordPepperKeyId = stored.PepperKeyId, Role = "User", IsActive = true,
        });
        await db.SaveChangesAsync();

        var smtp = (SmtpAuthEmailSender)sp.GetRequiredService<IAuthEmailSender>();
        await smtp.StartAsync(CancellationToken.None);
        using (var scope = sp.CreateScope())
            await scope.ServiceProvider.GetRequiredService<IPasswordChangeService>()
                .ChangeAsync(db.AuthUsers.Single().Id, Password, "Another-Passphrase-22");
        await smtp.StopAsync(CancellationToken.None);

        Assert.That(transport.Sent.Single().Subject, Is.EqualTo("Ideas: Your password was changed"));
    }
}
