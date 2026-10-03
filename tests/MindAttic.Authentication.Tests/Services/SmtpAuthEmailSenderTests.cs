using System.Collections.Concurrent;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using MimeKit;
using MindAttic.Authentication.Options;
using MindAttic.Authentication.Services;
using MindAttic.Authentication.Tests.TestSupport;
using MindAttic.Authentication.Web;

namespace MindAttic.Authentication.Tests.Services;

/// <summary>
/// Auth email delivery (AUTH-US-E4). Every test runs against <see cref="FakeTransport"/> — no socket is ever
/// opened and no mail is ever sent.
/// </summary>
public class SmtpAuthEmailSenderTests
{
    private const string Link = "https://ideas.example.com/reset-password?token=SECRET-TOKEN-VALUE";

    private static readonly AuthEmailSettings Settings =
        new("smtp.example.com", 587, "mailer@example.com", "p@ss-not-logged", "MindAttic <mailer@example.com>");

    /// <summary>Records messages; can fail the first N sends or block until released.</summary>
    private sealed class FakeTransport : IAuthMailTransport
    {
        public ConcurrentQueue<MimeMessage> Sent { get; } = new();
        public int FailFirst { get; set; }
        public int Attempts;
        public TaskCompletionSource? Gate { get; set; }

        public async Task SendAsync(MimeMessage message, CancellationToken ct)
        {
            if (Gate is { } gate) await gate.Task.WaitAsync(ct);
            if (Interlocked.Increment(ref Attempts) <= FailFirst)
                throw new IOException("simulated SMTP failure");
            Sent.Enqueue(message);
        }
    }

    private static SmtpAuthEmailSender NewSender(FakeTransport transport, CapturingLoggerProvider logs) =>
        new(transport, Settings, Build.Opt(new AuthResetOptions { TokenTtlMinutes = 15 }),
            logs.For<SmtpAuthEmailSender>(), "Ideas")
        { RetryDelay = TimeSpan.Zero };

    private static IConfiguration Config(Dictionary<string, string?> values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    private static Dictionary<string, string?> CompleteSmtp() => new()
    {
        [$"{AuthEmailSettings.SectionPath}:smtpHost"] = "smtp.example.com",
        [$"{AuthEmailSettings.SectionPath}:smtpPort"] = "465",
        [$"{AuthEmailSettings.SectionPath}:username"] = "mailer@example.com",
        [$"{AuthEmailSettings.SectionPath}:password"] = "p@ss-not-logged",
        [$"{AuthEmailSettings.SectionPath}:from"] = "mailer@example.com",
    };

    // ---- settings -------------------------------------------------------------------------------------

    [Test]
    public void Settings_Complete_LoadFromVaultNotificationsFormat()
    {
        var s = AuthEmailSettings.Load(Config(CompleteSmtp()), out var problems);

        Assert.That(s, Is.EqualTo(new AuthEmailSettings("smtp.example.com", 465, "mailer@example.com", "p@ss-not-logged", "mailer@example.com")));
        Assert.That(problems, Is.Empty);
        Assert.That(s!.ToString(), Does.Not.Contain("p@ss-not-logged"));
    }

    [Test]
    public void Settings_Absent_IsNullWithoutProblems()
    {
        Assert.That(AuthEmailSettings.Load(Config(new()), out var problems), Is.Null);
        Assert.That(problems, Is.Empty);
    }

    [Test]
    public void Settings_Partial_IsNullAndNamesTheMissingFields()
    {
        var values = CompleteSmtp();
        values.Remove($"{AuthEmailSettings.SectionPath}:password");
        values.Remove($"{AuthEmailSettings.SectionPath}:from");

        Assert.That(AuthEmailSettings.Load(Config(values), out var problems), Is.Null);
        Assert.That(problems.Single(), Does.Contain("password").And.Contain("from").And.Not.Contain("smtpHost"));
    }

    [TestCase("abc")]
    [TestCase("0")]
    [TestCase("70000")]
    public void Settings_UnusablePort_FallsBackTo587(string port)
    {
        var values = CompleteSmtp();
        values[$"{AuthEmailSettings.SectionPath}:smtpPort"] = port;
        Assert.That(AuthEmailSettings.Load(Config(values), out _)!.SmtpPort, Is.EqualTo(587));
    }

    // ---- sender ---------------------------------------------------------------------------------------

    [Test]
    public async Task PasswordReset_IsDeliveredWithLinkRecipientAndSender()
    {
        var transport = new FakeTransport();
        var logs = new CapturingLoggerProvider();
        var sender = NewSender(transport, logs);
        await sender.StartAsync(CancellationToken.None);

        await sender.SendPasswordResetAsync("alice@example.com", Link);
        await sender.StopAsync(CancellationToken.None);   // drains the queue

        var mail = transport.Sent.Single();
        Assert.That(mail.To.Mailboxes.Single().Address, Is.EqualTo("alice@example.com"));
        Assert.That(mail.From.Mailboxes.Single().Address, Is.EqualTo("mailer@example.com"));
        Assert.That(mail.Subject, Does.Contain("Ideas").And.Contain("reset"));
        Assert.That(mail.TextBody, Does.Contain(Link).And.Contain("15 minutes"));
    }

    [Test]
    public async Task SecurityAlert_IsDeliveredWithAppPrefixedSubject()
    {
        var transport = new FakeTransport();
        var sender = NewSender(transport, new CapturingLoggerProvider());
        await sender.StartAsync(CancellationToken.None);

        await sender.SendSecurityAlertAsync("bob@example.com", "New sign-in", "A new device signed in.");
        await sender.StopAsync(CancellationToken.None);

        var mail = transport.Sent.Single();
        Assert.That(mail.Subject, Is.EqualTo("Ideas: New sign-in"));
        Assert.That(mail.TextBody, Is.EqualTo("A new device signed in."));
    }

    [Test]
    public async Task Send_ReturnsImmediately_WithoutWaitingOnSmtp()
    {
        // Enumeration safety: the reset request path must not wait on (or be slowed by) the SMTP round-trip.
        var transport = new FakeTransport { Gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously) };
        var sender = NewSender(transport, new CapturingLoggerProvider());
        await sender.StartAsync(CancellationToken.None);

        var send = sender.SendPasswordResetAsync("alice@example.com", Link);

        Assert.That(send.IsCompletedSuccessfully, Is.True);
        Assert.That(transport.Sent, Is.Empty);
        transport.Gate.SetResult();
        await sender.StopAsync(CancellationToken.None);
        Assert.That(transport.Sent, Has.Count.EqualTo(1));
    }

    [Test]
    public async Task TransientFailure_IsRetried_ThenDelivered()
    {
        var transport = new FakeTransport { FailFirst = 2 };
        var sender = NewSender(transport, new CapturingLoggerProvider());
        await sender.StartAsync(CancellationToken.None);

        await sender.SendPasswordResetAsync("alice@example.com", Link);
        await sender.StopAsync(CancellationToken.None);

        Assert.That(transport.Attempts, Is.EqualTo(3));
        Assert.That(transport.Sent, Has.Count.EqualTo(1));
    }

    [Test]
    public async Task PermanentFailure_NeverThrowsToCaller_AndNeverLogsTheLinkOrPassword()
    {
        var transport = new FakeTransport { FailFirst = int.MaxValue };
        var logs = new CapturingLoggerProvider();
        var sender = NewSender(transport, logs);
        await sender.StartAsync(CancellationToken.None);

        Assert.DoesNotThrowAsync(() => sender.SendPasswordResetAsync("alice@example.com", Link));
        await sender.StopAsync(CancellationToken.None);

        Assert.That(transport.Attempts, Is.EqualTo(SmtpAuthEmailSender.MaxAttempts));
        Assert.That(transport.Sent, Is.Empty);
        Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Error && e.Text.Contains("FAILED")), Is.True);
        Assert.That(logs.AllText, Does.Not.Contain("SECRET-TOKEN-VALUE"));
        Assert.That(logs.AllText, Does.Not.Contain("p@ss-not-logged"));
        Assert.That(logs.AllText, Does.Not.Contain("alice@example.com"));   // masked: a***@example.com
    }

    [Test]
    public async Task InvalidRecipient_IsDroppedWithoutThrowing()
    {
        var transport = new FakeTransport();
        var logs = new CapturingLoggerProvider();
        var sender = NewSender(transport, logs);
        await sender.StartAsync(CancellationToken.None);

        Assert.DoesNotThrowAsync(() => sender.SendPasswordResetAsync("not an address", Link));
        await sender.StopAsync(CancellationToken.None);

        Assert.That(transport.Sent, Is.Empty);
        Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Error), Is.True);
    }

    // ---- registration ---------------------------------------------------------------------------------

    private static (ServiceProvider Sp, CapturingLoggerProvider Logs) Services(
        Dictionary<string, string?> config, Action<IServiceCollection>? before = null, string publicBaseUrl = "https://ideas.example.com")
    {
        var logs = new CapturingLoggerProvider();
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(logs));
        services.AddOptions<AuthResetOptions>().Configure(o => o.PublicBaseUrl = publicBaseUrl);
        before?.Invoke(services);
        services.AddMindAtticAuthEmail(Config(config), "Ideas");
        return (services.BuildServiceProvider(), logs);
    }

    private static async Task StartHostedAsync(IServiceProvider sp)
    {
        foreach (var h in sp.GetServices<IHostedService>()) await h.StartAsync(CancellationToken.None);
    }

    private static async Task StopHostedAsync(IServiceProvider sp)
    {
        foreach (var h in sp.GetServices<IHostedService>()) await h.StopAsync(CancellationToken.None);
    }

    [Test]
    public async Task Registration_NoSmtpConfigured_FallsBackToLogging_AndWarnsLoudlyAtStartup()
    {
        var (sp, logs) = Services(new());

        Assert.That(sp.GetRequiredService<IAuthEmailSender>(), Is.TypeOf<LoggingAuthEmailSender>());
        await StartHostedAsync(sp);

        var warning = logs.Entries.Single(e => e.Level == LogLevel.Warning);
        Assert.That(warning.Text, Does.Contain("will NOT be delivered").And.Contain(AuthEmailSettings.SectionPath));
    }

    [Test]
    public async Task Registration_PartialSmtp_FallsBackAndTheWarningNamesWhatIsMissing()
    {
        var values = CompleteSmtp();
        values.Remove($"{AuthEmailSettings.SectionPath}:password");
        var (sp, logs) = Services(values);

        Assert.That(sp.GetRequiredService<IAuthEmailSender>(), Is.TypeOf<LoggingAuthEmailSender>());
        await StartHostedAsync(sp);

        Assert.That(logs.Entries.Single(e => e.Level == LogLevel.Warning).Text, Does.Contain("missing: password"));
    }

    [Test]
    public async Task Registration_SmtpConfigured_UsesSmtpSender_AndDeliversThroughTheTransport()
    {
        var transport = new FakeTransport();
        var (sp, logs) = Services(CompleteSmtp(), s => s.AddSingleton<IAuthMailTransport>(transport));

        var sender = sp.GetRequiredService<IAuthEmailSender>();
        Assert.That(sender, Is.TypeOf<SmtpAuthEmailSender>());
        await StartHostedAsync(sp);
        await sender.SendPasswordResetAsync("alice@example.com", Link);
        await StopHostedAsync(sp);

        Assert.That(transport.Sent, Has.Count.EqualTo(1));
        Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Warning), Is.False);
        Assert.That(logs.AllText, Does.Contain("smtp.example.com:465").And.Not.Contain("p@ss-not-logged"));
    }

    [Test]
    public async Task Registration_SmtpConfigured_WithoutPublicBaseUrl_WarnsThatResetMailWillNotBeSent()
    {
        var (sp, logs) = Services(CompleteSmtp(), s => s.AddSingleton<IAuthMailTransport>(new FakeTransport()), publicBaseUrl: "");

        await StartHostedAsync(sp);
        await StopHostedAsync(sp);

        Assert.That(logs.Entries.Single(e => e.Level == LogLevel.Warning).Text, Does.Contain("PublicBaseUrl"));
    }

    [Test]
    public async Task RelativeResetLink_IsNotSent()
    {
        var transport = new FakeTransport();
        var logs = new CapturingLoggerProvider();
        var sender = NewSender(transport, logs);
        await sender.StartAsync(CancellationToken.None);

        await sender.SendPasswordResetAsync("alice@example.com", "/account/reset?token=SECRET-TOKEN-VALUE");
        await sender.StopAsync(CancellationToken.None);

        Assert.That(transport.Sent, Is.Empty);
        Assert.That(logs.Entries.Single(e => e.Level == LogLevel.Error).Text, Does.Contain("PublicBaseUrl"));
        Assert.That(logs.AllText, Does.Not.Contain("SECRET-TOKEN-VALUE"));
    }

    [Test]
    public void Registration_HostSenderWins()
    {
        var fake = new FakeEmailSender();
        var (sp, _) = Services(CompleteSmtp(), s => s.AddSingleton<IAuthEmailSender>(fake));

        Assert.That(sp.GetRequiredService<IAuthEmailSender>(), Is.SameAs(fake));
    }
}
