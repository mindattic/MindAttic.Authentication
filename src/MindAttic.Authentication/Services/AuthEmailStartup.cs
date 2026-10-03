using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MindAttic.Authentication.Services;

/// <summary>
/// Hosted service registered by <c>AddMindAtticAuthentication</c>. At startup it resolves the active
/// <see cref="IAuthEmailSender"/> and says, once and loudly, what will happen to auth email:
/// <list type="bullet">
/// <item><see cref="SmtpAuthEmailSender"/> → starts its delivery queue and logs the SMTP endpoint (no secrets);
/// warns if <c>MindAttic:Auth:Reset:PublicBaseUrl</c> is not absolute (reset emails are then not sent).</item>
/// <item><see cref="LoggingAuthEmailSender"/> → logs a <b>warning</b> that password-reset and security-alert
/// emails will NOT be delivered, naming the config section (and any missing fields) to fix it.</item>
/// <item>anything else → the host registered its own sender; logged as information.</item>
/// </list>
/// </summary>
public sealed class AuthEmailStartup(
    IServiceProvider services,
    AuthEmailStatus status,
    IOptions<MindAttic.Authentication.Options.AuthResetOptions> reset,
    ILogger<AuthEmailStartup> logger)
    : IHostedService
{
    private SmtpAuthEmailSender? _smtp;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var sender = services.GetRequiredService<IAuthEmailSender>();
        switch (sender)
        {
            case SmtpAuthEmailSender smtp:
                _smtp = smtp;
                await smtp.StartAsync(cancellationToken);
                logger.LogInformation("MindAttic.Authentication: auth email is delivered over SMTP ({Endpoint}).",
                    status.Settings?.ToString());
                if (!Uri.TryCreate(reset.Value.PublicBaseUrl, UriKind.Absolute, out _))
                    logger.LogWarning(
                        "MindAttic.Authentication: MindAttic:Auth:Reset:PublicBaseUrl is not set to an absolute URL — " +
                        "password-reset emails will NOT be sent (a reset link needs an absolute base URL).");
                break;

            case LoggingAuthEmailSender:
                logger.LogWarning(
                    "MindAttic.Authentication: NO EMAIL SENDER CONFIGURED — password-reset and security-alert " +
                    "emails will NOT be delivered (they are written to this log only). Configure SMTP under {Section} " +
                    "(smtpHost, smtpPort, username, password, from) or register your own IAuthEmailSender.{Problems}",
                    AuthEmailSettings.SectionPath,
                    status.Problems.Count == 0 ? "" : " Problem: " + string.Join("; ", status.Problems));
                break;

            default:
                logger.LogInformation("MindAttic.Authentication: auth email goes through the host's {Sender}.",
                    sender.GetType().FullName);
                break;
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) =>
        _smtp?.StopAsync(cancellationToken) ?? Task.CompletedTask;
}

/// <summary>What the library found in configuration: complete SMTP settings, or null plus why.</summary>
public sealed record AuthEmailStatus(AuthEmailSettings? Settings, IReadOnlyList<string> Problems)
{
    public static AuthEmailStatus From(IConfiguration configuration)
    {
        var settings = AuthEmailSettings.Load(configuration, out var problems);
        return new AuthEmailStatus(settings, problems);
    }
}