using Microsoft.Extensions.Logging;

namespace MindAttic.Authentication.Services;

/// <summary>
/// Transactional auth email (reset links, security alerts). <c>AddMindAtticAuthentication</c> picks the
/// implementation: <see cref="SmtpAuthEmailSender"/> when SMTP settings are configured
/// (<see cref="AuthEmailSettings.SectionPath"/>), otherwise the <see cref="LoggingAuthEmailSender"/> fallback
/// (with a startup warning). A host may register its own implementation instead.
/// </summary>
public interface IAuthEmailSender
{
    Task SendPasswordResetAsync(string toEmail, string resetLink, CancellationToken ct = default);
    Task SendSecurityAlertAsync(string toEmail, string subject, string body, CancellationToken ct = default);
}

/// <summary>Fallback sender used when no SMTP settings are configured — logs instead of sending, so dev works without email.</summary>
public sealed class LoggingAuthEmailSender(ILogger<LoggingAuthEmailSender> logger) : IAuthEmailSender
{
    public Task SendPasswordResetAsync(string toEmail, string resetLink, CancellationToken ct = default)
    {
        logger.LogWarning("[DEV EMAIL] Password reset for {Email}: {Link} — NOT delivered: configure SMTP at MindAttic:Vault:Notifications:email.", toEmail, resetLink);
        return Task.CompletedTask;
    }

    public Task SendSecurityAlertAsync(string toEmail, string subject, string body, CancellationToken ct = default)
    {
        logger.LogWarning("[DEV EMAIL] Security alert to {Email}: {Subject}", toEmail, subject);
        return Task.CompletedTask;
    }
}
