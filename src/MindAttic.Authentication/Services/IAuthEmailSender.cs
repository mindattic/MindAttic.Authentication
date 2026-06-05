using Microsoft.Extensions.Logging;

namespace MindAttic.Authentication.Services;

/// <summary>
/// Transactional auth email (reset links, security alerts). The host wires a real implementation — on
/// Windows hosts a MindAttic.Psst-backed adapter (email channel; SMS off). The library ships only the
/// logging fallback below so dev works without email configured.
/// </summary>
public interface IAuthEmailSender
{
    Task SendPasswordResetAsync(string toEmail, string resetLink, CancellationToken ct = default);
    Task SendSecurityAlertAsync(string toEmail, string subject, string body, CancellationToken ct = default);
}

/// <summary>Dev/fallback sender — logs instead of sending. Replace in the host with a Psst/SMTP adapter.</summary>
public sealed class LoggingAuthEmailSender(ILogger<LoggingAuthEmailSender> logger) : IAuthEmailSender
{
    public Task SendPasswordResetAsync(string toEmail, string resetLink, CancellationToken ct = default)
    {
        logger.LogWarning("[DEV EMAIL] Password reset for {Email}: {Link} — configure a real IAuthEmailSender (Psst).", toEmail, resetLink);
        return Task.CompletedTask;
    }

    public Task SendSecurityAlertAsync(string toEmail, string subject, string body, CancellationToken ct = default)
    {
        logger.LogWarning("[DEV EMAIL] Security alert to {Email}: {Subject}", toEmail, subject);
        return Task.CompletedTask;
    }
}
