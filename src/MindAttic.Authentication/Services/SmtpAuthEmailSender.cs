using System.Threading.Channels;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MimeKit;
using MindAttic.Authentication.Options;

namespace MindAttic.Authentication.Services;

/// <summary>Delivers one fully-built message. The seam that lets tests run the sender without a mail server.</summary>
public interface IAuthMailTransport
{
    Task SendAsync(MimeMessage message, CancellationToken ct);
}

/// <summary>
/// SMTP transport over MailKit (same library and TLS rule as MindAttic.Psst): port 465 is implicit TLS,
/// every other port requires STARTTLS — credentials never cross the wire in clear text. One connection per
/// message; auth email volume is tiny and a fresh session avoids reusing a server-dropped socket.
/// </summary>
public sealed class MailKitAuthMailTransport(AuthEmailSettings settings) : IAuthMailTransport
{
    public async Task SendAsync(MimeMessage message, CancellationToken ct)
    {
        using var smtp = new SmtpClient { Timeout = 30_000 };
        var secure = settings.SmtpPort == 465 ? SecureSocketOptions.SslOnConnect : SecureSocketOptions.StartTls;
        await smtp.ConnectAsync(settings.SmtpHost, settings.SmtpPort, secure, ct);
        await smtp.AuthenticateAsync(settings.Username, settings.Password, ct);
        await smtp.SendAsync(message, ct);
        await smtp.DisconnectAsync(quit: true, ct);
    }
}

/// <summary>
/// The real <see cref="IAuthEmailSender"/>: builds the reset / alert message and hands it to a background
/// queue that delivers it through <see cref="IAuthMailTransport"/> (up to 3 attempts, backing off).
/// <para>
/// Sending is <b>queued, never inline</b>: <see cref="IPasswordResetService.RequestAsync"/> must take the
/// same time and never throw whether or not the account exists, and an SMTP round-trip (or an SMTP failure)
/// on the known-account path would break that. A delivery failure is logged — never the link, which is a
/// bearer credential — and never surfaces to the caller.
/// </para>
/// Registered automatically by <c>AddMindAtticAuthentication</c> when <see cref="AuthEmailSettings"/> is
/// complete; started and drained by the library's hosted service.
/// </summary>
public sealed class SmtpAuthEmailSender : BackgroundService, IAuthEmailSender
{
    public const int QueueCapacity = 256;
    public const int MaxAttempts = 3;

    private readonly IAuthMailTransport _transport;
    private readonly MailboxAddress _from;
    private readonly string _appName;
    private readonly int _ttlMinutes;
    private readonly ILogger<SmtpAuthEmailSender> _logger;
    private readonly Channel<(MimeMessage Message, string Kind)> _queue =
        Channel.CreateBounded<(MimeMessage, string)>(new BoundedChannelOptions(QueueCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
        });

    /// <summary>Delay before retry n is <c>RetryDelay × n</c>. Settable so tests don't wait.</summary>
    public TimeSpan RetryDelay { get; init; } = TimeSpan.FromSeconds(2);

    public SmtpAuthEmailSender(
        IAuthMailTransport transport,
        AuthEmailSettings settings,
        IOptions<AuthResetOptions> resetOptions,
        ILogger<SmtpAuthEmailSender> logger,
        string appName = "MindAttic")
    {
        _transport = transport;
        _from = MailboxAddress.Parse(settings.From);   // a malformed From is a config error: fail at startup
        _ttlMinutes = resetOptions.Value.TokenTtlMinutes;
        _logger = logger;
        _appName = string.IsNullOrWhiteSpace(appName) ? "MindAttic" : appName;
    }

    public Task SendPasswordResetAsync(string toEmail, string resetLink, CancellationToken ct = default)
    {
        if (!Uri.TryCreate(resetLink, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
        {
            // A relative link is useless in an inbox: PublicBaseUrl was never configured.
            _logger.LogError("Auth email (password-reset) not sent: the reset link is not an absolute http(s) URL. " +
                             "Set MindAttic:Auth:Reset:PublicBaseUrl (e.g. https://app.example.com).");
            return Task.CompletedTask;
        }
        var body =
            $"Someone asked to reset the password for your {_appName} account.\n\n" +
            $"Reset it here (the link works once and expires in {_ttlMinutes} minutes):\n{resetLink}\n\n" +
            "If you didn't ask for this, ignore this email; your password has not changed.\n";
        Enqueue(toEmail, $"{_appName}: reset your password", body, "password-reset");
        return Task.CompletedTask;
    }

    public Task SendSecurityAlertAsync(string toEmail, string subject, string body, CancellationToken ct = default)
    {
        Enqueue(toEmail, $"{_appName}: {subject}", body, "security-alert");
        return Task.CompletedTask;
    }

    private void Enqueue(string toEmail, string subject, string body, string kind)
    {
        if (!MailboxAddress.TryParse(toEmail, out var to))
        {
            _logger.LogError("Auth email ({Kind}) not sent: recipient address is not valid.", kind);
            return;
        }

        var message = new MimeMessage();
        message.From.Add(_from);
        message.To.Add(to);
        message.Subject = subject;
        message.Body = new TextPart("plain") { Text = body };

        if (!_queue.Writer.TryWrite((message, kind)))
            _logger.LogError("Auth email ({Kind}) to {Recipient} dropped: the send queue is full or stopped.", kind, Mask(toEmail));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Read until the writer is completed (StopAsync), so queued mail drains on shutdown.
        while (await _queue.Reader.WaitToReadAsync(CancellationToken.None))
        {
            while (_queue.Reader.TryRead(out var item))
            {
                if (stoppingToken.IsCancellationRequested) return;
                await DeliverAsync(item.Message, item.Kind, stoppingToken);
            }
        }
    }

    private async Task DeliverAsync(MimeMessage message, string kind, CancellationToken ct)
    {
        var recipient = Mask(message.To.Mailboxes.FirstOrDefault()?.Address ?? "");
        for (var attempt = 1; attempt <= MaxAttempts; attempt++)
        {
            try
            {
                await _transport.SendAsync(message, ct);
                _logger.LogInformation("Auth email ({Kind}) delivered to {Recipient}.", kind, recipient);
                return;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                if (attempt == MaxAttempts)
                {
                    _logger.LogError(ex, "Auth email ({Kind}) to {Recipient} FAILED after {Attempts} attempts.",
                        kind, recipient, MaxAttempts);
                    return;
                }
                _logger.LogWarning("Auth email ({Kind}) to {Recipient} attempt {Attempt} failed: {Error}",
                    kind, recipient, attempt, ex.Message);
                try { await Task.Delay(RetryDelay * attempt, ct); }
                catch (OperationCanceledException) { return; }
            }
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _queue.Writer.TryComplete();
        if (ExecuteTask is { } running)
        {
            // Give queued mail until the host's shutdown deadline to drain, then cancel.
            try { await running.WaitAsync(cancellationToken); }
            catch (OperationCanceledException) { }
        }
        await base.StopAsync(cancellationToken);
    }

    /// <summary>"alice@example.com" → "a***@example.com" for logs.</summary>
    internal static string Mask(string email)
    {
        var at = email.IndexOf('@');
        return at <= 0 ? "***" : $"{email[0]}***{email[at..]}";
    }
}
