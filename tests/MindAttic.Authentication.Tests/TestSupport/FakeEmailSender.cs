using MindAttic.Authentication.Services;

namespace MindAttic.Authentication.Tests.TestSupport;

/// <summary>Captures outbound auth emails so tests can assert what (if anything) was sent.</summary>
public sealed class FakeEmailSender : IAuthEmailSender
{
    public List<(string To, string Link)> Resets { get; } = new();
    public List<(string To, string Subject, string Body)> Alerts { get; } = new();

    public Task SendPasswordResetAsync(string toEmail, string resetLink, CancellationToken ct = default)
    {
        Resets.Add((toEmail, resetLink));
        return Task.CompletedTask;
    }

    public Task SendSecurityAlertAsync(string toEmail, string subject, string body, CancellationToken ct = default)
    {
        Alerts.Add((toEmail, subject, body));
        return Task.CompletedTask;
    }

    /// <summary>The reset token extracted from the most recent reset link's <c>?token=</c> query.</summary>
    public string LastResetToken()
    {
        var link = Resets[^1].Link;
        var marker = "?token=";
        var token = link[(link.IndexOf(marker, StringComparison.Ordinal) + marker.Length)..];
        return Uri.UnescapeDataString(token);
    }
}
