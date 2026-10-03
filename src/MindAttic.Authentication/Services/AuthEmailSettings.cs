using Microsoft.Extensions.Configuration;

namespace MindAttic.Authentication.Services;

/// <summary>
/// SMTP settings for <see cref="SmtpAuthEmailSender"/>, read from the MindAttic.Vault
/// <c>Notifications</c> credential format — the same shape MindAttic.Psst reads:
/// <code>
/// MindAttic:Vault:Notifications:email:
///   smtpHost: "smtp.example.com"
///   smtpPort: 587                  # 465 = implicit TLS, anything else = STARTTLS (required)
///   username: "mailer@example.com"
///   password: "app-password"
///   from:     "MindAttic &lt;mailer@example.com&gt;"
/// </code>
/// Dev: <c>%APPDATA%\MindAttic\Notifications\providers.json</c> surfaced by
/// <c>AddMindAtticVaultFiles</c> (the host must include the <c>Notifications</c> bucket). Prod: env vars
/// (<c>MindAttic__Vault__Notifications__email__smtpHost</c>, …) or Key Vault references.
/// </summary>
public sealed record AuthEmailSettings(string SmtpHost, int SmtpPort, string Username, string Password, string From)
{
    public const string SectionPath = "MindAttic:Vault:Notifications:email";
    public const int DefaultPort = 587;

    /// <summary>
    /// Reads the settings. Returns null when the section is absent (nothing configured — the library falls
    /// back to <see cref="LoggingAuthEmailSender"/>) or only partly filled; in the partial case
    /// <paramref name="problems"/> names the missing fields so the startup warning can say what to fix.
    /// An unusable port (unparseable, ≤0, &gt;65535) falls back to <see cref="DefaultPort"/>.
    /// </summary>
    public static AuthEmailSettings? Load(IConfiguration configuration, out IReadOnlyList<string> problems)
    {
        var s = configuration.GetSection(SectionPath);
        var host = s["smtpHost"];
        var user = s["username"];
        var pass = s["password"];
        var from = s["from"];

        var missing = new List<string>();
        if (string.IsNullOrWhiteSpace(host)) missing.Add("smtpHost");
        if (string.IsNullOrWhiteSpace(user)) missing.Add("username");
        if (string.IsNullOrWhiteSpace(pass)) missing.Add("password");
        if (string.IsNullOrWhiteSpace(from)) missing.Add("from");

        if (missing.Count == 4)
        {
            problems = [];
            return null;
        }
        if (missing.Count > 0)
        {
            problems = [$"{SectionPath} is partially configured — missing: {string.Join(", ", missing)}"];
            return null;
        }

        problems = [];
        var port = int.TryParse(s["smtpPort"], out var p) && p is > 0 and <= 65535 ? p : DefaultPort;
        return new AuthEmailSettings(host!.Trim(), port, user!.Trim(), pass!, from!.Trim());
    }

    /// <summary>Never print the password.</summary>
    public override string ToString() => $"{SmtpHost}:{SmtpPort} as {Username} from {From}";
}
