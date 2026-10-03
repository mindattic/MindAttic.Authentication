using Microsoft.Extensions.Logging;
using MindAttic.Authentication.Entities;

namespace MindAttic.Authentication.Services;

/// <summary>The account events that send the owner a security-alert email.</summary>
public enum SecurityAlertKind
{
    /// <summary>The user changed their own password.</summary>
    PasswordChanged,
    /// <summary>The password was set through an emailed reset link.</summary>
    PasswordReset,
    /// <summary>An administrator set a new password for the account.</summary>
    PasswordResetByAdmin,
    /// <summary>Two-step verification (TOTP) was turned on, which also issues new recovery codes.</summary>
    MfaEnabled,
    /// <summary>A one-time recovery code was used to finish a sign-in.</summary>
    RecoveryCodeUsed,
    /// <summary>Repeated failed sign-ins put the account into back-off (sent once per run of failures).</summary>
    AccountLocked,
    /// <summary>A sign-in from a browser and network not seen on this account before.</summary>
    NewDeviceSignIn,
    /// <summary>The account's email address was changed (sent to the OLD address).</summary>
    EmailChanged,
    /// <summary>An administrator deactivated the account.</summary>
    AccountDeactivated,
}

/// <summary>Raises security-alert emails for account events. Best-effort: it never throws to the caller.</summary>
public interface IAuthSecurityAlerts
{
    /// <summary>Emails the account owner about <paramref name="kind"/> at <paramref name="toEmail"/> (defaults to the user's address).</summary>
    Task NotifyAsync(AuthUser user, SecurityAlertKind kind, string? userAgent = null, string? toEmail = null, CancellationToken ct = default);
}

/// <summary>
/// Default <see cref="IAuthSecurityAlerts"/>: builds a plain-text alert and hands it to
/// <see cref="IAuthEmailSender.SendSecurityAlertAsync"/>. Accounts without an email are skipped. The
/// message never contains a secret (no password, token, code or raw IP); it says what happened, when
/// (UTC), from which browser where relevant, and what to do if it was not the owner.
/// </summary>
public sealed class AuthSecurityAlerts(IAuthEmailSender email, TimeProvider clock, ILogger<AuthSecurityAlerts> logger)
    : IAuthSecurityAlerts
{
    public async Task NotifyAsync(AuthUser user, SecurityAlertKind kind, string? userAgent = null, string? toEmail = null, CancellationToken ct = default)
    {
        var to = toEmail ?? user.Email;
        if (string.IsNullOrWhiteSpace(to)) return;

        var (subject, what) = Describe(kind);
        var when = clock.GetUtcNow().UtcDateTime.ToString("yyyy-MM-dd HH:mm 'UTC'");
        var body =
            $"Hello {user.UserName},\n\n{what}\n\nWhen: {when}\n" +
            (string.IsNullOrWhiteSpace(userAgent) ? "" : $"Browser: {Trunc(userAgent.ReplaceLineEndings(" "), 200)}\n") +
            "\nIf this was you, no action is needed. If it was not, reset your password now and contact your administrator.\n";

        try
        {
            await email.SendSecurityAlertAsync(to, subject, body, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // An alert must never undo or fail the account change that triggered it.
            logger.LogError(ex, "Security alert ({Kind}) could not be queued.", kind);
        }
    }

    internal static (string Subject, string What) Describe(SecurityAlertKind kind) => kind switch
    {
        SecurityAlertKind.PasswordChanged => ("Your password was changed", "The password for your account was changed."),
        SecurityAlertKind.PasswordReset => ("Your password was reset", "The password for your account was reset using an emailed reset link."),
        SecurityAlertKind.PasswordResetByAdmin => ("Your password was reset by an administrator", "An administrator set a new password for your account."),
        SecurityAlertKind.MfaEnabled => ("Two-step verification was turned on", "Two-step verification was turned on for your account and new recovery codes were issued; older recovery codes no longer work."),
        SecurityAlertKind.RecoveryCodeUsed => ("A recovery code was used to sign in", "A one-time recovery code was used to sign in to your account."),
        SecurityAlertKind.AccountLocked => ("Repeated failed sign-ins", "Several sign-in attempts to your account failed in a row, so further attempts are being slowed down."),
        SecurityAlertKind.NewDeviceSignIn => ("New sign-in to your account", "Your account was signed in to from a browser and network it has not used before."),
        SecurityAlertKind.EmailChanged => ("Your email address was changed", "The email address on your account was changed. Security emails now go to the new address."),
        SecurityAlertKind.AccountDeactivated => ("Your account was deactivated", "An administrator deactivated your account. You can no longer sign in."),
        _ => ("Security alert", "A security-relevant change was made to your account."),
    };

    private static string Trunc(string s, int max) => s.Length <= max ? s : s[..max];
}
