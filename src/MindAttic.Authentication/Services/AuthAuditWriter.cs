using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using MindAttic.Authentication.Data;
using MindAttic.Authentication.Entities;
using MindAttic.Authentication.Internal;

namespace MindAttic.Authentication.Services;

/// <summary>One auditable auth event. Raw account/IP are hashed/canonicalized before storage.</summary>
public sealed record AuthAuditEntry(
    AuthEventType EventType,
    AuthOutcome Outcome,
    AuthReasonCode Reason,
    Guid? UserId = null,
    string? UserNameAttempted = null,
    string? AccountKeyRaw = null,
    string? SourceIpRaw = null,
    string? UserAgent = null,
    bool CaptchaPresented = false);

public interface IAuthAuditWriter
{
    Task WriteAsync(AuthAuditEntry entry, CancellationToken ct = default);
}

/// <summary>
/// Writes every auth attempt (success + failure) to <c>AuthAuditLog</c> on a FRESH scope, so an audit
/// write never participates in (or corrupts) the login transaction. Reason codes are server-only; the
/// user-agent is sanitized (log-injection safe). An audit-write failure is logged but never breaks auth.
/// </summary>
public sealed class AuthAuditWriter(IServiceScopeFactory scopeFactory, TimeProvider clock, ILogger<AuthAuditWriter> logger)
    : IAuthAuditWriter
{
    public async Task WriteAsync(AuthAuditEntry e, CancellationToken ct = default)
    {
        try
        {
            using var scope = scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<IAuthDataContext>();
            db.AuthAuditLog.Add(new AuthAuditLog
            {
                TimestampUtc = clock.GetUtcNow().UtcDateTime,
                UserId = e.UserId,
                UserNameAttempted = Truncate(e.UserNameAttempted, 256),
                EventType = e.EventType,
                Outcome = e.Outcome,
                ReasonCode = e.Reason,
                AccountKeyHash = string.IsNullOrWhiteSpace(e.AccountKeyRaw)
                    ? null
                    : AuthKeys.Hash(AuthKeys.NormalizeAccount(e.AccountKeyRaw!)),
                SourceIp = AuthKeys.CanonicalizeIp(e.SourceIpRaw),
                UserAgent = Sanitize(e.UserAgent),
                CaptchaPresented = e.CaptchaPresented,
            });
            await db.SaveChangesAsync(ct);
        }
        catch (Exception ex)
        {
            // Never let an audit failure break authentication; surface it to ops instead.
            logger.LogError(ex, "Failed to write auth audit event {EventType}/{Outcome}", e.EventType, e.Outcome);
        }
    }

    private static string? Truncate(string? s, int max) =>
        string.IsNullOrEmpty(s) ? s : (s.Length <= max ? s : s[..max]);

    private static string Sanitize(string? ua)
    {
        var s = (ua ?? "").Replace('\n', ' ').Replace('\r', ' ').Replace('\0', ' ');
        return s.Length <= 512 ? s : s[..512];
    }
}
