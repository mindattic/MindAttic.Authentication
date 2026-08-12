using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MindAttic.Authentication.Crypto;
using MindAttic.Authentication.Data;
using MindAttic.Authentication.Options;

namespace MindAttic.Authentication.Services;

public readonly record struct PasswordPolicyResult(bool Ok, string? Reason)
{
    public static readonly PasswordPolicyResult Allowed = new(true, null);
    public static PasswordPolicyResult Reject(string reason) => new(false, reason);
}

public interface IPasswordPolicy
{
    /// <summary>Validate a candidate (length, breach corpus, reuse history). HIBP fails OPEN.</summary>
    Task<PasswordPolicyResult> ValidateAsync(string password, Guid? userId = null, CancellationToken ct = default);
}

/// <summary>
/// NIST-aligned policy: length only (no composition rules / no rotation), HIBP k-anonymity breach check
/// (fail-open online + bundled offline fallback + audited skip), and reuse-history rejection.
/// </summary>
public sealed class PasswordPolicy(
    IHttpClientFactory httpFactory,
    IOptions<AuthPolicyOptions> options,
    IAuthDataContext db,
    IPasswordHasher hasher,
    IAuthAuditWriter audit,
    ILogger<PasswordPolicy> logger) : IPasswordPolicy
{
    private readonly AuthPolicyOptions _o = options.Value;

    // Minimal bundled corpus for when HIBP is unreachable (worst-known passwords).
    private static readonly HashSet<string> OfflineWorst = new(StringComparer.OrdinalIgnoreCase)
    {
        "password","123456","123456789","12345678","12345","1234567","qwerty","abc123","password1",
        "111111","123123","admin","letmein","welcome","iloveyou","monkey","dragon","sunshine",
        "princess","qwerty123","000000","passw0rd","login","starwars","changeme","trustno1",
    };

    public async Task<PasswordPolicyResult> ValidateAsync(string password, Guid? userId = null, CancellationToken ct = default)
    {
        if (password is null) return PasswordPolicyResult.Reject("Password is required.");
        var normalized = password.Normalize(NormalizationForm.FormKC);
        if (normalized.Length < _o.MinLength) return PasswordPolicyResult.Reject($"Password must be at least {_o.MinLength} characters.");
        if (normalized.Length > _o.MaxLength) return PasswordPolicyResult.Reject($"Password must be at most {_o.MaxLength} characters.");

        if (OfflineWorst.Contains(normalized.Trim()))
            return PasswordPolicyResult.Reject("That password is too common.");

        if (_o.CheckHibp)
        {
            var breach = await CheckHibpAsync(normalized, ct);
            if (breach == HibpResult.Breached)
                return PasswordPolicyResult.Reject("That password has appeared in a known data breach.");
            // HibpResult.Skipped → fail-open (already passed the offline corpus); audited inside CheckHibpAsync.
        }

        if (userId is { } id && _o.HistoryDepth > 0 && await IsReusedAsync(id, password, ct))
            return PasswordPolicyResult.Reject($"You can't reuse one of your last {_o.HistoryDepth} passwords.");

        return PasswordPolicyResult.Allowed;
    }

    private enum HibpResult { NotBreached, Breached, Skipped }

    private async Task<HibpResult> CheckHibpAsync(string normalizedPassword, CancellationToken ct)
    {
        try
        {
            var sha1 = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(normalizedPassword)));
            var prefix = sha1[..5];
            var suffix = sha1[5..];

            var client = httpFactory.CreateClient(AuthPolicyOptions.HibpHttpClient);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(_o.HibpTimeoutMs);

            using var req = new HttpRequestMessage(HttpMethod.Get, _o.HibpRangeBaseUrl + prefix);
            req.Headers.Add("Add-Padding", "true");
            using var resp = await client.SendAsync(req, cts.Token);
            resp.EnsureSuccessStatusCode();
            var body = await resp.Content.ReadAsStringAsync(cts.Token);

            foreach (var line in body.Split('\n'))
            {
                var sep = line.IndexOf(':');
                if (sep <= 0) continue;
                if (line.AsSpan(0, sep).Trim().Equals(suffix, StringComparison.OrdinalIgnoreCase))
                {
                    var countSpan = line.AsSpan(sep + 1).Trim();
                    return long.TryParse(countSpan, out var c) && c > 0 ? HibpResult.Breached : HibpResult.NotBreached;
                }
            }
            return HibpResult.NotBreached;
        }
        catch (Exception ex) when (_o.HibpFailOpen)
        {
            logger.LogWarning(ex, "HIBP breach check unavailable; failing open (offline corpus already applied).");
            await audit.WriteAsync(new AuthAuditEntry(
                Entities.AuthEventType.HibpOnlineSkipped, Entities.AuthOutcome.Success, Entities.AuthReasonCode.Ok), ct);
            return HibpResult.Skipped;
        }
    }

    private async Task<bool> IsReusedAsync(Guid userId, string password, CancellationToken ct)
    {
        var recent = await db.AuthPasswordHistory.AsNoTracking()
            .Where(h => h.UserId == userId)
            .OrderByDescending(h => h.CreatedUtc)
            .Take(_o.HistoryDepth)
            .ToListAsync(ct);
        foreach (var h in recent)
            if (hasher.Verify(password, h.PasswordHash, h.PepperKeyId, null).Succeeded)
                return true;
        return false;
    }
}
