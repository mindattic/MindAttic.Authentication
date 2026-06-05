using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MindAttic.Authentication.Crypto;
using MindAttic.Authentication.Data;
using MindAttic.Authentication.Entities;
using MindAttic.Authentication.Options;
using MindAttic.Authentication.Secrets;

namespace MindAttic.Authentication.Services;

public readonly record struct ResetConfirmResult(bool Ok, string? Error);

public interface IPasswordResetService
{
    /// <summary>Always enumeration-safe: behaves identically whether or not the account exists.</summary>
    Task RequestAsync(string userNameOrEmail, string sourceIp, string userAgent, CancellationToken ct = default);
    Task<ResetConfirmResult> ConfirmAsync(string token, string newPassword, CancellationToken ct = default);
}

/// <summary>
/// Secure password reset. Tokens are 256-bit CSPRNG, single-use, short-lived, and stored only as an
/// HMAC-SHA256 (keyed by a Vault secret) — never plaintext. Requesting a reset is enumeration-safe and
/// rate-capped; confirming rotates the SecurityStamp, invalidates other tokens, and does NOT auto-login
/// (so the next sign-in still goes through MFA).
/// </summary>
public sealed class PasswordResetService(
    IUserStore users,
    IAuthDataContext db,
    IPasswordHasher hasher,
    IPasswordPolicy policy,
    IAuthSecrets secrets,
    IAuthEmailSender email,
    IAuthAuditWriter audit,
    IOptions<AuthResetOptions> resetOptions,
    TimeProvider clock) : IPasswordResetService
{
    private readonly AuthResetOptions _o = resetOptions.Value;

    public async Task RequestAsync(string userNameOrEmail, string sourceIp, string userAgent, CancellationToken ct = default)
    {
        var now = clock.GetUtcNow().UtcDateTime;
        var user = await users.FindByUserNameAsync(userNameOrEmail, ct)
                   ?? await FindByEmailAsync(userNameOrEmail, ct);

        // Always audit; never reveal existence.
        await audit.WriteAsync(new AuthAuditEntry(AuthEventType.PasswordReset, AuthOutcome.Success, AuthReasonCode.Ok,
            user?.Id, userNameOrEmail, userNameOrEmail, sourceIp, userAgent), ct);

        if (user is null || !user.IsActive || string.IsNullOrWhiteSpace(user.Email)) return;

        // Per-account hourly cap.
        var since = now.AddHours(-1);
        var recent = await db.AuthPasswordResetTokens.CountAsync(t => t.UserId == user.Id && t.CreatedUtc >= since, ct);
        if (recent >= _o.MaxEmailsPerHour) return;

        var token = Base64Url(RandomNumberGenerator.GetBytes(32));   // 256-bit
        db.AuthPasswordResetTokens.Add(new AuthPasswordResetToken
        {
            UserId = user.Id,
            TokenHash = HashToken(token),
            CreatedUtc = now,
            ExpiresUtc = now.AddMinutes(_o.TokenTtlMinutes),
            RequestIp = Internal.AuthKeys.CanonicalizeIp(sourceIp),
            RequestUserAgent = Trunc(userAgent, 512),
        });
        await db.SaveChangesAsync(ct);

        var link = $"{_o.PublicBaseUrl.TrimEnd('/')}{_o.ResetPath}?token={Uri.EscapeDataString(token)}";
        await email.SendPasswordResetAsync(user.Email!, link, ct);
    }

    public async Task<ResetConfirmResult> ConfirmAsync(string token, string newPassword, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(token)) return new(false, "This reset link is invalid or has expired.");
        var now = clock.GetUtcNow().UtcDateTime;
        var hash = HashToken(token);

        var row = await db.AuthPasswordResetTokens
            .FirstOrDefaultAsync(t => t.TokenHash == hash && t.ConsumedUtc == null && t.ExpiresUtc > now, ct);
        if (row is null) return new(false, "This reset link is invalid or has expired.");

        var user = await users.FindByIdAsync(row.UserId, ct);
        if (user is null || !user.IsActive) return new(false, "This reset link is invalid or has expired.");

        var policyResult = await policy.ValidateAsync(newPassword, user.Id, ct);
        if (!policyResult.Ok) return new(false, policyResult.Reason);

        // History push + rehash + stamp rotation.
        db.AuthPasswordHistory.Add(new AuthPasswordHistory
        {
            UserId = user.Id, PasswordHash = user.PasswordHash, PepperKeyId = user.PasswordPepperKeyId, CreatedUtc = now,
        });
        var newHash = hasher.Hash(newPassword);
        user.PasswordHash = newHash.Phc;
        user.PasswordPepperKeyId = newHash.PepperKeyId;
        user.LegacyHashScheme = null;
        user.PasswordUpdatedUtc = now;
        user.MustChangePassword = false;
        user.SecurityStamp = Guid.NewGuid().ToString("N");

        // Consume this token + invalidate all other outstanding tokens for the user.
        row.ConsumedUtc = now;
        var others = await db.AuthPasswordResetTokens
            .Where(t => t.UserId == user.Id && t.ConsumedUtc == null && t.Id != row.Id)
            .ToListAsync(ct);
        foreach (var o in others) o.ConsumedUtc = now;

        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuthAuditEntry(AuthEventType.PasswordReset, AuthOutcome.Success, AuthReasonCode.Ok,
            user.Id, user.UserName), ct);
        return new(true, null);   // NOTE: no auto-login — user signs in fresh (→ MFA).
    }

    private async Task<AuthUser?> FindByEmailAsync(string email, CancellationToken ct)
    {
        var normalized = (email ?? "").Normalize(NormalizationForm.FormKC).Trim().ToUpperInvariant();
        return await db.AuthUsers.FirstOrDefaultAsync(u => u.NormalizedEmail == normalized, ct);
    }

    private string HashToken(string token)
    {
        var key = secrets.GetRequiredBytes("reset-token-key");
        try
        {
            using var hmac = new HMACSHA256(key);
            return Convert.ToHexStringLower(hmac.ComputeHash(Encoding.UTF8.GetBytes(token)));
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private static string Trunc(string? s, int max) => string.IsNullOrEmpty(s) ? "" : (s.Length <= max ? s : s[..max]);

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
