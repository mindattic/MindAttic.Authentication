using Microsoft.EntityFrameworkCore;
using MindAttic.Authentication.Data;
using MindAttic.Authentication.Entities;
using MindAttic.Authentication.Internal;

namespace MindAttic.Authentication.Services;

/// <summary>Result of a throttle check.</summary>
/// <param name="Allowed">False ⇒ the caller is in backoff.</param>
/// <param name="RetryAfter">How long until the next attempt is allowed (when not allowed).</param>
public readonly record struct ThrottleDecision(bool Allowed, TimeSpan RetryAfter);

public interface IAccountLockoutService
{
    Task<ThrottleDecision> CheckAsync(ThrottleScope scope, string rawKey, CancellationToken ct = default);
    Task RecordFailureAsync(ThrottleScope scope, string rawKey, CancellationToken ct = default);
    Task ResetAsync(ThrottleScope scope, string rawKey, CancellationToken ct = default);
}

/// <summary>
/// Persistent (DB-backed) per-account AND per-IP brute-force defense with exponential backoff. Survives
/// restarts and is shared across instances — replaces all in-memory lockout. No hard permanent lockout
/// (DoS-safe, NIST 800-63B 5.2.2). Account counter resets only on full success.
/// </summary>
public sealed class AccountLockoutService(IAuthDataContext db, TimeProvider clock) : IAccountLockoutService
{
    // f<=3 → no wait; then 1,2,4,…s capped at 900s (15m).
    public static TimeSpan BackoffFor(int consecutiveFailures)
    {
        if (consecutiveFailures <= 3) return TimeSpan.Zero;
        var seconds = Math.Min(900d, Math.Pow(2, consecutiveFailures - 4));
        return TimeSpan.FromSeconds(seconds);
    }

    public async Task<ThrottleDecision> CheckAsync(ThrottleScope scope, string rawKey, CancellationToken ct = default)
    {
        var keyHash = KeyHash(scope, rawKey);
        var row = await db.AuthLoginThrottles.AsNoTracking()
            .FirstOrDefaultAsync(x => x.Scope == scope && x.KeyHash == keyHash, ct);
        var now = clock.GetUtcNow().UtcDateTime;
        if (row?.NextAttemptAllowedUtc is { } until && until > now)
            return new ThrottleDecision(false, until - now);
        return new ThrottleDecision(true, TimeSpan.Zero);
    }

    public async Task RecordFailureAsync(ThrottleScope scope, string rawKey, CancellationToken ct = default)
    {
        var keyHash = KeyHash(scope, rawKey);
        var now = clock.GetUtcNow().UtcDateTime;

        // One optimistic-concurrency retry covers the common cross-instance race.
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var row = await db.AuthLoginThrottles
                .FirstOrDefaultAsync(x => x.Scope == scope && x.KeyHash == keyHash, ct);
            if (row is null)
            {
                db.AuthLoginThrottles.Add(new AuthLoginThrottle
                {
                    Scope = scope, KeyHash = keyHash, ConsecutiveFailures = 1,
                    FirstFailureUtc = now, LastFailureUtc = now,
                    NextAttemptAllowedUtc = now + BackoffFor(1),
                });
            }
            else
            {
                row.ConsecutiveFailures++;
                row.LastFailureUtc = now;
                row.NextAttemptAllowedUtc = now + BackoffFor(row.ConsecutiveFailures);
            }
            try { await db.SaveChangesAsync(ct); return; }
            catch (DbUpdateConcurrencyException) { /* retry once */ }
            catch (DbUpdateException) when (attempt == 0) { /* unique-key race on insert; retry as update */ }
        }
    }

    public async Task ResetAsync(ThrottleScope scope, string rawKey, CancellationToken ct = default)
    {
        var keyHash = KeyHash(scope, rawKey);
        var row = await db.AuthLoginThrottles
            .FirstOrDefaultAsync(x => x.Scope == scope && x.KeyHash == keyHash, ct);
        if (row is null) return;
        db.AuthLoginThrottles.Remove(row);
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateConcurrencyException) { /* already gone / changed — benign */ }
    }

    private static byte[] KeyHash(ThrottleScope scope, string rawKey) =>
        AuthKeys.Hash(scope == ThrottleScope.Ip ? AuthKeys.CanonicalizeIp(rawKey) : AuthKeys.NormalizeAccount(rawKey));
}
