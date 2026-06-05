using Microsoft.Extensions.Logging;
using MindAttic.Authentication.Crypto;
using MindAttic.Authentication.Data;
using MindAttic.Authentication.Entities;
using MindAttic.Authentication.Secrets;

namespace MindAttic.Authentication.Services;

/// <summary>
/// First-run admin bootstrap. NO hardcoded default credentials: the initial admin's password is the
/// operator-provided Vault <c>Security:bootstrap-token</c> (≥12 chars), and the account is created with
/// MustChangePassword + MustEnrollMfa. Idempotent and race-safe (no-op if any user exists; a concurrent
/// double-seed is caught by the unique username index). After seeding, the operator MUST rotate the
/// bootstrap token in Vault (the app cannot write prod secrets).
/// </summary>
public sealed class AuthBootstrapper(
    IAuthDataContext db,
    IUserStore users,
    IPasswordHasher hasher,
    IAuthSecrets secrets,
    TimeProvider clock,
    ILogger<AuthBootstrapper> logger)
{
    public async Task SeedAdminAsync(string adminUserName = "admin", CancellationToken ct = default)
    {
        if (await users.AnyUsersAsync(ct)) return;   // idempotent

        var bootstrapPassword = secrets.GetRequired("bootstrap-token");   // fail-closed; operator-provided
        var hash = hasher.Hash(bootstrapPassword);
        var now = clock.GetUtcNow().UtcDateTime;

        db.AuthUsers.Add(new AuthUser
        {
            UserName = adminUserName,
            NormalizedUserName = IUserStore.Normalize(adminUserName),
            Role = MaRoles.Admin,
            PasswordHash = hash.Phc,
            PasswordPepperKeyId = hash.PepperKeyId,
            PasswordUpdatedUtc = now,
            MustChangePassword = true,
            MustEnrollMfa = true,
            IsActive = true,
            CreatedUtc = now,
        });

        try
        {
            await db.SaveChangesAsync(ct);
            logger.LogWarning("Seeded bootstrap admin '{User}'. ROTATE the Vault Security:bootstrap-token now — " +
                              "it is the initial password and a standing backdoor until rotated.", adminUserName);
        }
        catch (Exception ex)
        {
            // Concurrent instance already seeded (unique username index) — benign.
            logger.LogInformation(ex, "Bootstrap admin seed skipped (already present / concurrent seed).");
        }
    }
}
