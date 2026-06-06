using Microsoft.EntityFrameworkCore;
using MindAttic.Authentication.Data;
using MindAttic.Authentication.Entities;

namespace MindAttic.Authentication.Tests.TestSupport;

/// <summary>
/// An EF Core in-memory <see cref="DbContext"/> that plays the role of a consuming app's context: it
/// applies the library's canonical model via <see cref="AuthModel.ApplyMindAtticAuthConfiguration"/> and
/// implements <see cref="IAuthDataContext"/> — exactly the seam the services operate over.
/// </summary>
public sealed class TestAuthDbContext(DbContextOptions<TestAuthDbContext> options)
    : DbContext(options), IAuthDataContext
{
    public DbSet<AuthUser> AuthUsers => Set<AuthUser>();
    public DbSet<AuthUserMfa> AuthUserMfa => Set<AuthUserMfa>();
    public DbSet<AuthRecoveryCode> AuthRecoveryCodes => Set<AuthRecoveryCode>();
    public DbSet<AuthSession> AuthSessions => Set<AuthSession>();
    public DbSet<AuthLoginThrottle> AuthLoginThrottles => Set<AuthLoginThrottle>();
    public DbSet<AuthAuditLog> AuthAuditLog => Set<AuthAuditLog>();
    public DbSet<AuthPasswordHistory> AuthPasswordHistory => Set<AuthPasswordHistory>();
    public DbSet<AuthPasswordResetToken> AuthPasswordResetTokens => Set<AuthPasswordResetToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder) =>
        modelBuilder.ApplyMindAtticAuthConfiguration();

    /// <summary>A fresh, isolated in-memory store (unique db name) per call.</summary>
    public static TestAuthDbContext NewInMemory()
    {
        var options = new DbContextOptionsBuilder<TestAuthDbContext>()
            .UseInMemoryDatabase($"auth-tests-{Guid.NewGuid():N}")
            .EnableSensitiveDataLogging()
            .Options;
        return new TestAuthDbContext(options);
    }
}
