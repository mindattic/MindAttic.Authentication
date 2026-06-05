using Microsoft.EntityFrameworkCore;
using MindAttic.Authentication.Entities;

namespace MindAttic.Authentication.Data;

/// <summary>
/// Applies the canonical MindAttic.Authentication EF model (all tables in the <c>auth</c> schema, no FKs
/// into app tables). Each consuming app calls this from its <c>DbContext.OnModelCreating</c> and runs its
/// own migration. The library embeds a model fingerprint (<see cref="ModelFingerprint"/>) so a host can
/// fail-fast on a stale migration.
/// </summary>
public static class AuthModel
{
    public const string DefaultSchema = "auth";

    /// <summary>Bumped whenever the auth EF model changes; hosts assert their migration matches.</summary>
    public const string ModelFingerprint = "auth-v1";

    public static ModelBuilder ApplyMindAtticAuthConfiguration(this ModelBuilder b, string schema = DefaultSchema)
    {
        b.Entity<AuthUser>(e =>
        {
            e.ToTable("AuthUsers", schema);
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.NormalizedUserName).IsUnique();
            e.HasIndex(x => x.NormalizedEmail);
            e.Property(x => x.UserName).HasMaxLength(256).IsRequired();
            e.Property(x => x.NormalizedUserName).HasMaxLength(256).IsRequired();
            e.Property(x => x.Email).HasMaxLength(256);
            e.Property(x => x.NormalizedEmail).HasMaxLength(256);
            e.Property(x => x.PasswordHash).HasMaxLength(512).IsRequired();
            e.Property(x => x.PasswordPepperKeyId).HasMaxLength(16);
            e.Property(x => x.LegacyHashScheme).HasMaxLength(16);
            e.Property(x => x.SecurityStamp).HasMaxLength(64).IsRequired();
            e.Property(x => x.Role).HasMaxLength(64).IsRequired();
            e.Property(x => x.RowVersion).IsRowVersion();
        });

        b.Entity<AuthUserMfa>(e =>
        {
            e.ToTable("AuthUserMfa", schema);
            e.HasKey(x => x.UserId);
            e.Property(x => x.SecretEncrypted).HasMaxLength(512);
            e.Property(x => x.PendingSecretEncrypted).HasMaxLength(512);
            e.Property(x => x.RowVersion).IsRowVersion();
            e.HasOne<AuthUser>().WithOne().HasForeignKey<AuthUserMfa>(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<AuthRecoveryCode>(e =>
        {
            e.ToTable("AuthRecoveryCodes", schema);
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.UserId);
            e.Property(x => x.CodeHash).HasMaxLength(512).IsRequired();
            e.Property(x => x.CodePepperKeyId).HasMaxLength(16);
            e.HasOne<AuthUser>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<AuthSession>(e =>
        {
            e.ToTable("AuthSessions", schema);
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.AuthUserId);
            e.Property(x => x.IpHash).HasMaxLength(64).IsFixedLength().IsRequired();
            e.Property(x => x.UserAgent).HasMaxLength(512).IsRequired();
            e.Property(x => x.RevokedReason).HasMaxLength(64);
            e.HasOne<AuthUser>().WithMany().HasForeignKey(x => x.AuthUserId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<AuthLoginThrottle>(e =>
        {
            e.ToTable("AuthLoginThrottles", schema);
            e.HasKey(x => x.Id);
            e.HasIndex(x => new { x.Scope, x.KeyHash }).IsUnique();
            e.Property(x => x.KeyHash).HasMaxLength(32).IsFixedLength().IsRequired();
            e.Property(x => x.RowVersion).IsRowVersion();
        });

        b.Entity<AuthAuditLog>(e =>
        {
            e.ToTable("AuthAuditLog", schema);
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.TimestampUtc);
            e.HasIndex(x => x.AccountKeyHash);
            e.Property(x => x.UserNameAttempted).HasMaxLength(256);
            e.Property(x => x.AccountKeyHash).HasMaxLength(32).IsFixedLength();
            e.Property(x => x.SourceIp).HasMaxLength(45).IsRequired();
            e.Property(x => x.UserAgent).HasMaxLength(512).IsRequired();
        });

        b.Entity<AuthPasswordHistory>(e =>
        {
            e.ToTable("AuthPasswordHistory", schema);
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.UserId);
            e.Property(x => x.PasswordHash).HasMaxLength(512).IsRequired();
            e.Property(x => x.PepperKeyId).HasMaxLength(16);
            e.HasOne<AuthUser>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<AuthPasswordResetToken>(e =>
        {
            e.ToTable("AuthPasswordResetTokens", schema);
            e.HasKey(x => x.Id);
            e.HasIndex(x => new { x.UserId, x.ConsumedUtc });
            e.HasIndex(x => x.TokenHash).IsUnique();
            e.Property(x => x.TokenHash).HasMaxLength(64).IsFixedLength().IsRequired();
            e.Property(x => x.RequestIp).HasMaxLength(45).IsRequired();
            e.Property(x => x.RequestUserAgent).HasMaxLength(512).IsRequired();
            e.HasOne<AuthUser>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        return b;
    }
}
