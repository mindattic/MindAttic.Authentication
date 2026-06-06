using MindAttic.Authentication.Entities;
using MindAttic.Authentication.Services;
using MindAttic.Authentication.Tests.TestSupport;

namespace MindAttic.Authentication.Tests.Services;

/// <summary>
/// Administrative user management. Security-relevant invariants: passwords go through policy + Argon2id and
/// are never stored raw; role/active changes rotate the SecurityStamp (so live sessions revalidate); and a
/// guard refuses to remove or deactivate the last active administrator (lock-out / privilege-loss defense).
/// </summary>
[TestFixture]
public sealed class UserAdminServiceTests
{
    private static (UserAdminService svc, TestAuthDbContext db, FakePasswordPolicy policy) New(PasswordPolicyResult? policyResult = null)
    {
        var db = TestAuthDbContext.NewInMemory();
        var policy = policyResult is { } r ? new FakePasswordPolicy(r) : new FakePasswordPolicy();
        var svc = new UserAdminService(db, Build.Hasher(), policy, new FakeAuditWriter(),
            FixedClock.At(new DateTimeOffset(2026, 6, 6, 12, 0, 0, TimeSpan.Zero)));
        return (svc, db, policy);
    }

    private static async Task<AuthUser> SeedAdmin(TestAuthDbContext db, string name = "root", bool active = true)
    {
        var hasher = Build.Hasher();
        var stored = hasher.Hash("Admin-Passphrase-1");
        var u = new AuthUser
        {
            UserName = name, NormalizedUserName = IUserStore.Normalize(name),
            PasswordHash = stored.Phc, PasswordPepperKeyId = stored.PepperKeyId,
            Role = MaRoles.Admin, IsActive = active, CreatedUtc = DateTime.UtcNow,
        };
        db.AuthUsers.Add(u);
        await db.SaveChangesAsync();
        return u;
    }

    [Test]
    public async Task Create_HashesPassword_AndNeverStoresRaw()
    {
        var (svc, db, _) = New();
        var result = await svc.CreateAsync("newuser", "new@example.com", "User", "Fresh-Passphrase-1");
        Assert.That(result.Ok, Is.True);
        var user = db.AuthUsers.Single(u => u.Id == result.UserId);
        Assert.That(user.PasswordHash, Does.StartWith("$argon2id$"));
        Assert.That(user.PasswordHash, Does.Not.Contain("Fresh-Passphrase-1"));
        Assert.That(user.PasswordPepperKeyId, Is.EqualTo("v1"));
        Assert.That(user.MustChangePassword, Is.True, "new accounts must change password by default");
    }

    [Test]
    public async Task Create_DuplicateUserName_Fails()
    {
        var (svc, _, _) = New();
        await svc.CreateAsync("dupe", null, "User", "Fresh-Passphrase-1");
        var second = await svc.CreateAsync("DUPE", null, "User", "Other-Passphrase-2");
        Assert.That(second.Ok, Is.False, "normalized username collision must be rejected");
    }

    [Test]
    public async Task Create_BlankUserName_Fails()
    {
        var (svc, _, _) = New();
        Assert.That((await svc.CreateAsync("   ", null, "User", "Fresh-Passphrase-1")).Ok, Is.False);
    }

    [Test]
    public async Task Create_PolicyRejection_IsSurfaced()
    {
        var (svc, _, _) = New(PasswordPolicyResult.Reject("nope"));
        var result = await svc.CreateAsync("weakling", null, "User", "weak");
        Assert.That(result.Ok, Is.False);
        Assert.That(result.Error, Is.EqualTo("nope"));
    }

    [Test]
    public async Task SetRole_DemotingLastAdmin_IsBlocked()
    {
        var (svc, db, _) = New();
        var admin = await SeedAdmin(db);
        var result = await svc.SetRoleAsync(admin.Id, "User");
        Assert.That(result.Ok, Is.False);
        Assert.That(db.AuthUsers.Single(u => u.Id == admin.Id).Role, Is.EqualTo(MaRoles.Admin), "still admin");
    }

    [Test]
    public async Task SetRole_WithAnotherAdminPresent_Succeeds_AndRotatesStamp()
    {
        var (svc, db, _) = New();
        var a1 = await SeedAdmin(db, "root");
        await SeedAdmin(db, "backup");
        var before = a1.SecurityStamp;
        var result = await svc.SetRoleAsync(a1.Id, "User");
        Assert.That(result.Ok, Is.True);
        Assert.That(db.AuthUsers.Single(u => u.Id == a1.Id).SecurityStamp, Is.Not.EqualTo(before),
            "role change must rotate the stamp");
    }

    [Test]
    public async Task SetActive_DeactivatingLastAdmin_IsBlocked()
    {
        var (svc, db, _) = New();
        var admin = await SeedAdmin(db);
        Assert.That((await svc.SetActiveAsync(admin.Id, false)).Ok, Is.False);
        Assert.That(db.AuthUsers.Single(u => u.Id == admin.Id).IsActive, Is.True);
    }

    [Test]
    public async Task SetActive_Deactivate_RotatesStampToKillSessions()
    {
        var (svc, db, _) = New();
        await SeedAdmin(db, "root");
        var victim = await SeedAdmin(db, "victim");
        var before = victim.SecurityStamp;
        var result = await svc.SetActiveAsync(victim.Id, false);
        Assert.That(result.Ok, Is.True);
        var fresh = db.AuthUsers.Single(u => u.Id == victim.Id);
        Assert.That(fresh.IsActive, Is.False);
        Assert.That(fresh.SecurityStamp, Is.Not.EqualTo(before));
    }

    [Test]
    public async Task ResetPassword_RotatesStamp_PushesHistory_AndForcesChange()
    {
        var (svc, db, _) = New();
        var user = await SeedAdmin(db, "root");
        await SeedAdmin(db, "backup"); // so root isn't the last admin (not required, but realistic)
        var oldHash = user.PasswordHash;
        var oldStamp = user.SecurityStamp;

        var result = await svc.ResetPasswordAsync(user.Id, "Operator-Set-Passphrase-9");
        Assert.That(result.Ok, Is.True);
        var fresh = db.AuthUsers.Single(u => u.Id == user.Id);
        Assert.That(fresh.PasswordHash, Is.Not.EqualTo(oldHash));
        Assert.That(fresh.SecurityStamp, Is.Not.EqualTo(oldStamp));
        Assert.That(fresh.MustChangePassword, Is.True);
        Assert.That(db.AuthPasswordHistory.Any(h => h.UserId == user.Id && h.PasswordHash == oldHash), Is.True);
    }

    [Test]
    public async Task ResetPassword_UnknownUser_Fails()
    {
        var (svc, _, _) = New();
        Assert.That((await svc.ResetPasswordAsync(Guid.NewGuid(), "Whatever-Passphrase-1")).Ok, Is.False);
    }

    [Test]
    public async Task List_And_Get_ExposeSummaryWithoutPasswordHash()
    {
        var (svc, db, _) = New();
        var admin = await SeedAdmin(db);
        var list = await svc.ListAsync();
        Assert.That(list, Has.Count.EqualTo(1));
        var summary = await svc.GetAsync(admin.Id);
        Assert.That(summary, Is.Not.Null);
        Assert.That(summary!.UserName, Is.EqualTo("root"));
        // AuthUserSummary has no hash member at all — exposure is impossible by construction.
        Assert.That(typeof(AuthUserSummary).GetProperty("PasswordHash"), Is.Null);
    }

    [Test]
    public async Task UpdateProfile_SetsEmailAndNormalizedForm()
    {
        var (svc, db, _) = New();
        var admin = await SeedAdmin(db);
        await svc.UpdateProfileAsync(admin.Id, "Root@Example.com");
        var fresh = db.AuthUsers.Single(u => u.Id == admin.Id);
        Assert.That(fresh.Email, Is.EqualTo("Root@Example.com"));
        Assert.That(fresh.NormalizedEmail, Is.EqualTo("ROOT@EXAMPLE.COM"));
    }
}
