using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using MindAttic.Authentication.Data;
using MindAttic.Authentication.Entities;
using MindAttic.Authentication.Internal;
using MindAttic.Authentication.Services;
using MindAttic.Authentication.Tests.TestSupport;

namespace MindAttic.Authentication.Tests.Services;

/// <summary>
/// The audit writer (OWASP Logging CS / ASVS 7.x) must be log-injection safe (strip CR/LF/NUL from the
/// user-agent), store accounts and IPs only in hashed/canonical form, truncate oversized fields, and never
/// let an audit failure break authentication.
/// </summary>
[TestFixture]
public sealed class AuthAuditWriterTests
{
    private static (AuthAuditWriter writer, TestAuthDbContext db) New()
    {
        var db = TestAuthDbContext.NewInMemory();
        var sp = new ServiceCollection().AddSingleton<IAuthDataContext>(db).BuildServiceProvider();
        var writer = new AuthAuditWriter(
            sp.GetRequiredService<IServiceScopeFactory>(),
            FixedClock.At(new DateTimeOffset(2026, 6, 6, 12, 0, 0, TimeSpan.Zero)),
            NullLogger<AuthAuditWriter>.Instance);
        return (writer, db);
    }

    [Test]
    public async Task Write_SanitizesUserAgent_StrippingNewlinesAndNul()
    {
        var (writer, db) = New();
        var malicious = $"Mozilla{(char)10}FAKE LOG ENTRY{(char)13}injected{(char)0}null";
        await writer.WriteAsync(new AuthAuditEntry(
            AuthEventType.Login, AuthOutcome.Failure, AuthReasonCode.BadPassword, UserAgent: malicious));

        var row = db.AuthAuditLog.Single();
        // Ordinal char checks — NUnit's Does.Contain is culture-sensitive and mis-handles control chars.
        Assert.That(row.UserAgent.IndexOf('\n'), Is.EqualTo(-1), "LF must be stripped");
        Assert.That(row.UserAgent.IndexOf('\r'), Is.EqualTo(-1), "CR must be stripped");
        Assert.That(row.UserAgent.IndexOf('\0'), Is.EqualTo(-1), "NUL must be stripped");
        Assert.That(row.UserAgent, Is.EqualTo("Mozilla FAKE LOG ENTRY injected null"),
            "control chars are replaced with spaces, preserving readable content");
    }

    [Test]
    public async Task Write_HashesAccountKey_NeverStoresRaw()
    {
        var (writer, db) = New();
        await writer.WriteAsync(new AuthAuditEntry(
            AuthEventType.Login, AuthOutcome.Failure, AuthReasonCode.UnknownUser, AccountKeyRaw: "Alice@Example.com"));

        var row = db.AuthAuditLog.Single();
        Assert.That(row.AccountKeyHash, Is.Not.Null);
        Assert.That(row.AccountKeyHash, Has.Length.EqualTo(32));
        // The stored hash equals the hash of the NORMALIZED key (so equivalent identities collapse).
        Assert.That(row.AccountKeyHash, Is.EqualTo(AuthKeys.Hash(AuthKeys.NormalizeAccount("Alice@Example.com"))));
    }

    [Test]
    public async Task Write_NullAccountKey_LeavesHashNull()
    {
        var (writer, db) = New();
        await writer.WriteAsync(new AuthAuditEntry(AuthEventType.Login, AuthOutcome.Success, AuthReasonCode.Ok));
        Assert.That(db.AuthAuditLog.Single().AccountKeyHash, Is.Null);
    }

    [Test]
    public async Task Write_CanonicalizesSourceIp()
    {
        var (writer, db) = New();
        await writer.WriteAsync(new AuthAuditEntry(
            AuthEventType.Login, AuthOutcome.Failure, AuthReasonCode.BadPassword,
            SourceIpRaw: "2001:db8:abcd:1234:ffff::1"));
        Assert.That(db.AuthAuditLog.Single().SourceIp, Is.EqualTo("2001:db8:abcd:1234::/64"));
    }

    [Test]
    public async Task Write_TruncatesOversizedUserName()
    {
        var (writer, db) = New();
        await writer.WriteAsync(new AuthAuditEntry(
            AuthEventType.Login, AuthOutcome.Failure, AuthReasonCode.BadPassword,
            UserNameAttempted: new string('x', 1000)));
        Assert.That(db.AuthAuditLog.Single().UserNameAttempted!, Has.Length.EqualTo(256));
    }

    [Test]
    public void Write_NeverThrows_EvenWhenContextUnavailable()
    {
        // Scope factory resolves a context, then we dispose it so SaveChanges fails — must be swallowed.
        var db = TestAuthDbContext.NewInMemory();
        var sp = new ServiceCollection().AddSingleton<IAuthDataContext>(db).BuildServiceProvider();
        var writer = new AuthAuditWriter(sp.GetRequiredService<IServiceScopeFactory>(),
            FixedClock.AtUtcNow(), NullLogger<AuthAuditWriter>.Instance);
        db.Dispose();
        Assert.DoesNotThrowAsync(() => writer.WriteAsync(
            new AuthAuditEntry(AuthEventType.Login, AuthOutcome.Failure, AuthReasonCode.BadPassword)));
    }
}
