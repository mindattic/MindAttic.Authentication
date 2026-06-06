using MindAttic.Authentication.Services;

namespace MindAttic.Authentication.Tests.TestSupport;

/// <summary>Captures audit entries in memory so tests can assert what was (and wasn't) recorded.</summary>
public sealed class FakeAuditWriter : IAuthAuditWriter
{
    public List<AuthAuditEntry> Entries { get; } = new();

    public Task WriteAsync(AuthAuditEntry entry, CancellationToken ct = default)
    {
        Entries.Add(entry);
        return Task.CompletedTask;
    }
}
