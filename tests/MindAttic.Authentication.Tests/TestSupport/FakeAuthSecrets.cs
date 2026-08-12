using System.Security.Cryptography;
using System.Text;
using MindAttic.Authentication.Secrets;

namespace MindAttic.Authentication.Tests.TestSupport;

/// <summary>
/// Deterministic, fail-closed test double for <see cref="IAuthSecrets"/>. Every secret name resolves to a
/// stable 32-byte value (so the same pepper id yields the same bytes across hasher instances — required to
/// verify a hash produced elsewhere). Names added to <see cref="Missing"/> throw, exercising fail-closed
/// paths (a missing pepper must never coerce to empty).
/// </summary>
public sealed class FakeAuthSecrets : IAuthSecrets
{
    private readonly Dictionary<string, string> _cache = new(StringComparer.Ordinal);

    /// <summary>Secret names that should behave as absent (GetRequired/GetRequiredBytes throw).</summary>
    public HashSet<string> Missing { get; } = new(StringComparer.Ordinal);

    public FakeAuthSecrets MarkMissing(string name) { Missing.Add(name); return this; }

    public string GetRequired(string name)
    {
        if (Missing.Contains(name))
            throw new InvalidOperationException($"Required auth secret '{name}' is absent (fail-closed test double).");
        return Resolve(name);
    }

    public string? GetOptional(string name) => Missing.Contains(name) ? null : Resolve(name);

    public byte[] GetRequiredBytes(string name) => Convert.FromBase64String(GetRequired(name));

    private string Resolve(string name)
    {
        if (_cache.TryGetValue(name, out var v)) return v;
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes("mindattic-test-secret:" + name)); // 32 bytes
        var b64 = Convert.ToBase64String(bytes);
        _cache[name] = b64;
        return b64;
    }
}
