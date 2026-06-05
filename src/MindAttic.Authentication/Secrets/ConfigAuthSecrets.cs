using Microsoft.Extensions.Configuration;

namespace MindAttic.Authentication.Secrets;

/// <summary>
/// <see cref="IAuthSecrets"/> over the MindAttic.Vault <c>Security</c> configuration section
/// (<c>MindAttic:Vault:Security:&lt;name&gt;</c>). Dev: surfaced from %APPDATA%\MindAttic\Security via
/// AddMindAtticVaultFiles. Prod: env vars / Azure Key Vault references (read-only). Resolved values are
/// cached after first read (mitigates a Key Vault blip mid-run). Fail-closed: blank ⇒ throw.
/// </summary>
public sealed class ConfigAuthSecrets(IConfiguration configuration) : IAuthSecrets
{
    public const string SectionPath = "MindAttic:Vault:Security";

    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _cache = new(StringComparer.Ordinal);

    public string GetRequired(string name)
    {
        var v = GetOptional(name);
        if (string.IsNullOrWhiteSpace(v))
            throw new InvalidOperationException(
                $"Required auth secret '{name}' was not found at {SectionPath}:{name}. " +
                "Provision it in the MindAttic.Vault Security bucket (dev) or Key Vault/env (prod). " +
                "Auth refuses to start without it (fail-closed).");
        return v;
    }

    public string? GetOptional(string name)
    {
        if (_cache.TryGetValue(name, out var cached)) return cached;
        var v = configuration[$"{SectionPath}:{name}"];
        if (!string.IsNullOrWhiteSpace(v)) _cache[name] = v;
        return string.IsNullOrWhiteSpace(v) ? null : v;
    }

    public byte[] GetRequiredBytes(string name)
    {
        var v = GetRequired(name);
        try { return Convert.FromBase64String(v); }
        catch (FormatException ex)
        {
            throw new InvalidOperationException($"Auth secret '{name}' is not valid base64.", ex);
        }
    }
}
