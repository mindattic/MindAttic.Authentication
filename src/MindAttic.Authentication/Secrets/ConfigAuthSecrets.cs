using Microsoft.Extensions.Configuration;

namespace MindAttic.Authentication.Secrets;

/// <summary>
/// <see cref="IAuthSecrets"/> over the MindAttic.Vault <c>Security</c> configuration section
/// (<c>MindAttic:Vault:Security:&lt;name&gt;</c>). Dev: surfaced from the Vault roaming store via
/// AddMindAtticVaultFiles. Prod: env vars / Azure Key Vault references (read-only). Resolved values
/// are cached after first read (mitigates a Key Vault blip mid-run). Fail-closed: blank ⇒ throw.
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

        var v = configuration[$"{SectionPath}:{name}"] ?? FindByRelaxedName(name);

        if (!string.IsNullOrWhiteSpace(v)) _cache[name] = v;
        return string.IsNullOrWhiteSpace(v) ? null : v;
    }

    /// <summary>
    /// Second chance for a secret whose key survived the trip to production with a different spelling.
    /// <para>
    /// Azure App Service on <b>Linux</b> rewrites application-setting names when it injects them as
    /// environment variables: separators that are illegal in a POSIX variable name are removed or
    /// replaced. <c>pepper.v1</c> arrives as <c>pepper_v1</c> and <c>bootstrap-token</c> as
    /// <c>bootstraptoken</c>, so an exact lookup finds nothing and auth fail-closes on a secret the
    /// operator did provision. Windows hosts pass the name through untouched, which is why this only
    /// ever bites after a Linux deploy.
    /// </para>
    /// <para>
    /// The mangling is not invertible — you cannot tell where a hyphen used to be — so the match runs
    /// the other way: both sides are reduced to letters and digits and compared case-insensitively.
    /// A collision would need two secrets differing only in punctuation, which the ambiguity check
    /// below refuses rather than guesses at.
    /// </para>
    /// </summary>
    private string? FindByRelaxedName(string name)
    {
        var wanted = Relax(name);
        if (wanted.Length == 0) return null;

        string? found = null;
        var section = configuration.GetSection(SectionPath);

        foreach (var child in section.GetChildren())
        {
            if (!string.Equals(Relax(child.Key), wanted, StringComparison.OrdinalIgnoreCase)) continue;
            if (string.IsNullOrWhiteSpace(child.Value)) continue;

            if (found != null && !string.Equals(found, child.Value, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Auth secret '{name}' is ambiguous: more than one key under {SectionPath} reduces to " +
                    $"'{wanted}' with different values. Rename the secrets so they differ by more than " +
                    "punctuation — auth will not guess which one you meant.");
            }
            found = child.Value;
        }

        return found;
    }

    /// <summary>Reduces a key to letters and digits, so punctuation differences stop mattering.</summary>
    private static string Relax(string value)
    {
        Span<char> buffer = value.Length <= 128 ? stackalloc char[value.Length] : new char[value.Length];
        var n = 0;
        foreach (var c in value)
        {
            if (char.IsLetterOrDigit(c)) buffer[n++] = char.ToLowerInvariant(c);
        }
        return new string(buffer[..n]);
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
