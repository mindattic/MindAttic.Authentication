namespace MindAttic.Authentication.Secrets;

/// <summary>
/// Fail-CLOSED access to auth secrets (pepper, Data-Protection KEK, reset-token key, CAPTCHA secret,
/// bootstrap token) resolved from the MindAttic.Vault <c>Security</c> bucket. A missing/blank secret
/// NEVER coerces to empty — <see cref="GetRequired"/> throws. This directly neutralizes Vault's
/// best-effort "return null on any IO/parse error" behavior (red-team mustFix #2 / verdict).
/// </summary>
public interface IAuthSecrets
{
    /// <summary>Returns the secret, or throws <see cref="InvalidOperationException"/> if absent/blank.</summary>
    string GetRequired(string name);

    /// <summary>Returns the secret or null if absent. Use only for genuinely optional secrets.</summary>
    string? GetOptional(string name);

    /// <summary>Base64-decoded required secret bytes (e.g. a 32-byte pepper). Throws if absent/blank/invalid.</summary>
    byte[] GetRequiredBytes(string name);
}
