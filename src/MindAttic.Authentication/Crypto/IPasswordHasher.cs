namespace MindAttic.Authentication.Crypto;

/// <summary>Outcome of verifying a credential.</summary>
/// <param name="Succeeded">True iff the password matched.</param>
/// <param name="NeedsRehash">True iff the stored hash should be re-hashed (legacy scheme, weaker params, or stale pepper).</param>
public readonly record struct PasswordVerifyResult(bool Succeeded, bool NeedsRehash);

/// <summary>A freshly produced hash + the pepper key id it was peppered with.</summary>
/// <param name="Phc">The PHC string to store in <c>AuthUser.PasswordHash</c>.</param>
/// <param name="PepperKeyId">Store in <c>AuthUser.PasswordPepperKeyId</c>.</param>
public readonly record struct PasswordHash(string Phc, string PepperKeyId);

/// <summary>
/// Argon2id+pepper password hashing with transparent legacy-upgrade. Verification is constant-time and
/// runs even for absent users (decoy) so it cannot be used as a username oracle.
/// </summary>
public interface IPasswordHasher
{
    /// <summary>Hash a new/changed password with the current params + current pepper.</summary>
    PasswordHash Hash(string password);

    /// <summary>
    /// Verify against a stored hash. <paramref name="pepperKeyId"/> is the row's pepper id (null for
    /// legacy rows); <paramref name="legacyScheme"/> is "bcrypt"/"sha256" until first rehash, else null.
    /// </summary>
    PasswordVerifyResult Verify(string password, string storedHash, string? pepperKeyId, string? legacyScheme);

    /// <summary>Run an equivalent-cost decoy verification for an absent/inactive user (uniform timing).</summary>
    void VerifyDecoy(string password);
}
