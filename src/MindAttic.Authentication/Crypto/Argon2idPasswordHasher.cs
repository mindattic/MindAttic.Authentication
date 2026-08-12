using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.Extensions.Options;
using MindAttic.Authentication.Options;
using MindAttic.Authentication.Secrets;

namespace MindAttic.Authentication.Crypto;

/// <summary>
/// Argon2id (Konscious) with an HMAC-SHA256 pepper pre-hash, self-describing PHC storage, transparent
/// legacy bcrypt/SHA-256 upgrade-on-verify, constant-time comparison, a decoy path for absent users
/// (no username oracle), and a concurrency gate (peak RAM = N × MemoryKiB) so Argon2 cost can't be
/// weaponized into a login-flood OOM. Pepper lives in Vault, a different trust domain than the DB.
/// </summary>
public sealed class Argon2idPasswordHasher : IPasswordHasher, IDisposable
{
    private readonly IAuthSecrets _secrets;
    private readonly AuthCryptoOptions _o;
    private readonly SemaphoreSlim _gate;
    private readonly string _decoyPhc;
    private readonly string _decoyPepperId;

    public Argon2idPasswordHasher(IAuthSecrets secrets, IOptions<AuthCryptoOptions> options)
    {
        _secrets = secrets;
        _o = options.Value;
        _o.ValidateOrThrow();
        _gate = new SemaphoreSlim(_o.EffectiveMaxConcurrentHashes, _o.EffectiveMaxConcurrentHashes);
        // Precompute a decoy hash at the CURRENT params+pepper so absent-user verifies cost the same.
        // Also fails startup fast if the current pepper is missing (fail-closed).
        _decoyPepperId = _o.CurrentPepperKeyId;
        var decoyPassword = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
        _decoyPhc = HashInternal(decoyPassword, _decoyPepperId).Phc;
    }

    public PasswordHash Hash(string password)
    {
        if (password is null) throw new ArgumentNullException(nameof(password));
        if (password.Length < _o.MinPasswordChars || password.Length > _o.MaxPasswordChars)
            throw new ArgumentException($"Password length must be {_o.MinPasswordChars}–{_o.MaxPasswordChars} characters.", nameof(password));
        return HashInternal(password, _o.CurrentPepperKeyId);
    }

    public PasswordVerifyResult Verify(string password, string storedHash, string? pepperKeyId, string? legacyScheme)
    {
        if (string.IsNullOrEmpty(storedHash) || string.IsNullOrEmpty(password) || password.Length > _o.MaxPasswordChars)
        {
            VerifyDecoy(password ?? "");
            return new PasswordVerifyResult(false, false);
        }

        // Legacy bcrypt → verify with the ORIGINAL (un-normalized) password; upgrade on success.
        if (string.Equals(legacyScheme, "bcrypt", StringComparison.OrdinalIgnoreCase) || storedHash.StartsWith("$2", StringComparison.Ordinal))
        {
            bool ok;
            try { ok = BCrypt.Net.BCrypt.Verify(password, storedHash); } catch { ok = false; }
            if (!ok) VerifyDecoy(password); // keep timing comparable to argon2 path on failure
            return new PasswordVerifyResult(ok, ok);
        }

        // Legacy SHA-256 (Tutor) → constant-time compare; upgrade on success.
        if (string.Equals(legacyScheme, "sha256", StringComparison.OrdinalIgnoreCase))
        {
            bool ok;
            try
            {
                var computed = SHA256.HashData(Encoding.UTF8.GetBytes(password));
                ok = CryptographicOperations.FixedTimeEquals(computed, Convert.FromBase64String(storedHash));
            }
            catch { ok = false; }
            if (!ok) VerifyDecoy(password);
            return new PasswordVerifyResult(ok, ok);
        }

        // Argon2id
        if (!PhcArgon2.TryParse(storedHash, out var phc) || string.IsNullOrEmpty(pepperKeyId))
        {
            VerifyDecoy(password);
            return new PasswordVerifyResult(false, false);
        }
        byte[] pepper;
        try { pepper = _secrets.GetRequiredBytes($"pepper.{pepperKeyId}"); }
        catch { VerifyDecoy(password); return new PasswordVerifyResult(false, false); }

        var preHash = PreHash(password, pepper);
        try
        {
            var computed = Argon2(preHash, phc.Salt, phc.MemoryKiB, phc.Iterations, phc.Parallelism, phc.Hash.Length);
            var match = CryptographicOperations.FixedTimeEquals(computed, phc.Hash);
            CryptographicOperations.ZeroMemory(computed);
            return new PasswordVerifyResult(match, match && NeedsRehash(phc, pepperKeyId));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(preHash);
            CryptographicOperations.ZeroMemory(pepper);
        }
    }

    public void VerifyDecoy(string password)
    {
        if (!PhcArgon2.TryParse(_decoyPhc, out var phc)) return;
        byte[] pepper;
        try { pepper = _secrets.GetRequiredBytes($"pepper.{_decoyPepperId}"); } catch { return; }
        var input = password.Length > _o.MaxPasswordChars ? password[.._o.MaxPasswordChars] : password;
        var preHash = PreHash(input, pepper);
        try { _ = Argon2(preHash, phc.Salt, phc.MemoryKiB, phc.Iterations, phc.Parallelism, phc.Hash.Length); }
        finally { CryptographicOperations.ZeroMemory(preHash); CryptographicOperations.ZeroMemory(pepper); }
    }

    private PasswordHash HashInternal(string password, string pepperKeyId)
    {
        var pepper = _secrets.GetRequiredBytes($"pepper.{pepperKeyId}");
        var salt = RandomNumberGenerator.GetBytes(_o.SaltBytes);
        var preHash = PreHash(password, pepper);
        try
        {
            var hash = Argon2(preHash, salt, _o.MemoryKiB, _o.Iterations, _o.Parallelism, _o.HashBytes);
            var phc = new PhcArgon2(PhcArgon2.ArgonVersion, _o.MemoryKiB, _o.Iterations, _o.Parallelism, salt, hash).Encode();
            return new PasswordHash(phc, pepperKeyId);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(preHash);
            CryptographicOperations.ZeroMemory(pepper);
        }
    }

    private bool NeedsRehash(PhcArgon2 phc, string pepperKeyId) =>
        phc.MemoryKiB < _o.MemoryKiB || phc.Iterations < _o.Iterations || phc.Parallelism < _o.Parallelism
        || phc.Salt.Length < _o.SaltBytes || phc.Hash.Length < _o.HashBytes
        || !string.Equals(pepperKeyId, _o.CurrentPepperKeyId, StringComparison.Ordinal);

    private static byte[] PreHash(string password, byte[] pepper)
    {
        var bytes = Encoding.UTF8.GetBytes(password.Normalize(NormalizationForm.FormKC));
        try
        {
            using var hmac = new HMACSHA256(pepper);
            return hmac.ComputeHash(bytes);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private byte[] Argon2(byte[] input, byte[] salt, int memoryKiB, int iterations, int parallelism, int outLen)
    {
        _gate.Wait();
        try
        {
            using var argon2 = new Argon2id(input)
            {
                Salt = salt,
                MemorySize = memoryKiB,
                Iterations = iterations,
                DegreeOfParallelism = parallelism,
            };
            return argon2.GetBytes(outLen);
        }
        finally { _gate.Release(); }
    }

    public void Dispose() => _gate.Dispose();
}
