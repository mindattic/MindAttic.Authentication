namespace MindAttic.Authentication.Options;

/// <summary>
/// Argon2id parameters + password bounds. Bound from configuration (non-secret). Defaults exceed the
/// OWASP floor (m≥19456, t≥2, p≥1). Calibrate <see cref="Iterations"/> on PROD hardware to ~250–500ms
/// per verify (Konscious pure-managed is slower than native). Floors are enforced at startup, fail-closed.
/// </summary>
public sealed class AuthCryptoOptions
{
    /// <summary>Argon2 memory cost in KiB. Default 65536 (64 MiB).</summary>
    public int MemoryKiB { get; set; } = 65536;
    /// <summary>Argon2 time cost (iterations). Calibrate on prod hardware.</summary>
    public int Iterations { get; set; } = 3;
    /// <summary>Argon2 degree of parallelism. Keep ≤ 2× physical cores.</summary>
    public int Parallelism { get; set; } = 4;
    public int SaltBytes { get; set; } = 16;
    public int HashBytes { get; set; } = 32;

    /// <summary>Reject longer inputs BEFORE the HMAC pre-hash (Argon2 has no bcrypt 72-byte cap → DoS guard).</summary>
    public int MaxPasswordChars { get; set; } = 128;
    public int MinPasswordChars { get; set; } = 12;

    /// <summary>The pepper key id new hashes use, e.g. "v1". Older ids stay verifiable during rotation.</summary>
    public string CurrentPepperKeyId { get; set; } = "v1";

    /// <summary>Cap on concurrent Argon2 hashes (peak RAM ≈ N × MemoryKiB). 0 ⇒ ProcessorCount.</summary>
    public int MaxConcurrentHashes { get; set; }

    // --- absolute floors (OWASP); a misconfig below these fails startup ---
    public const int FloorMemoryKiB = 19456;
    public const int FloorIterations = 2;
    public const int FloorParallelism = 1;
    public const int FloorSaltBytes = 16;
    public const int FloorHashBytes = 32;

    public void ValidateOrThrow()
    {
        if (MemoryKiB < FloorMemoryKiB) throw new InvalidOperationException($"Argon2 MemoryKiB {MemoryKiB} < floor {FloorMemoryKiB}.");
        if (Iterations < FloorIterations) throw new InvalidOperationException($"Argon2 Iterations {Iterations} < floor {FloorIterations}.");
        if (Parallelism < FloorParallelism) throw new InvalidOperationException($"Argon2 Parallelism {Parallelism} < floor {FloorParallelism}.");
        if (SaltBytes < FloorSaltBytes) throw new InvalidOperationException($"Argon2 SaltBytes {SaltBytes} < floor {FloorSaltBytes}.");
        if (HashBytes < FloorHashBytes) throw new InvalidOperationException($"Argon2 HashBytes {HashBytes} < floor {FloorHashBytes}.");
        if (MinPasswordChars < 12) throw new InvalidOperationException("MinPasswordChars must be ≥ 12 (NIST).");
        if (MaxPasswordChars is < 64 or > 4096) throw new InvalidOperationException("MaxPasswordChars must be in [64, 4096].");
        if (string.IsNullOrWhiteSpace(CurrentPepperKeyId)) throw new InvalidOperationException("CurrentPepperKeyId is required.");
    }

    public int EffectiveMaxConcurrentHashes => MaxConcurrentHashes > 0 ? MaxConcurrentHashes : Environment.ProcessorCount;
}
