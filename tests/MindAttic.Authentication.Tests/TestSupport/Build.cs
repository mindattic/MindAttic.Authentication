using Microsoft.Extensions.Options;
using MindAttic.Authentication.Crypto;
using MindAttic.Authentication.Options;

namespace MindAttic.Authentication.Tests.TestSupport;

/// <summary>Builders for the units under test, wired with fast-but-valid params and test doubles.</summary>
public static class Build
{
    /// <summary>
    /// Crypto options at the OWASP floor (m=19456, t=2, p=1) — the cheapest configuration that still passes
    /// <see cref="AuthCryptoOptions.ValidateOrThrow"/> — to keep Argon2-heavy tests fast.
    /// </summary>
    public static AuthCryptoOptions FastCrypto(string pepperId = "v1") => new()
    {
        MemoryKiB = AuthCryptoOptions.FloorMemoryKiB,
        Iterations = AuthCryptoOptions.FloorIterations,
        Parallelism = AuthCryptoOptions.FloorParallelism,
        SaltBytes = 16,
        HashBytes = 32,
        MinPasswordChars = 12,
        MaxPasswordChars = 128,
        CurrentPepperKeyId = pepperId,
        MaxConcurrentHashes = 2,
    };

    public static Argon2idPasswordHasher Hasher(AuthCryptoOptions? options = null, FakeAuthSecrets? secrets = null) =>
        new(secrets ?? new FakeAuthSecrets(), Microsoft.Extensions.Options.Options.Create(options ?? FastCrypto()));

    public static IOptions<T> Opt<T>(T value) where T : class => Microsoft.Extensions.Options.Options.Create(value);
}
