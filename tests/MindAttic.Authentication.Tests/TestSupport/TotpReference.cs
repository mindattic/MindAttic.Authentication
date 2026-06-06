using System.Buffers.Binary;
using System.Security.Cryptography;

namespace MindAttic.Authentication.Tests.TestSupport;

/// <summary>
/// An INDEPENDENT RFC 6238 (HMAC-SHA1) TOTP generator used purely to produce known-good codes for a given
/// secret/step in tests, so we can cross-check <c>TotpService.Validate</c> without reaching into its
/// internals. Mirrors the standard dynamic-truncation algorithm.
/// </summary>
public static class TotpReference
{
    public static string Compute(byte[] secret, long step, int digits = 6)
    {
        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, step);
        Span<byte> mac = stackalloc byte[20];
        HMACSHA1.HashData(secret, counter, mac);
        var offset = mac[^1] & 0x0F;
        var binary = ((mac[offset] & 0x7F) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
        var otp = binary % (int)Math.Pow(10, digits);
        return otp.ToString().PadLeft(digits, '0');
    }

    public static long StepFor(DateTimeOffset time, int periodSeconds = 30) =>
        time.ToUnixTimeSeconds() / periodSeconds;
}
