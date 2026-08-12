using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using MindAttic.Authentication.Options;

namespace MindAttic.Authentication.Services;

public interface ITotpService
{
    /// <summary>Generate a new 160-bit secret (raw bytes).</summary>
    byte[] GenerateSecret();
    /// <summary>Base32 (RFC 4648, no padding) for otpauth URIs / manual entry.</summary>
    string ToBase32(byte[] secret);
    /// <summary>otpauth:// URI with explicit algorithm/digits/period so apps fail closed.</summary>
    string BuildOtpAuthUri(byte[] secret, string accountName);
    /// <summary>
    /// Validate a code at the current time ±window. Returns the matched Unix step (for replay-guarding via
    /// <c>AuthUserMfa.LastTotpStepUsed</c>), or null if no match / step already consumed.
    /// </summary>
    long? Validate(byte[] secret, string code, long lastStepUsed);
    /// <summary>Generate human-formatted single-use recovery codes (plaintext, shown once).</summary>
    IReadOnlyList<string> GenerateRecoveryCodes();
}

/// <summary>RFC 6238 TOTP (HMAC-SHA1) with a replay-aware validation window.</summary>
public sealed class TotpService(IOptions<MfaOptions> options, TimeProvider clock) : ITotpService
{
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private readonly MfaOptions _o = options.Value;

    public byte[] GenerateSecret() => RandomNumberGenerator.GetBytes(_o.SecretBytes);

    public string BuildOtpAuthUri(byte[] secret, string accountName)
    {
        var issuer = Uri.EscapeDataString(_o.Issuer);
        var account = Uri.EscapeDataString(accountName);
        var secret32 = ToBase32(secret);
        return $"otpauth://totp/{issuer}:{account}?secret={secret32}&issuer={issuer}" +
               $"&algorithm=SHA1&digits={_o.Digits}&period={_o.PeriodSeconds}";
    }

    public long? Validate(byte[] secret, string code, long lastStepUsed)
    {
        if (string.IsNullOrWhiteSpace(code)) return null;
        code = code.Trim();
        var currentStep = clock.GetUtcNow().ToUnixTimeSeconds() / _o.PeriodSeconds;
        for (var offset = -_o.WindowSteps; offset <= _o.WindowSteps; offset++)
        {
            var step = currentStep + offset;
            if (step <= lastStepUsed) continue; // replay guard: never accept a consumed/earlier step
            var expected = Compute(secret, step);
            // constant-time compare of the digit strings
            if (CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(code)))
                return step;
        }
        return null;
    }

    public IReadOnlyList<string> GenerateRecoveryCodes()
    {
        var codes = new List<string>(_o.RecoveryCodeCount);
        for (var i = 0; i < _o.RecoveryCodeCount; i++)
        {
            var raw = ToBase32(RandomNumberGenerator.GetBytes(_o.RecoveryCodeBytes)).ToLowerInvariant();
            // group as xxxx-xxxx-xxxx for readability
            var groups = new List<string>();
            for (var p = 0; p < raw.Length; p += 4) groups.Add(raw.Substring(p, Math.Min(4, raw.Length - p)));
            codes.Add(string.Join('-', groups));
        }
        return codes;
    }

    private string Compute(byte[] secret, long step)
    {
        Span<byte> counter = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(counter, step);
        Span<byte> mac = stackalloc byte[20];
        HMACSHA1.HashData(secret, counter, mac);
        var offset = mac[^1] & 0x0F;
        var binary = ((mac[offset] & 0x7F) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
        var otp = binary % (int)Math.Pow(10, _o.Digits);
        return otp.ToString().PadLeft(_o.Digits, '0');
    }

    public string ToBase32(byte[] data)
    {
        var sb = new StringBuilder((data.Length * 8 + 4) / 5);
        int buffer = 0, bitsLeft = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                bitsLeft -= 5;
                sb.Append(Base32Alphabet[(buffer >> bitsLeft) & 31]);
            }
        }
        if (bitsLeft > 0) sb.Append(Base32Alphabet[(buffer << (5 - bitsLeft)) & 31]);
        return sb.ToString();
    }
}
