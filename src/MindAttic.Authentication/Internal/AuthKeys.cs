using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace MindAttic.Authentication.Internal;

/// <summary>Canonicalization + hashing of throttle/audit keys (accounts and IPs). Never stores raw values.</summary>
public static class AuthKeys
{
    /// <summary>Normalize an account identifier (email/username): NFKC, trim, invariant-lower.</summary>
    public static string NormalizeAccount(string accountKey) =>
        (accountKey ?? "").Normalize(NormalizationForm.FormKC).Trim().ToLowerInvariant();

    /// <summary>Canonical IP key: IPv4 as-is; IPv6 truncated to its /64 prefix (defeats trivial rotation).</summary>
    public static string CanonicalizeIp(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return "unknown";
        if (!IPAddress.TryParse(ip, out var addr)) return "unknown";
        if (addr.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var bytes = addr.GetAddressBytes();   // 16 bytes
            for (var i = 8; i < bytes.Length; i++) bytes[i] = 0;  // zero the lower 64 bits
            return new IPAddress(bytes).ToString() + "/64";
        }
        return addr.ToString();
    }

    /// <summary>SHA-256 of a (canonicalized) key — 32 bytes, fixed-length, never reversible to the raw value.</summary>
    public static byte[] Hash(string canonicalKey) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(canonicalKey));

    /// <summary>SHA-256 hex (lowercase) — for IpHash columns.</summary>
    public static string HashHex(string canonicalKey) =>
        Convert.ToHexStringLower(Hash(canonicalKey));
}
