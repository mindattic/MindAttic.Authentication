namespace MindAttic.Authentication.Crypto;

/// <summary>
/// PHC-string codec for Argon2id: <c>$argon2id$v=19$m=65536,t=3,p=4$&lt;b64salt&gt;$&lt;b64hash&gt;</c>
/// (base64 without padding, per the PHC spec). Self-describing so work factors can be raised over time
/// and rehash-on-login is deterministic.
/// </summary>
public readonly record struct PhcArgon2(int Version, int MemoryKiB, int Iterations, int Parallelism, byte[] Salt, byte[] Hash)
{
    public const int ArgonVersion = 19; // 0x13

    public string Encode()
    {
        var salt = Convert.ToBase64String(Salt).TrimEnd('=');
        var hash = Convert.ToBase64String(Hash).TrimEnd('=');
        return $"$argon2id$v={Version}$m={MemoryKiB},t={Iterations},p={Parallelism}${salt}${hash}";
    }

    public static bool TryParse(string? s, out PhcArgon2 result)
    {
        result = default;
        if (string.IsNullOrEmpty(s)) return false;
        // ["", "argon2id", "v=19", "m=..,t=..,p=..", "<salt>", "<hash>"]
        var parts = s.Split('$');
        if (parts.Length != 6 || parts[0].Length != 0) return false;
        if (!parts[1].Equals("argon2id", StringComparison.Ordinal)) return false;
        if (!TryKv(parts[2], "v", out var v)) return false;
        var perf = parts[3].Split(',');
        if (perf.Length != 3 || !TryKv(perf[0], "m", out var m) || !TryKv(perf[1], "t", out var t) || !TryKv(perf[2], "p", out var p))
            return false;
        if (!TryB64(parts[4], out var salt) || !TryB64(parts[5], out var hash)) return false;
        result = new PhcArgon2(v, m, t, p, salt, hash);
        return true;
    }

    private static bool TryKv(string segment, string key, out int value)
    {
        value = 0;
        var eq = segment.IndexOf('=');
        if (eq <= 0 || !segment.AsSpan(0, eq).SequenceEqual(key)) return false;
        return int.TryParse(segment.AsSpan(eq + 1), out value);
    }

    private static bool TryB64(string s, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        var pad = s.Length % 4;
        if (pad != 0) s = s + new string('=', 4 - pad);
        Span<byte> buf = new byte[((s.Length + 3) / 4) * 3];
        if (Convert.TryFromBase64String(s, buf, out var written)) { bytes = buf[..written].ToArray(); return true; }
        return false;
    }
}
