namespace MindAttic.Authentication.Internal;

/// <summary>Open-redirect-safe local-URL check for returnUrl handling.</summary>
public static class UrlSafety
{
    /// <summary>True only for same-site relative paths. Rejects absolute/scheme/protocol-relative/control-char URLs.</summary>
    public static bool IsLocalUrl(string? url)
    {
        if (string.IsNullOrEmpty(url)) return false;
        foreach (var ch in url)
            if (ch < 0x20 || ch == 0x7F) return false;     // reject control chars (incl. \t \r \n)

        // "/path" but not "//host" or "/\host"
        if (url[0] == '/')
            return url.Length == 1 || (url[1] != '/' && url[1] != '\\');

        // "~/path"
        if (url[0] == '~' && url.Length > 1 && url[1] == '/')
            return true;

        return false;
    }

    /// <summary>Returns <paramref name="url"/> if it's a safe local URL, else <paramref name="fallback"/>.</summary>
    public static string LocalOrDefault(string? url, string fallback = "/") => IsLocalUrl(url) ? url! : fallback;
}
