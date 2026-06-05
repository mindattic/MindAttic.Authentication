using System.Diagnostics;
using System.Security.Cryptography;

namespace MindAttic.Authentication.Internal;

/// <summary>
/// Enforces a minimum, jittered wall-clock duration on the login endpoint so response timing never
/// reveals which factor failed (unknown user / bad password / locked / MFA). The floor is validated to
/// exceed the worst-case Argon2 verify at startup.
/// </summary>
public static class TimingFloor
{
    public const int DefaultFloorMs = 750;
    public const int DefaultMaxJitterMs = 100;

    /// <summary>Delay until at least <c>floor + jitter</c> ms have elapsed since <paramref name="startTimestamp"/>.</summary>
    public static async Task EnforceAsync(long startTimestamp, int floorMs = DefaultFloorMs, int maxJitterMs = DefaultMaxJitterMs)
    {
        var elapsedMs = Stopwatch.GetElapsedTime(startTimestamp).TotalMilliseconds;
        var target = floorMs + RandomNumberGenerator.GetInt32(0, maxJitterMs + 1);
        var remaining = target - elapsedMs;
        if (remaining > 0) await Task.Delay((int)remaining);
    }
}
