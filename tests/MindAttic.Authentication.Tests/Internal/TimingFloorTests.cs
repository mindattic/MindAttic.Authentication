using System.Diagnostics;
using MindAttic.Authentication.Internal;

namespace MindAttic.Authentication.Tests.Internal;

/// <summary>
/// The login timing floor (ASVS 2.2.4) hides which factor failed by forcing a minimum wall-clock duration.
/// We use a small floor so the suite stays fast while still proving the floor and the no-negative-wait path.
/// </summary>
[TestFixture]
public sealed class TimingFloorTests
{
    [Test]
    public async Task EnforceAsync_WaitsUntilFloorWhenWorkWasFast()
    {
        var start = Stopwatch.GetTimestamp();
        await TimingFloor.EnforceAsync(start, floorMs: 200, maxJitterMs: 0);
        var elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
        Assert.That(elapsed, Is.GreaterThanOrEqualTo(190), "should not return before the floor");
    }

    [Test]
    public async Task EnforceAsync_DoesNotBlockWhenWorkAlreadyExceededFloor()
    {
        // A timestamp far in the past ⇒ elapsed already past the floor ⇒ returns ~immediately.
        var longAgo = Stopwatch.GetTimestamp() - (long)(Stopwatch.Frequency * 5);
        var start = Stopwatch.GetTimestamp();
        await TimingFloor.EnforceAsync(longAgo, floorMs: 200, maxJitterMs: 0);
        var elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
        Assert.That(elapsed, Is.LessThan(100), "no artificial delay when the floor is already met");
    }

    [Test]
    public void Defaults_AreSpecValues()
    {
        Assert.That(TimingFloor.DefaultFloorMs, Is.EqualTo(750));
        Assert.That(TimingFloor.DefaultMaxJitterMs, Is.EqualTo(100));
    }
}
