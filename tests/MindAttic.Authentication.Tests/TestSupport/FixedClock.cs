namespace MindAttic.Authentication.Tests.TestSupport;

/// <summary>A <see cref="TimeProvider"/> pinned to a fixed instant, advanceable for time-dependent tests.</summary>
public sealed class FixedClock(DateTimeOffset now) : TimeProvider
{
    private DateTimeOffset _now = now;

    public static FixedClock At(DateTimeOffset instant) => new(instant);
    public static FixedClock AtUtcNow() => new(DateTimeOffset.UtcNow);

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now = _now.Add(by);
    public void Set(DateTimeOffset instant) => _now = instant;
}
