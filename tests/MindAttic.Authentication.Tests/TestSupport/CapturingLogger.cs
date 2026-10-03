using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace MindAttic.Authentication.Tests.TestSupport;

/// <summary>Logger provider that records every formatted entry (level + message + exception text).</summary>
public sealed class CapturingLoggerProvider : ILoggerProvider
{
    public ConcurrentQueue<(LogLevel Level, string Text)> Entries { get; } = new();

    public ILogger CreateLogger(string categoryName) => new CapturingLogger(this);

    public ILogger<T> For<T>() => new Logger<T>(new LoggerFactory([this]));

    public string AllText => string.Join("\n", Entries.Select(e => e.Text));

    public void Dispose() { }

    private sealed class CapturingLogger(CapturingLoggerProvider owner) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            owner.Entries.Enqueue((logLevel, formatter(state, exception) + (exception is null ? "" : " | " + exception)));
    }
}
