namespace MindAttic.Authentication.Tests.TestSupport;

/// <summary>An <see cref="IHttpClientFactory"/> whose clients are driven by a caller-supplied handler.</summary>
public sealed class StubHttpClientFactory(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> respond)
    : IHttpClientFactory
{
    public int Calls { get; private set; }

    public HttpClient CreateClient(string name) => new(new StubHandler(this, respond));

    private sealed class StubHandler(
        StubHttpClientFactory owner,
        Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            owner.Calls++;
            return Task.FromResult(respond(request, ct));
        }
    }

    /// <summary>Factory whose every send throws — exercises HIBP fail-open.</summary>
    public static StubHttpClientFactory ThatThrows() =>
        new((_, _) => throw new HttpRequestException("simulated HIBP outage"));

    /// <summary>Factory returning a fixed 200 body.</summary>
    public static StubHttpClientFactory ThatReturns(string body) =>
        new((_, _) => new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = new StringContent(body),
        });
}
