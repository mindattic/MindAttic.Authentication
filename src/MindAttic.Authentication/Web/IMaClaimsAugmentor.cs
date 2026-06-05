using System.Security.Claims;

namespace MindAttic.Authentication.Web;

/// <summary>
/// App-implemented hook to bake EXTRA claims into the auth cookie at sign-in (resolved zero-or-many via
/// <c>GetServices</c>). Runs once, just before <c>SignInAsync</c>, so the claims live for the cookie's
/// lifetime. Because claims are NOT rebuilt on revalidation, an augmentor MUST be deterministic from the
/// identity's existing claims (role, amr, uid) — e.g. Ideas adds <c>AuthorRawMarkup</c> iff the identity
/// is an Admin with <c>amr=mfa</c>. Resolve scoped services from the supplied provider if needed.
/// </summary>
public interface IMaClaimsAugmentor
{
    ValueTask AugmentAsync(ClaimsIdentity identity, IServiceProvider services, CancellationToken ct);
}
