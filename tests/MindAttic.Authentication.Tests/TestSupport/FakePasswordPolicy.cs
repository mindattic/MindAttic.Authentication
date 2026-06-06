using MindAttic.Authentication.Services;

namespace MindAttic.Authentication.Tests.TestSupport;

/// <summary>
/// Configurable <see cref="IPasswordPolicy"/> double for isolating services that depend on policy from the
/// real (HIBP/HTTP-touching) implementation. Records every candidate it was asked to validate.
/// </summary>
public sealed class FakePasswordPolicy : IPasswordPolicy
{
    private readonly Func<string, Guid?, PasswordPolicyResult> _decide;

    public List<(string Password, Guid? UserId)> Seen { get; } = new();

    public FakePasswordPolicy(PasswordPolicyResult? fixedResult = null)
        => _decide = (_, _) => fixedResult ?? PasswordPolicyResult.Allowed;

    public FakePasswordPolicy(Func<string, Guid?, PasswordPolicyResult> decide) => _decide = decide;

    public Task<PasswordPolicyResult> ValidateAsync(string password, Guid? userId = null, CancellationToken ct = default)
    {
        Seen.Add((password, userId));
        return Task.FromResult(_decide(password, userId));
    }
}
