namespace MindAttic.Authentication.Options;

/// <summary>
/// A public, UI-facing description of the enforced password policy, so an app's forms can show
/// requirements WITHOUT reaching into the validator. Reflects the ACTUAL (NIST-aligned) policy: length +
/// breach/history checks, NO composition rules. Built from <see cref="AuthPolicyOptions"/>; injectable.
/// </summary>
public sealed class PasswordPolicyDescriptor
{
    public required int MinLength { get; init; }
    public required int MaxLength { get; init; }
    public required IReadOnlyList<string> Requirements { get; init; }

    public static PasswordPolicyDescriptor From(AuthPolicyOptions o)
    {
        var reqs = new List<string> { $"At least {o.MinLength} characters (longer is better)" };
        if (o.CheckHibp) reqs.Add("Not found in any known data breach");
        if (o.HistoryDepth > 0) reqs.Add($"Not one of your last {o.HistoryDepth} passwords");
        return new PasswordPolicyDescriptor { MinLength = o.MinLength, MaxLength = o.MaxLength, Requirements = reqs };
    }
}
