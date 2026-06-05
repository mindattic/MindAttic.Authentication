namespace MindAttic.Authentication;

/// <summary>Canonical claim types issued by MindAttic.Authentication. Apps must not redefine these.</summary>
public static class MaClaims
{
    public const string UserId = "ma:uid";
    public const string SecurityStamp = "ma:stamp";
    public const string SessionId = "ma:sid";          // surfaced AuthSession.Id
    /// <summary>Authentication methods references: "pwd", "mfa".</summary>
    public const string Amr = "amr";
    /// <summary>"1" if the user must change their password (forced-step middleware reads this — no DB hit).</summary>
    public const string MustChangePassword = "ma:mcp";
    /// <summary>"1" if the user must enroll MFA before reaching protected surfaces.</summary>
    public const string MustEnrollMfa = "ma:mem";
}

/// <summary>Canonical roles. Apps extend with their own; never redefine these.</summary>
public static class MaRoles
{
    public const string Admin = "Admin";
}

/// <summary>Canonical authorization policies registered by the library.</summary>
public static class MaPolicies
{
    /// <summary>Authenticated admin who has completed MFA step-up (role + amr=mfa).</summary>
    public const string Admin = "ma:admin";
}

/// <summary>Authentication scheme names.</summary>
public static class MaSchemes
{
    public const string Cookie = "MindAttic.Auth";
    /// <summary>Short-lived scheme holding a password-verified but pre-MFA principal. Grants no app access.</summary>
    public const string MfaPending = "MindAttic.MfaPending";
}
