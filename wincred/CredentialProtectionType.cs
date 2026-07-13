namespace wincred;

/// <summary>
/// How a <see cref="CredentialProtector"/>-protected string is bound.
/// </summary>
public enum CredentialProtectionType : uint
{
    /// <summary>
    /// The string is not protected (plaintext, or not recognized as a protected blob at all).
    /// </summary>
    Unprotected = 0,
    /// <summary>
    /// Protected such that only the current user, on this machine, can unprotect it.
    /// </summary>
    UserProtection = 1,
    /// <summary>
    /// Protected such that any caller with the same trust level, on this machine, can unprotect it.
    /// </summary>
    TrustedProtection = 2,
    /// <summary>
    /// Protected for use by the LocalSystem account. Only meaningful in services running as LocalSystem.
    /// </summary>
    ForSystemProtection = 3
}
