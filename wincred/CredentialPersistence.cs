namespace wincred;

/// <summary>
/// How long a credential survives after being written.
/// </summary>
public enum CredentialPersistence : uint
{
    /// <summary>
    /// Lasts only for the caller's logon session.
    /// </summary>
    Session = 1,
    /// <summary>
    /// Kept until deleted; local to this machine.
    /// </summary>
    LocalMachine = 2,
    /// <summary>
    /// Kept until deleted; roams via Credential Roaming.
    /// </summary>
    Enterprise = 3
}
