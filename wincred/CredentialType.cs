namespace wincred;

/// <summary>
/// The kind of credential being stored, read, or deleted.
/// </summary>
public enum CredentialType : uint
{
    /// <summary>
    /// Arbitrary caller-defined credential; the only type with a free-form target name.
    /// </summary>
    Generic = 1,
    /// <summary>
    /// Windows domain password. <c>target</c> must be a server or domain name.
    /// </summary>
    DomainPassword = 2,
    /// <summary>
    /// Certificate-based domain credential. Readable/deletable; not writable (see <see cref="CredentialStore.TryWrite(string, ReadOnlySpan{byte}, CredentialType, string, string, CredentialPersistence, ReadOnlySpan{CredentialAttributeEntry})"/>).
    /// </summary>
    DomainCertificate = 3,
    /// <summary>
    /// Like <see cref="DomainPassword"/>, but stored and shown unencrypted.
    /// </summary>
    DomainVisiblePassword = 4,
    /// <summary>
    /// Certificate tied to a <see cref="Generic"/> target. Readable/deletable; not writable (see <see cref="CredentialStore.TryWrite(string, ReadOnlySpan{byte}, CredentialType, string, string, CredentialPersistence, ReadOnlySpan{CredentialAttributeEntry})"/>).
    /// </summary>
    GenericCertificate = 5,
    /// <summary>
    /// Domain credential whose target also names a package (e.g. <c>Domain:target=TERMSRV/server</c>).
    /// </summary>
    DomainExtended = 6
}
