using wincred.Interop;

namespace wincred;

/// <summary>
/// DPAPI protection for credential text you store somewhere other than Credential Manager (a config file, etc). Unrelated to <see cref="CredentialStore"/>, which never needs this.
/// </summary>
public static unsafe class CredentialProtector
{
    /// <summary>
    /// Protects <paramref name="credentials"/> into <paramref name="destination"/>.
    /// </summary>
    /// <param name="credentials">The plaintext to protect.</param>
    /// <param name="destination">Receives the protected text; pass empty to query the required size via <paramref name="charsWritten"/>.</param>
    /// <param name="charsWritten">Chars written on success; required buffer size on failure, if known.</param>
    /// <param name="protectionType">The protection actually applied.</param>
    /// <param name="asSelf">False to protect as the thread's impersonated identity instead of the caller.</param>
    /// <returns><see langword="true"/> if protected.</returns>
    public static bool TryProtect(string credentials, Span<char> destination, out int charsWritten, out CredentialProtectionType protectionType, bool asSelf = true)
    {
        if (string.IsNullOrEmpty(credentials))
        {
            ThrowHelpers.ThrowNullArgumentCredentials();
        }

        fixed (char* c = credentials)
        fixed (char* d = destination)
        {
            var maxChars = (uint)destination.Length;
            uint protType;
            var ok = Advapi32.CredProtectW(asSelf, c, (uint)(credentials.Length + 1), d, ref maxChars, &protType);
            protectionType = (CredentialProtectionType)protType;
            // maxChars includes the null terminator
            charsWritten = ok ? (int)maxChars - 1 : (int)maxChars;
            return ok;
        }
    }

    /// <summary>
    /// Reverses <see cref="TryProtect"/>.
    /// </summary>
    /// <param name="protectedCredentials">The protected text, as produced by <see cref="TryProtect"/>.</param>
    /// <param name="destination">Receives the plaintext; pass empty to query the required size via <paramref name="charsWritten"/>.</param>
    /// <param name="charsWritten">Chars written on success; required buffer size on failure, if known.</param>
    /// <param name="asSelf">Must match the value used to protect it.</param>
    /// <returns><see langword="true"/> if unprotected.</returns>
    public static bool TryUnprotect(string protectedCredentials, Span<char> destination, out int charsWritten, bool asSelf = true)
    {
        if (string.IsNullOrEmpty(protectedCredentials))
        {
            ThrowHelpers.ThrowNullArgumentCredentials();
        }

        fixed (char* p = protectedCredentials)
        fixed (char* d = destination)
        {
            var maxChars = (uint)destination.Length;
            var ok = Advapi32.CredUnprotectW(asSelf, p, (uint)(protectedCredentials.Length + 1), d, ref maxChars);
            charsWritten = ok ? (int)maxChars - 1 : (int)maxChars;
            return ok;
        }
    }

    /// <summary>
    /// Determines whether a string is one produced by <see cref="TryProtect"/>, and if so, how it's bound.
    /// </summary>
    /// <param name="protectedCredentials">The text to inspect. Must not be null or empty.</param>
    /// <param name="protectionType">The protection type, or <see cref="CredentialProtectionType.Unprotected"/> if the string isn't a protected blob.</param>
    /// <returns><see langword="true"/> if the string is protected; otherwise, <see langword="false"/>.</returns>
    public static bool IsProtected(string protectedCredentials, out CredentialProtectionType protectionType)
    {
        if (string.IsNullOrEmpty(protectedCredentials))
        {
            ThrowHelpers.ThrowNullArgumentCredentials();
        }

        fixed (char* p = protectedCredentials)
        {
            uint protType;
            var ok = Advapi32.CredIsProtectedW(p, &protType);
            protectionType = (CredentialProtectionType)protType;
            return ok && protectionType != CredentialProtectionType.Unprotected;
        }
    }
}
