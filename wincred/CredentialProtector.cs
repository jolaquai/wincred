using System.Buffers;

using wincred.Interop;

namespace wincred;

/// <summary>
/// DPAPI protection for credential text you store somewhere other than Credential Manager (a config file, etc). Unrelated to <see cref="CredentialStore"/>, which never needs this.
/// </summary>
public static unsafe class CredentialProtector
{
    // ERROR_INSUFFICIENT_BUFFER
    private const int ErrorInsufficientBuffer = 122;
    // largest plaintext (incl. terminator) copied onto the stack before falling back to the pool, in chars
    private const int MaxStackChars = 512;

    /// <summary>
    /// Protects <paramref name="credentials"/> into <paramref name="destination"/>.
    /// </summary>
    /// <param name="credentials">The plaintext to protect.</param>
    /// <param name="destination">Receives the protected text; pass empty to query the required size via <paramref name="charsWritten"/>.</param>
    /// <param name="charsWritten">On success, chars written (excluding the terminator). On an insufficient-buffer failure, the required size (including the terminator); otherwise 0.</param>
    /// <param name="protectionType">The protection actually applied.</param>
    /// <param name="asSelf">False to protect as the thread's impersonated identity instead of the caller.</param>
    /// <returns><see langword="true"/> if protected.</returns>
    public static bool TryProtect(string credentials, Span<char> destination, out int charsWritten, out CredentialProtectionType protectionType, bool asSelf = true)
    {
        if (string.IsNullOrEmpty(credentials))
        {
            ThrowHelpers.ThrowNullArgumentCredentials();
        }

        // strings are null-terminated, so protect Length + 1 chars (the terminator becomes part of the payload) with no copy
        fixed (char* c = credentials)
        {
            return ProtectCore(asSelf, c, (uint)(credentials.Length + 1), destination, out charsWritten, out protectionType);
        }
    }

    /// <summary>
    /// Protects <paramref name="credentials"/> into <paramref name="destination"/>, without forcing the plaintext into a <see cref="string"/>.
    /// </summary>
    /// <param name="credentials">The plaintext to protect.</param>
    /// <param name="destination">Receives the protected text; pass empty to query the required size via <paramref name="charsWritten"/>.</param>
    /// <param name="charsWritten">On success, chars written (excluding the terminator). On an insufficient-buffer failure, the required size (including the terminator); otherwise 0.</param>
    /// <param name="protectionType">The protection actually applied.</param>
    /// <param name="asSelf">False to protect as the thread's impersonated identity instead of the caller.</param>
    /// <returns><see langword="true"/> if protected.</returns>
    public static bool TryProtect(ReadOnlySpan<char> credentials, Span<char> destination, out int charsWritten, out CredentialProtectionType protectionType, bool asSelf = true)
    {
        if (credentials.IsEmpty)
        {
            ThrowHelpers.ThrowNullArgumentCredentials();
        }

        // the API expects a null-terminated input; a span isn't, so stage it into a terminated scratch buffer we can zero afterwards
        var needed = credentials.Length + 1;
        char[] rented = null;
        var input = needed <= MaxStackChars ? stackalloc char[needed] : (rented = ArrayPool<char>.Shared.Rent(needed)).AsSpan(0, needed);
        try
        {
            credentials.CopyTo(input);
            input[credentials.Length] = '\0';
            fixed (char* c = input)
            {
                return ProtectCore(asSelf, c, (uint)needed, destination, out charsWritten, out protectionType);
            }
        }
        finally
        {
            input.Clear(); // scrub the staged plaintext
            if (rented is not null)
            {
                ArrayPool<char>.Shared.Return(rented);
            }
        }
    }

    private static bool ProtectCore(bool asSelf, char* credentials, uint credentialsSize, Span<char> destination, out int charsWritten, out CredentialProtectionType protectionType)
    {
        fixed (char* d = destination)
        {
            var maxChars = (uint)destination.Length;
            uint protType;
            var ok = Advapi32.CredProtectW(asSelf, credentials, credentialsSize, d, ref maxChars, &protType);
            protectionType = (CredentialProtectionType)protType;
            // maxChars includes the null terminator; on a size failure the API reports the required size, otherwise it's untouched and meaningless
            charsWritten = ok ? (int)maxChars - 1
                : Marshal.GetLastWin32Error() == ErrorInsufficientBuffer ? (int)maxChars : 0;
            return ok;
        }
    }

    /// <summary>
    /// Reverses <see cref="TryProtect(string, Span{char}, out int, out CredentialProtectionType, bool)"/>.
    /// </summary>
    /// <param name="protectedCredentials">The protected text, as produced by <see cref="TryProtect(string, Span{char}, out int, out CredentialProtectionType, bool)"/>.</param>
    /// <param name="destination">Receives the plaintext; pass empty to query the required size via <paramref name="charsWritten"/>.</param>
    /// <param name="charsWritten">On success, chars written (excluding the terminator). On an insufficient-buffer failure, the required size (including the terminator); otherwise 0.</param>
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
            charsWritten = ok ? (int)maxChars - 1
                : Marshal.GetLastWin32Error() == ErrorInsufficientBuffer ? (int)maxChars : 0;
            return ok;
        }
    }

    /// <summary>
    /// Determines whether a string is one produced by <see cref="TryProtect(string, Span{char}, out int, out CredentialProtectionType, bool)"/>, and if so, how it's bound.
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
