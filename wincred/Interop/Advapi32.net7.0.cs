namespace wincred.Interop;

internal static unsafe partial class Advapi32
{
    [LibraryImport("Advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CredWriteW(NativeCredential* credential, uint flags);

    [LibraryImport("Advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CredReadW(char* target, uint type, uint flags, out NativeCredential* credential);

    [LibraryImport("Advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CredDeleteW(char* target, uint type, uint flags);

    [LibraryImport("Advapi32.dll", SetLastError = true)]
    internal static partial void CredFree(nint buffer);

    [LibraryImport("Advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CredEnumerateW(char* filter, uint flags, out uint count, out nint credentials);

    [LibraryImport("Advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CredProtectW([MarshalAs(UnmanagedType.Bool)] bool fAsSelf, char* credentials, uint credentialsSize, char* protectedCredentials, ref uint maxChars, uint* protectionType);

    [LibraryImport("Advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CredUnprotectW([MarshalAs(UnmanagedType.Bool)] bool fAsSelf, char* protectedCredentials, uint protectedCredentialsSize, char* credentials, ref uint maxChars);

    [LibraryImport("Advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CredIsProtectedW(char* protectedCredentials, uint* protectionType);
}
