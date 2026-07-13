namespace wincred.Interop;

internal static unsafe class Advapi32
{

    [DllImport("Advapi32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CredWriteW(NativeCredential* credential, uint flags);

    [DllImport("Advapi32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CredReadW(char* target, uint type, uint flags, out NativeCredential* credential);

    [DllImport("Advapi32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CredDeleteW(char* target, uint type, uint flags);

    [DllImport("Advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern void CredFree(nint buffer);

    [DllImport("Advapi32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CredEnumerateW(char* filter, uint flags, out uint count, out nint credentials);

    [DllImport("Advapi32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CredProtectW([MarshalAs(UnmanagedType.Bool)] bool fAsSelf, char* credentials, uint credentialsSize, char* protectedCredentials, ref uint maxChars, uint* protectionType);

    [DllImport("Advapi32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CredUnprotectW([MarshalAs(UnmanagedType.Bool)] bool fAsSelf, char* protectedCredentials, uint protectedCredentialsSize, char* credentials, ref uint maxChars);

    [DllImport("Advapi32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CredIsProtectedW(char* protectedCredentials, uint* protectionType);
}
