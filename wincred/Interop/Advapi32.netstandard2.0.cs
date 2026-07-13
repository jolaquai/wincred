namespace wincred.Interop;

internal static unsafe class Advapi32
{

    [DllImport("Advapi32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredWriteW(NativeCredential* credential, uint flags);

    [DllImport("Advapi32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredReadW(char* target, uint type, uint flags, out NativeCredential* credential);

    [DllImport("Advapi32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredDeleteW(char* target, uint type, uint flags);

    [DllImport("Advapi32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern void CredFree(nint buffer);
}
