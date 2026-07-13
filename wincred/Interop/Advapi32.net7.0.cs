using System.Net;

namespace wincred.Interop;

internal static unsafe partial class Advapi32
{
    [LibraryImport("Advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CredWriteW(NativeCredential* credential, uint flags);

    [LibraryImport("Advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CredReadW(char* target, uint type, uint flags, out NativeCredential* credential);

    [LibraryImport("Advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CredDeleteW(char* target, uint type, uint flags);

    [LibraryImport("Advapi32.dll", SetLastError = true)]
    private static partial void CredFree(nint buffer);
}
