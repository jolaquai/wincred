namespace wincred.Interop;

internal static partial class Kernel32
{
    [LibraryImport("Kernel32.dll", SetLastError = true)]
    internal static partial nint LocalFree(nint hMem);
}
