namespace wincred.Interop;

internal static class Kernel32
{
    [DllImport("Kernel32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern nint LocalFree(nint hMem);
}
