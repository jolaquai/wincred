namespace wincred.Interop;

internal static unsafe partial class Crypt32
{
    [LibraryImport("Crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptProtectData(NativeDataBlob* dataIn, char* dataDescr, NativeDataBlob* entropy, nint reserved, nint promptStruct, uint flags, NativeDataBlob* dataOut);

    [LibraryImport("Crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptUnprotectData(NativeDataBlob* dataIn, nint dataDescr, NativeDataBlob* entropy, nint reserved, nint promptStruct, uint flags, NativeDataBlob* dataOut);
}
