namespace wincred.Interop;

internal static unsafe class Crypt32
{
    [DllImport("Crypt32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptProtectData(NativeDataBlob* dataIn, char* dataDescr, NativeDataBlob* entropy, nint reserved, nint promptStruct, uint flags, NativeDataBlob* dataOut);

    [DllImport("Crypt32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptUnprotectData(NativeDataBlob* dataIn, nint dataDescr, NativeDataBlob* entropy, nint reserved, nint promptStruct, uint flags, NativeDataBlob* dataOut);
}
