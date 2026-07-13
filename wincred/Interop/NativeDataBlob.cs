namespace wincred.Interop;

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeDataBlob
{
    public uint cbData;
    public byte* pbData;
}
