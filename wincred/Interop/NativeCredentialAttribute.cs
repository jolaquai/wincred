namespace wincred.Interop;

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeCredentialAttribute
{
    public char* Keyword;
    public uint Flags;
    public uint ValueSize;
    public byte* Value;
}
