namespace wincred.Interop;

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeCredential
{
    public uint Flags;
    public uint Type;
    public char* TargetName;
    public char* Comment;
    public long LastWritten;
    public uint CredentialBlobSize;
    public byte* CredentialBlob;
    public uint Persist;
    public uint AttributeCount;
    public NativeCredentialAttribute* Attributes;
    public char* TargetAlias;
    public char* UserName;
}
