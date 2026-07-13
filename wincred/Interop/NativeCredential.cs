using System;
using System.Collections.Generic;
using System.Text;

namespace wincred.Interop;


[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeCredential
{
    private const int CRED_TYPE_GENERIC = 1;
    private const int CRED_PERSIST_LOCAL_MACHINE = 2;

    public uint Flags;
    public uint Type;
    public char* TargetName;
    public char* Comment;
    public long LastWritten;
    public uint CredentialBlobSize;
    public byte* CredentialBlob;
    public uint Persist;
    public uint AttributeCount;
    public nint Attributes;
    public char* TargetAlias;
    public char* UserName;
}