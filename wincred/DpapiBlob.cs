using wincred.Interop;

namespace wincred;

/// <summary>
/// Zero-copy view over a buffer allocated by <see cref="Dpapi"/>. Must be disposed.
/// </summary>
public unsafe ref struct DpapiBlob : IDisposable
{
    private nint _pointer;
    private readonly int _length;

    internal DpapiBlob(nint pointer, int length)
    {
        _pointer = pointer;
        _length = length;
    }

    /// <summary>The blob's bytes.</summary>
    public readonly ReadOnlySpan<byte> Data => _pointer == 0 ? default : new ReadOnlySpan<byte>((void*)_pointer, _length);

    /// <summary>Releases the buffer.</summary>
    public void Dispose()
    {
        if (_pointer != 0)
        {
            Kernel32.LocalFree(_pointer);
            _pointer = 0;
        }
    }
}
