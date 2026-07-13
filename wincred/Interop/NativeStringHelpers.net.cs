namespace wincred.Interop;

internal static unsafe class NativeStringHelpers
{
    // vectorized strlen; returns empty for a null pointer
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static ReadOnlySpan<char> AsSpan(char* value) => MemoryMarshal.CreateReadOnlySpanFromNullTerminated(value);
}
