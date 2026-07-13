namespace wincred.Interop;

internal static unsafe class NativeStringHelpers
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static ReadOnlySpan<char> AsSpan(char* value)
    {
        if (value is null)
        {
            return default;
        }

        var length = 0;
        while (value[length] != '\0')
        {
            length++;
        }
        return new ReadOnlySpan<char>(value, length);
    }
}
