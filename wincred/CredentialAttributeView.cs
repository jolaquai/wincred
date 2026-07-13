using wincred.Interop;

namespace wincred;

/// <summary>
/// Zero-copy view over a single attribute of a credential returned by <see cref="CredentialStore.TryRead"/>.
/// </summary>
public readonly unsafe ref struct CredentialAttributeView
{
    /// <summary>
    /// The attribute's name.
    /// </summary>
    public ReadOnlySpan<char> Keyword { get; }

    /// <summary>
    /// The attribute's value.
    /// </summary>
    public ReadOnlySpan<byte> Value { get; }

    internal CredentialAttributeView(NativeCredentialAttribute* native)
    {
        Keyword = NativeStringHelpers.AsSpan(native->Keyword);
        Value = native->Value is null ? default : new ReadOnlySpan<byte>(native->Value, (int)native->ValueSize);
    }
}
