namespace wincred;

/// <summary>
/// An application-defined key/value pair to attach when writing a credential.
/// </summary>
public readonly struct CredentialAttributeEntry(string keyword, ReadOnlyMemory<byte> value) : IEquatable<CredentialAttributeEntry>
{
    /// <summary>
    /// Max <see cref="CredentialStore.MaxAttributeKeywordLength"/> characters.
    /// </summary>
    public string Keyword { get; } = keyword;

    /// <summary>
    /// Max <see cref="CredentialStore.MaxAttributeValueSize"/> bytes.
    /// </summary>
    public ReadOnlyMemory<byte> Value { get; } = value;

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public override bool Equals(object obj) => obj is CredentialAttributeEntry other && Equals(other);
    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool Equals(CredentialAttributeEntry other) => Keyword == other.Keyword && Value.Span.SequenceEqual(other.Value.Span);
    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hc = new HashCode();
        hc.Add(Keyword);
#if NET7_0_OR_GREATER
        hc.AddBytes(Value.Span);
#else
        var span = Value.Span;
        for (var i = 0; i < span.Length; i++)
        {
            hc.Add(span[i]);
        }
#endif
        return hc.ToHashCode();
    }
    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool operator ==(CredentialAttributeEntry left, CredentialAttributeEntry right) => left.Equals(right);
    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool operator !=(CredentialAttributeEntry left, CredentialAttributeEntry right) => !(left == right);
}
