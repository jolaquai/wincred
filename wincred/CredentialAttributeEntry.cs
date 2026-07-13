namespace wincred;

/// <summary>
/// An application-defined key/value pair to attach when writing a credential.
/// </summary>
public readonly struct CredentialAttributeEntry(string keyword, byte[] value) : IEquatable<CredentialAttributeEntry>
{
    /// <summary>
    /// Max <see cref="CredentialStore.MaxAttributeKeywordLength"/> characters.
    /// </summary>
    public string Keyword { get; } = keyword;

    /// <summary>
    /// Max <see cref="CredentialStore.MaxAttributeValueSize"/> bytes.
    /// </summary>
    public byte[] Value { get; } = value;

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public override bool Equals(object obj) => obj is CredentialAttributeEntry other && Equals(other);
    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool Equals(CredentialAttributeEntry other) => Keyword == other.Keyword && Value == other.Value;
    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public override int GetHashCode() => HashCode.Combine(Keyword, Value);
    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool operator ==(CredentialAttributeEntry left, CredentialAttributeEntry right) => left.Equals(right);
    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool operator !=(CredentialAttributeEntry left, CredentialAttributeEntry right) => !(left == right);
}
