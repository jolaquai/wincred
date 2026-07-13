namespace wincred;

/// <summary>
/// An application-defined key/value pair to attach when writing a credential.
/// </summary>
public readonly struct CredentialAttributeEntry(string keyword, byte[] value)
{
    /// <summary>
    /// Max <see cref="CredentialStore.MaxAttributeKeywordLength"/> characters.
    /// </summary>
    public string Keyword { get; } = keyword;

    /// <summary>
    /// Max <see cref="CredentialStore.MaxAttributeValueSize"/> bytes.
    /// </summary>
    public byte[] Value { get; } = value;
}
