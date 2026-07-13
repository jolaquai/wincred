using wincred.Interop;

namespace wincred;

/// <summary>
/// Zero-copy view over a credential from <see cref="CredentialStore.TryRead"/>. Must be disposed. A <see langword="default"/> instance is unsafe to use.
/// </summary>
public unsafe ref struct CredentialReader : IDisposable
{
    private NativeCredential* _credential;
    private readonly bool _owned;

    internal CredentialReader(NativeCredential* credential) : this(credential, owned: true) { }

    // owned: false when vended by CredentialEnumerator, which owns the shared buffer instead
    internal CredentialReader(NativeCredential* credential, bool owned)
    {
        _credential = credential;
        _owned = owned;
    }

    /// <summary>
    /// The decrypted secret blob.
    /// </summary>
    public readonly ReadOnlySpan<byte> Secret
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => _credential->CredentialBlob is null ? default : new ReadOnlySpan<byte>(_credential->CredentialBlob, (int)_credential->CredentialBlobSize);
    }

    /// <summary>
    /// Secret as UTF-16LE text (a plaintext password). Throws <see cref="FormatException"/> if not well-formed UTF-16; use <see cref="UnsafePassword"/> to skip that check.
    /// </summary>
    public readonly ReadOnlySpan<char> Password
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get
        {
            var secret = Secret;
            if ((secret.Length & 1) != 0)
            {
                ThrowHelpers.ThrowInvalidUtf16Secret();
            }

            var chars = MemoryMarshal.Cast<byte, char>(secret);
            if (!IsWellFormedUtf16(chars))
            {
                ThrowHelpers.ThrowInvalidUtf16Secret();
            }

            return chars;
        }
    }

    /// <summary>
    /// Secret as UTF-16LE text, unchecked. UB if the secret isn't valid UTF-16.
    /// </summary>
    public readonly ReadOnlySpan<char> UnsafePassword
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => MemoryMarshal.Cast<byte, char>(Secret);
    }

    /// <summary>
    /// The credential's type.
    /// </summary>
    public readonly CredentialType Type
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => (CredentialType)_credential->Type;
    }

    /// <summary>
    /// The target name it was stored under.
    /// </summary>
    public readonly ReadOnlySpan<char> TargetName
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => AsSpan(_credential->TargetName);
    }

    /// <summary>
    /// Associated username, if any.
    /// </summary>
    public readonly ReadOnlySpan<char> UserName
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => AsSpan(_credential->UserName);
    }

    /// <summary>
    /// Associated comment, if any.
    /// </summary>
    public readonly ReadOnlySpan<char> Comment
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => AsSpan(_credential->Comment);
    }

    /// <summary>
    /// Persistence scope it was written with.
    /// </summary>
    public readonly CredentialPersistence Persistence
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => (CredentialPersistence)_credential->Persist;
    }

    /// <summary>
    /// UTC time of last write.
    /// </summary>
    public readonly DateTime LastWritten
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => DateTime.FromFileTimeUtc(_credential->LastWritten);
    }

    /// <summary>
    /// Application-defined attributes, if any.
    /// </summary>
    public readonly CredentialAttributeList Attributes
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => new(_credential->Attributes, (int)_credential->AttributeCount);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ReadOnlySpan<char> AsSpan(char* value) => NativeStringHelpers.AsSpan(value);

    private static bool IsWellFormedUtf16(ReadOnlySpan<char> chars)
    {
        for (var i = 0; i < chars.Length; i++)
        {
            if (char.IsHighSurrogate(chars[i]))
            {
                if (i + 1 >= chars.Length || !char.IsLowSurrogate(chars[i + 1]))
                {
                    return false;
                }
                i++;
            }
            else if (char.IsLowSurrogate(chars[i]))
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Releases the buffer backing this reader.
    /// </summary>
    public void Dispose()
    {
        if (_owned && _credential is not null)
        {
            Advapi32.CredFree((nint)_credential);
        }
        _credential = null;
    }
}
