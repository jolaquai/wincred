using System.Buffers;

using wincred.Interop;

namespace wincred;

/// <summary>
/// Low-alloc access to the Windows Credential Manager.
/// </summary>
public static unsafe class CredentialStore
{
    // CRED_ENUMERATE_ALL_CREDENTIALS
    private const uint EnumerateAllCredentialsFlag = 0x1;

    /// <summary>
    /// Max secret blob size, in bytes.
    /// </summary>
    public const int MaxSecretSize = 5 * 512;

    /// <summary>
    /// Max attributes per credential.
    /// </summary>
    public const int MaxAttributeCount = 64;

    /// <summary>
    /// Max attribute keyword length, in characters.
    /// </summary>
    public const int MaxAttributeKeywordLength = 256;

    /// <summary>
    /// Max attribute value size, in bytes.
    /// </summary>
    public const int MaxAttributeValueSize = 256;

    /// <summary>
    /// Writes (or overwrites) a credential.
    /// </summary>
    /// <param name="target">The name to store and look the credential up under.</param>
    /// <param name="secret">The raw secret to store, up to <see cref="MaxSecretSize"/> bytes.</param>
    /// <param name="type"><see cref="CredentialType.DomainCertificate"/>/<see cref="CredentialType.GenericCertificate"/> are rejected by the OS; this just returns <see langword="false"/> for them.</param>
    /// <param name="userName">The associated username, if any.</param>
    /// <param name="comment">A free-text comment, if any.</param>
    /// <param name="persistence"></param>
    /// <param name="attributes">Application-defined key/value pairs to attach, up to <see cref="MaxAttributeCount"/> entries.</param>
    /// <returns><see langword="true"/> if written.</returns>
    public static bool TryWrite(string target, ReadOnlySpan<byte> secret, CredentialType type = CredentialType.Generic, string userName = null, string comment = null, CredentialPersistence persistence = CredentialPersistence.LocalMachine, ReadOnlySpan<CredentialAttributeEntry> attributes = default)
    {
        if (type is CredentialType.DomainCertificate or CredentialType.GenericCertificate)
        {
            return false;
        }
        if (string.IsNullOrEmpty(target))
        {
            ThrowHelpers.ThrowNullArgumentTarget();
        }
        if (secret.Length > MaxSecretSize)
        {
            ThrowHelpers.ThrowOutOfRangeSecretSize(secret.Length);
        }
        if (attributes.Length > MaxAttributeCount)
        {
            ThrowHelpers.ThrowTooManyAttributes(attributes.Length);
        }
        for (var i = 0; i < attributes.Length; i++)
        {
            var keyword = attributes[i].Keyword;
            if (keyword is null)
            {
                ThrowHelpers.ThrowNullAttributeKeyword();
            }
            if (keyword.Length > MaxAttributeKeywordLength)
            {
                ThrowHelpers.ThrowAttributeKeywordTooLong(keyword);
            }
            if (attributes[i].Value.Length > MaxAttributeValueSize)
            {
                ThrowHelpers.ThrowAttributeValueTooLarge(attributes[i].Value.Length);
            }
        }

        var attributeCount = attributes.Length;

        Span<NativeCredentialAttribute> natives = stackalloc NativeCredentialAttribute[attributeCount];

        // keyword is a string -> GCHandle-pinnable; blittable (one IntPtr), so stackalloc, bounded by MaxAttributeCount (64)
        Span<GCHandle> keywordHandles = stackalloc GCHandle[attributeCount];
        // MemoryHandle holds a managed ref, so it can't live in a stackalloc'd span; heap-alloc only when there are attributes
        var valueHandles = attributeCount == 0 ? null : new MemoryHandle[attributeCount];
        try
        {
            for (var i = 0; i < attributeCount; i++)
            {
                var entry = attributes[i];

                keywordHandles[i] = GCHandle.Alloc(entry.Keyword, GCHandleType.Pinned);
                natives[i].Keyword = (char*)keywordHandles[i].AddrOfPinnedObject();
                natives[i].Flags = 0;

                var value = entry.Value;
                natives[i].ValueSize = (uint)value.Length;
                if (!value.IsEmpty)
                {
                    valueHandles[i] = value.Pin();
                    natives[i].Value = (byte*)valueHandles[i].Pointer;
                }
            }

            fixed (char* t = target)
            fixed (char* u = userName)
            fixed (char* c = comment)
            fixed (byte* s = secret)
            fixed (NativeCredentialAttribute* a = natives)
            {
                var native = new NativeCredential
                {
                    Type = (uint)type,
                    TargetName = t,
                    Comment = c,
                    CredentialBlobSize = (uint)secret.Length,
                    CredentialBlob = s, // `fixed` over an empty span already yields null
                    Persist = (uint)persistence,
                    UserName = u,
                    AttributeCount = (uint)attributeCount,
                    Attributes = a
                };
                return Advapi32.CredWriteW(&native, 0);
            }
        }
        finally
        {
            foreach (var handle in keywordHandles)
            {
                if (handle.IsAllocated)
                {
                    handle.Free();
                }
            }
            if (valueHandles is not null)
            {
                foreach (var handle in valueHandles)
                {
                    handle.Dispose(); // default MemoryHandle.Dispose is a no-op
                }
            }
        }
    }

    /// <summary>
    /// Writes (or overwrites) a credential holding a plaintext password.
    /// </summary>
    /// <param name="target">The name to store and look the credential up under.</param>
    /// <param name="password">The password, reinterpreted as UTF-16LE bytes with no allocation.</param>
    /// <param name="type"><see cref="CredentialType.DomainCertificate"/>/<see cref="CredentialType.GenericCertificate"/> are rejected by the OS; this just returns <see langword="false"/> for them.</param>
    /// <param name="userName">The associated username, if any.</param>
    /// <param name="comment">A free-text comment, if any.</param>
    /// <param name="persistence"></param>
    /// <param name="attributes">Application-defined key/value pairs to attach, up to <see cref="MaxAttributeCount"/> entries.</param>
    /// <returns><see langword="true"/> if written.</returns>
    public static bool TryWrite(string target, ReadOnlySpan<char> password, CredentialType type = CredentialType.Generic, string userName = null, string comment = null, CredentialPersistence persistence = CredentialPersistence.LocalMachine, ReadOnlySpan<CredentialAttributeEntry> attributes = default)
        => TryWrite(target, MemoryMarshal.AsBytes(password), type, userName, comment, persistence, attributes);

    /// <summary>
    /// Reads a credential. The returned <see cref="CredentialReader"/> must be disposed.
    /// </summary>
    /// <param name="target">The name the credential was stored under.</param>
    /// <param name="reader">A zero-copy view over the credential, valid until disposed.</param>
    /// <param name="type">The credential type to look up.</param>
    /// <returns><see langword="true"/> if found.</returns>
    public static bool TryRead(string target, out CredentialReader reader, CredentialType type = CredentialType.Generic)
    {
        if (string.IsNullOrEmpty(target))
        {
            ThrowHelpers.ThrowNullArgumentTarget();
        }

        fixed (char* t = target)
        {
            if (Advapi32.CredReadW(t, (uint)type, 0, out var native))
            {
                reader = new CredentialReader(native);
                return true;
            }
        }

        reader = default;
        return false;
    }

    /// <summary>
    /// Deletes a credential.
    /// </summary>
    /// <param name="target">The name the credential was stored under.</param>
    /// <param name="type">The credential type to delete.</param>
    /// <returns><see langword="true"/> if deleted.</returns>
    public static bool Delete(string target, CredentialType type = CredentialType.Generic)
    {
        if (string.IsNullOrEmpty(target))
        {
            ThrowHelpers.ThrowNullArgumentTarget();
        }

        fixed (char* t = target)
        {
            return Advapi32.CredDeleteW(t, (uint)type, 0);
        }
    }

    /// <summary>
    /// Renames via write-new-then-delete-old (Windows has no atomic rename); not transactional. A failure after the new
    /// name is written degrades to a duplicate, never to data loss.
    /// </summary>
    /// <param name="oldTarget">The credential's current target name.</param>
    /// <param name="newTarget">The target name to move it to.</param>
    /// <param name="type">The credential type.</param>
    /// <returns><see langword="true"/> if the credential existed and was moved.</returns>
    public static bool TryRename(string oldTarget, string newTarget, CredentialType type = CredentialType.Generic)
    {
        if (string.IsNullOrEmpty(newTarget))
        {
            ThrowHelpers.ThrowNullArgumentTarget();
        }
        if (!TryRead(oldTarget, out var reader, type))
        {
            return false;
        }

        using (reader)
        {
            // copy the whole native record and swap only the target name: preserves Flags/TargetAlias/blob verbatim and
            // never lands the plaintext secret on the managed heap. Backing buffers stay valid until `reader` is disposed.
            fixed (char* nt = newTarget)
            {
                var native = *reader.Raw;
                native.TargetName = nt;
                if (!Advapi32.CredWriteW(&native, 0))
                {
                    return false;
                }
            }

            // new name is written; drop the old entry unless it's the same key (case-insensitive), which the write just overwrote
            if (!string.Equals(oldTarget, newTarget, StringComparison.OrdinalIgnoreCase))
            {
                Delete(oldTarget, type);
            }
            return true;
        }
    }

    /// <summary>
    /// Enumerates credentials. The returned <see cref="CredentialEnumerator"/> must be disposed.
    /// </summary>
    /// <param name="enumerator">Zero-copy view over matches, valid until disposed.</param>
    /// <param name="filter">Target name filter, one trailing wildcard only (e.g. <c>"myapp*"</c>). Null enumerates all of the current user's.</param>
    /// <param name="allCredentials">Include otherwise-excluded credentials; only applies when <paramref name="filter"/> is null.</param>
    /// <returns><see langword="true"/> if at least one matched.</returns>
    public static bool TryEnumerate(out CredentialEnumerator enumerator, string filter = null, bool allCredentials = false)
    {
        var flags = filter is null && allCredentials ? EnumerateAllCredentialsFlag : 0;

        fixed (char* f = filter)
        {
            if (Advapi32.CredEnumerateW(f, flags, out var count, out var credentials))
            {
                enumerator = new CredentialEnumerator(credentials, (int)count);
                return true;
            }
        }

        enumerator = default;
        return false;
    }
}
