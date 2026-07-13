using wincred.Interop;

namespace wincred;

/// <summary>
/// Zero-copy view over credentials from <see cref="CredentialStore.TryEnumerate"/>. One shared allocation, freed by <see cref="Dispose"/>; vended readers don't own it.
/// </summary>
public unsafe ref struct CredentialEnumerator : IDisposable
{
    private nint _base;
    private NativeCredential** _credentials;

    /// <summary>
    /// The number of credentials.
    /// </summary>
    public int Count { get; }

    internal CredentialEnumerator(nint rawBase, int count)
    {
        _base = rawBase;
        _credentials = (NativeCredential**)rawBase;
        Count = count;
    }

    /// <summary>
    /// Gets a non-owning view over the credential at <paramref name="index"/>. Do not dispose it; disposing this enumerator frees it.
    /// </summary>
    public readonly CredentialReader this[int index]
    {
        get
        {
            if ((uint)index >= (uint)Count)
            {
                ThrowHelpers.ThrowIndexOutOfRange();
            }
            return new CredentialReader(_credentials[index], owned: false);
        }
    }

    /// <summary>
    /// Returns an enumerator over the credentials.
    /// </summary>
    public Enumerator GetEnumerator() => new(this);

    /// <summary>
    /// Enumerates a <see cref="CredentialEnumerator"/>.
    /// </summary>
    public ref struct Enumerator
    {
        private readonly CredentialEnumerator _list;
        private int _index;

        internal Enumerator(CredentialEnumerator list)
        {
            _list = list;
            _index = -1;
        }

        /// <summary>
        /// The current credential.
        /// </summary>
        public readonly CredentialReader Current => _list[_index];

        /// <summary>
        /// Advances to the next credential.
        /// </summary>
        public bool MoveNext() => ++_index < _list.Count;
    }

    /// <summary>
    /// Releases the single native allocation backing every entry in this enumerator.
    /// </summary>
    public void Dispose()
    {
        if (_base != 0)
        {
            Advapi32.CredFree(_base);
            _base = 0;
        }
        _credentials = null;
    }
}
