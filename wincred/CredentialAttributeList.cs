using wincred.Interop;

namespace wincred;

/// <summary>
/// Zero-copy, indexable view over a credential's attributes.
/// </summary>
public readonly unsafe ref struct CredentialAttributeList
{
    private readonly NativeCredentialAttribute* _attributes;

    /// <summary>
    /// The number of attributes.
    /// </summary>
    public int Count { get; }

    internal CredentialAttributeList(NativeCredentialAttribute* attributes, int count)
    {
        _attributes = attributes;
        Count = count;
    }

    /// <summary>
    /// Gets the attribute at <paramref name="index"/>.
    /// </summary>
    public CredentialAttributeView this[int index]
    {
        get
        {
            if ((uint)index >= (uint)Count)
            {
                ThrowHelpers.ThrowIndexOutOfRange();
            }
            return new CredentialAttributeView(_attributes + index);
        }
    }

    /// <summary>
    /// Returns an enumerator over the attributes.
    /// </summary>
    public Enumerator GetEnumerator() => new(this);

    /// <summary>
    /// Enumerates a <see cref="CredentialAttributeList"/>.
    /// </summary>
    public ref struct Enumerator
    {
        private readonly CredentialAttributeList _list;
        private int _index;

        internal Enumerator(CredentialAttributeList list)
        {
            _list = list;
            _index = -1;
        }

        /// <summary>
        /// The current attribute.
        /// </summary>
        public readonly CredentialAttributeView Current => _list[_index];

        /// <summary>
        /// Advances to the next attribute.
        /// </summary>
        public bool MoveNext() => ++_index < _list.Count;
    }
}
