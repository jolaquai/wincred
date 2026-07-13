using System.Diagnostics.CodeAnalysis;

namespace wincred;

#pragma warning disable CA2208 // Instantiate argument exceptions correctly

internal static class ThrowHelpers
{
    // hoisted: interpolation isn't const
    private static readonly string OutOfRangeSecretSizeMessage = $"Credential secret must not exceed {CredentialStore.MaxSecretSize} bytes.";
    private static readonly string TooManyAttributesMessage = $"A credential must not have more than {CredentialStore.MaxAttributeCount} attributes.";
    private static readonly string AttributeKeywordTooLongMessage = $"An attribute keyword must not exceed {CredentialStore.MaxAttributeKeywordLength} characters.";
    private static readonly string AttributeValueTooLargeMessage = $"An attribute value must not exceed {CredentialStore.MaxAttributeValueSize} bytes.";

    [MethodImpl(MethodImplOptions.NoInlining)]
    [DoesNotReturn]
    internal static void ThrowOutOfRangeSecretSize(int secretLength) => throw new ArgumentOutOfRangeException("secret", secretLength, OutOfRangeSecretSizeMessage);
    [MethodImpl(MethodImplOptions.NoInlining)]
    [DoesNotReturn]
    internal static void ThrowNullArgumentTarget() => throw new ArgumentException("Target name must not be null or empty.", "target");
    [MethodImpl(MethodImplOptions.NoInlining)]
    [DoesNotReturn]
    internal static void ThrowNullArgumentCredentials() => throw new ArgumentException("Credentials must not be null or empty.", "credentials");
    [MethodImpl(MethodImplOptions.NoInlining)]
    [DoesNotReturn]
    internal static void ThrowInvalidUtf16Secret() => throw new FormatException("The credential's secret is not well-formed UTF-16 text.");
    [MethodImpl(MethodImplOptions.NoInlining)]
    [DoesNotReturn]
    internal static void ThrowTooManyAttributes(int count) => throw new ArgumentOutOfRangeException("attributes", count, TooManyAttributesMessage);
    [MethodImpl(MethodImplOptions.NoInlining)]
    [DoesNotReturn]
    internal static void ThrowNullAttributeKeyword() => throw new ArgumentException("An attribute keyword must not be null.", "attributes");
    [MethodImpl(MethodImplOptions.NoInlining)]
    [DoesNotReturn]
    internal static void ThrowAttributeKeywordTooLong(string keyword) => throw new ArgumentOutOfRangeException("attributes", keyword, AttributeKeywordTooLongMessage);
    [MethodImpl(MethodImplOptions.NoInlining)]
    [DoesNotReturn]
    internal static void ThrowAttributeValueTooLarge(int size) => throw new ArgumentOutOfRangeException("attributes", size, AttributeValueTooLargeMessage);
    [MethodImpl(MethodImplOptions.NoInlining)]
    [DoesNotReturn]
    internal static void ThrowIndexOutOfRange() => throw new ArgumentOutOfRangeException("index");
}

#if NETSTANDARD2_0
// inert polyfill, avoids #if per throw helper
internal class DoesNotReturnAttribute : Attribute { }
#endif