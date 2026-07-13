using wincred.Interop;

namespace wincred;

/// <summary>
/// Raw DPAPI encrypt/decrypt for arbitrary binary data, via <c>CryptProtectData</c>/<c>CryptUnprotectData</c>.
/// Unlike <see cref="CredentialProtector"/>, this has no text encoding baked in and no null-terminator requirement.
/// </summary>
public static unsafe class Dpapi
{
    // CRYPTPROTECT_UI_FORBIDDEN: never allowed to prompt
    private const uint UiForbiddenFlag = 0x1;
    // CRYPTPROTECT_LOCAL_MACHINE
    private const uint LocalMachineFlag = 0x4;

    /// <summary>
    /// Encrypts <paramref name="data"/>. The returned <see cref="DpapiBlob"/> must be disposed.
    /// </summary>
    /// <param name="data">The plaintext to encrypt.</param>
    /// <param name="result">The encrypted bytes.</param>
    /// <param name="entropy">Extra secret mixed into the encryption; the same bytes must be passed to <see cref="TryUnprotect"/>.</param>
    /// <param name="localMachine">If <see langword="true"/>, any user on this machine can decrypt it. If <see langword="false"/> (default), only the current user can.</param>
    /// <returns><see langword="true"/> if encrypted.</returns>
    public static bool TryProtect(ReadOnlySpan<byte> data, out DpapiBlob result, ReadOnlySpan<byte> entropy = default, bool localMachine = false)
    {
        fixed (byte* d = data)
        fixed (byte* e = entropy)
        {
            var dataIn = new NativeDataBlob { cbData = (uint)data.Length, pbData = d };
            var entropyBlob = new NativeDataBlob { cbData = (uint)entropy.Length, pbData = e };
            var entropyPtr = entropy.IsEmpty ? null : &entropyBlob;

            var flags = UiForbiddenFlag | (localMachine ? LocalMachineFlag : 0);
            NativeDataBlob dataOut;
            var ok = Crypt32.CryptProtectData(&dataIn, null, entropyPtr, 0, 0, flags, &dataOut);
            result = ok ? new DpapiBlob((nint)dataOut.pbData, (int)dataOut.cbData) : default;
            return ok;
        }
    }

    /// <summary>
    /// Reverses <see cref="TryProtect"/>. The returned <see cref="DpapiBlob"/> must be disposed.
    /// </summary>
    /// <param name="data">The encrypted bytes, as produced by <see cref="TryProtect"/>.</param>
    /// <param name="result">The decrypted plaintext.</param>
    /// <param name="entropy">Must match the value passed to <see cref="TryProtect"/> when the data was encrypted.</param>
    /// <param name="localMachine">Must match the value passed to <see cref="TryProtect"/> when the data was encrypted.</param>
    /// <returns><see langword="true"/> if decrypted.</returns>
    public static bool TryUnprotect(ReadOnlySpan<byte> data, out DpapiBlob result, ReadOnlySpan<byte> entropy = default, bool localMachine = false)
    {
        fixed (byte* d = data)
        fixed (byte* e = entropy)
        {
            var dataIn = new NativeDataBlob { cbData = (uint)data.Length, pbData = d };
            var entropyBlob = new NativeDataBlob { cbData = (uint)entropy.Length, pbData = e };
            var entropyPtr = entropy.IsEmpty ? null : &entropyBlob;

            var flags = UiForbiddenFlag | (localMachine ? LocalMachineFlag : 0);
            NativeDataBlob dataOut;
            var ok = Crypt32.CryptUnprotectData(&dataIn, 0, entropyPtr, 0, 0, flags, &dataOut);
            result = ok ? new DpapiBlob((nint)dataOut.pbData, (int)dataOut.cbData) : default;
            return ok;
        }
    }
}
