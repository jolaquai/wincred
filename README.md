# `wincred`

Low-alloc interaction with the Windows Credential Manager and the DPAPI.

## WCM

Compat down to `netstandard2.0` (using `System.Memory` and `Microsoft.Bcl.HashCode`) with additional TFMs for even better perf where available.

Offers nearly every feature you could ever want from WCM while keeping allocations low, exposing nothing but `Span<>` (or custom `ref struct`s) wherever possible and sensible:
* Read and write credentials
* Enumerate credentials ("give me everything under `myapp/*`")
* Persistence support
* Attribute support

## DPAPI

Direct access to the DPAPI, independent of the credential store:
* Text encryption/decryption suitable for text storage (`advapi32`'s `CredProtect`/`CredUnprotect`/`CredIsProtected`)
* Arbitrary binary encryption/decryption (`crypt32`'s `CryptProtectData`/`CryptUnprotectData`)

## Quick Start

Runnable examples covering writes/reads/enumeration/deletion, raw binary secrets, attributes, and DPAPI live in [`Examples/Examples.cs`](Examples/Examples.cs). Build the solution and run the `Examples` project to try them immediately:

```
dotnet run --project Examples
```

## Contribution

Contact me on Discord @ `eyeoftheenemy` or open an issue here if you have any questions, suggestions or want to contribute!
