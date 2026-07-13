using System.Security.Cryptography;

using wincred;

// Write a password (stored as UTF-16LE bytes, no allocation for the conversion)
CredentialStore.TryWrite("myapp/api-token", "s3cr3t".AsSpan(), userName: "j.laquai");

// Read it back
if (CredentialStore.TryRead("myapp/api-token", out var reader))
{
    using (reader)
    {
        Console.WriteLine(reader.Password.ToString());
        Console.WriteLine(reader.UserName.ToString());
    }
}

// Enumerate everything under a prefix
if (CredentialStore.TryEnumerate(out var enumerator, filter: "myapp/*"))
{
    using (enumerator)
    {
        foreach (var cred in enumerator)
        {
            Console.WriteLine(cred.TargetName.ToString());
        }
    }
}

// Delete
CredentialStore.Delete("myapp/api-token");

// Raw binary secrets (keys, tokens, anything that isn't UTF-16 text) go through the
// ReadOnlySpan<byte> overload directly, and come back via reader.Secret instead of reader.Password
var keyBytes = RandomNumberGenerator.GetBytes(32);
CredentialStore.TryWrite("myapp/signing-key", keyBytes);

if (CredentialStore.TryRead("myapp/signing-key", out var keyReader))
{
    using (keyReader)
    {
        ReadOnlySpan<byte> key = keyReader.Secret;
    }
}

// Attributes go through the same TryWrite overloads
CredentialAttributeEntry[] attributes = [new("env", "prod"u8.ToArray())];
CredentialStore.TryWrite("myapp/api-token-with-attrs", keyBytes, attributes: attributes);
CredentialStore.Delete("myapp/api-token-with-attrs");
CredentialStore.Delete("myapp/signing-key");

// DPAPI helpers work independently of the credential store, e.g. for encrypting secrets
// you keep in your own config file
var plaintextBytes = "config-secret"u8.ToArray();
if (Dpapi.TryProtect(plaintextBytes, out var blob))
{
    using (blob)
    {
        File.WriteAllBytes("secret.bin", blob.Data.ToArray());
    }
}
