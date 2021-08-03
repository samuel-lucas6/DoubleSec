[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/samuel-lucas6/DoubleSec/blob/main/LICENSE)
[![CodeQL](https://github.com/samuel-lucas6/DoubleSec/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/samuel-lucas6/DoubleSec/actions)

# DoubleSec
DoubleSec is a simple, double-paranoid encryption library inspired by [TripleSec](https://keybase.io/triplesec/). It encrypts data with XChaCha20 and AES-CTR to account for a future compromise of one of these ciphers.

To make things simple, you just need to pass in a message and a password or shared secret. DoubleSec derives keys using Argon2id when using a password and salted BLAKE2b when using a shared secret. Then HMAC-SHA512 and BLAKE2b-512 are used to authenticate the ciphertext and headers.

## FAQ
### Why would I use cascade encryption?
Example use cases include storing data for a long period of time and sharing data with a remote server, meaning you cannot guarantee that that data will ever be deleted. In these scenarios, cascade encryption arguably provides an additional layer of protection. However, [many](https://blog.cryptographyengineering.com/2012/02/02/multiple-encryption/) argue that it solves a problem that *mostly* does not exist. When you need speed, you should avoid cascade encryption.

### Why should I use this library?
Because it improves on [TripleSec](https://keybase.io/triplesec/) in several respects. For instance, XChaCha20 is used instead of XSalsa20, Argon2id is used instead of scrypt, stronger password hashing parameters are used, the authentication tags are in the typical position, and BLAKE2b is faster than HMAC-SHA3.

### Is this provably secure?
As noted by the authors of [TripleSec](https://keybase.io/triplesec/), there is not an exact proof of security for cascade encryption using stream ciphers. However, the consensus is that this encryption can only be broken if all of the algorithms are broken. Both HMAC-SHA512 and BLAKE2b would have to be broken in order to malleate a message, meaning DoubleSec has IND-CCA2 security.

### Is there a streaming interface?
Not at the moment. This might be worked on in the future. However, if you want speed, then you should avoid cascade encryption.

## Usage
### Installation
1. Install the [Sodium.Core](https://www.nuget.org/packages/Sodium.Core) NuGet package in [Visual Studio](https://docs.microsoft.com/en-us/nuget/quickstart/install-and-use-a-package-in-visual-studio).
2. Download the latest [release](https://github.com/samuel-lucas6/DoubleSec/releases).
3. Move the downloaded DLL file into your Visual Studio project folder.
3. Click on the ```Project``` tab and ```Add Project Reference...``` in Visual Studio.
4. Go to ```Browse```, click the ```Browse``` button, and select the downloaded DLL file.

### Password
⚠️**WARNING: Always use a strong password (20+ random characters or a 6+ random word passphrase).**
```c#
// The password should ideally come from a char array since strings are immutable
byte[] password = Encoding.UTF8.GetBytes("Upper-Correct-Breeder-Uncle-Poise-Wilt9");

// The message could be a file
byte[] message = Encoding.UTF8.GetBytes("This is an example.");

// Encrypt the message
byte[] ciphertext = DoubleSecV1.EncryptUsingPassword(password, message);
```

### Shared secret
⚠️**WARNING: DoubleSec does not do the key exchange for you. Make sure you research the most suitable method of key exchange for your application. In many cases, you will want the key exchange to be [authenticated](https://neilmadden.blog/2018/11/26/public-key-authenticated-encryption-and-why-you-want-it-part-ii/).**
```c#
// The shared secret is obtained by performing a key exchange with an algorithm like X25519
byte[] sharedSecret = ScalarMult.Mult(privateKey, publicKey);

// The message could be a file
byte[] message = Encoding.UTF8.GetBytes("This is an example.");

// Encrypt the message
byte[] ciphertext = DoubleSecV1.EncryptUsingSharedSecret(sharedSecret, message);
```

## Design
### Format
`magicBytes || version || salt || iv || ciphertext || hmacTag || blake2bTag`
- `magicBytes`: `Encoding.UTF8.GetBytes("DOUBLESEC")` (9 bytes). This identifies a DoubleSec encrypted ciphertext.
- `version`: `BitConversion.GetBytes(1)` (2 bytes). This will only be incremented when the file structure/cryptographic algorithms change.
- `salt`: a random salt used for key derivation (16 bytes).
- `iv`: a random initialization vector used as the counter for AES-CTR (16 bytes).
- `ciphertext`: `AesCTR.Encrypt(XChaCha20.Encrypt(plaintext))` (length of the message).
- `hmacTag`: the HMAC-SHA512 tag for the ciphertext and headers (64 bytes).
- `blake2bTag`: the BLAKE2b-512 tag for the ciphertext and headers (64 bytes).

### Algorithms
DoubleSec encrypts data in four steps:

1. **Key derivation**: the user's password is hashed using Argon2id, with a random 128-bit salt, a memory size of 256 MiB, an iteration count of 12, and an output length of 192 bytes. The output is split into two 256-bit encryption keys and two 512-bit MAC keys. If the user provides a shared secret instead of a password, then salted BLAKE2b is used to derive four separate keys. The first 128-bit salt is randomly generated before being incremented for each call to BLAKE2b. Each call also uses a different context message for domain separation.

2. **IV/nonce generation**: a cryptographically secure random number generator is used to generate a 192-bit nonce for XChaCha20 and a 128-bit IV for AES-CTR.

3. **Cascade encryption**: the plaintext message is encrypted using XChaCha20, with the derived encryption key and randomly generated nonce. The nonce is then prepended to the ciphertext. Next, AES-CTR is used to encrypt the XChaCha20 nonce and ciphertext with the derived encryption key and randomly generated IV. The AES-CTR IV and headers (magic bytes, version, and salt) are then prepended to the AES-CTR ciphertext.

4. **Authentication**: the headers and AES-CTR encrypted ciphertext are authenticated using HMAC-SHA512 and BLAKE2b-512 with different keys. These 512-bit authentication tags are then appended to the ciphertext.

### Considerations
This design shares the same benefits as [TripleSec](https://keybase.io/triplesec/) over Bruce Shneier's recommendation in *Applied Cryptography* (Section 15.8):
- DoubleSec encrypts the inner nonce to avoid exposing an input unnecessarily. This seems sensible, but it has not been proven that this makes the scheme more secure.
- The output is the same size as the plaintext message plus the length of the headers and authentication tags. Whilst this does not hide the length of the plaintext, one could pad the message before encryption if this was a concern.

Furthermore, like [TripleSec](https://keybase.io/triplesec/), DoubleSec protects against a break in HMAC-SHA512 by also using BLAKE2b-512 for authentication. Although BLAKE2b is more similar to SHA2 than SHA3, it is faster than SHA3, with the same practical level of security. BLAKE2b also appears to have seen more adoption than SHA3, likely due to its performance in software.
