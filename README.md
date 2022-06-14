# AEADSafe

High-level, misuse-resistant secret key-based cipher library using platform-native AEAD algorithms

## What is AEADSafe?

The term AEAD stands for Authenticated Encryption with Associated Data. An AEAD construction's goal is to simultaneously assure the confidentiality and the authenticity of data. Semantically, an AEAD structure has two components: a secret encrypted component (ciphertext), and a public unencrypted component (associated data). The whole structure is authenticated: any unauthorized change of either the ciphertext or the associated data is detected during decryption.

AEADSafe is a high-level AEAD structure, providing two operations:

1. `lockSafe`
   - input:
     - `secretData` — the data that is locked into the safe, so it cannot be accessed without the key or modified without detection _(encrypted and authenticated)_
     - `additionalPublicData` — the data that is engraved onto the outside of the safe, so it can be publicly accessed, but cannot be modified without detection _(authenticated)_
     - `lockedSafeEncoding` — the encoding of the `lockedSafe` output (`binary` or `base64`)
     - `keyEncoding` — the encoding of the `key` output (`binary` or `base64`)
   - output:
     - `lockedSafe` — the locked safe, with all AEAD parameters encoded in a self-contained way
     - `key` — the encryption key (always generated internally), **must be kept secret**
2. `unlockSafe`
   - input:
     - `lockedSafe` — the locked safe, with all AEAD parameters encoded in a self-contained way
     - `key` — the encryption key
   - output:
     - `secretData` — same as the input of `lockSafe`
     - `additionalPublicData` — same as the input of `lockSafe`

Due to misuse resistance, it is not possible to provide an external key.

## Use cases

Instead of this library, you should use [libsodium](https://github.com/jedisct1/libsodium), which is the best cryptography library out there.

But if all of the following apply to you, you can also use this library:

- For some reason, you don't want to use [libsodium](https://github.com/jedisct1/libsodium), which is the best cryptography library out there.
- You need to encrypt and/or authenticate pieces of information with a symmetric key (then you also need decrypt them sometime in the future).
- You don't need to or you don't want to deal with low-level cryptographic features, such as key generation, algorithm and parameter selection, etc.
- You need a self-contained, standalone AEAD structure. All necessary information for decryption/authentication is encoded in the output, except the key.

## Supported platforms

| Platform | Support            |
| -------- | ------------------ |
| Node.js  | :heavy_check_mark: |

Further platform support is expected soon.

## Versions and algorithms

Independent of library versions, AEADSafe defines _algorithm versions_. This intends to be a transparently upgradable abstraction from the actual, underlying AEAD constructions. The `lockSafe` operation always encrypts with the most recent version, encoding the used algorithm version into the output. The backwards compatible `unlockSafe` operation first decodes the used algorithm version, then decrypts and authenticates with the corresponding algorithm.

### Version 1 - ChaCha20-Poly1305

The first and most recent AEADSafe algorithm. Secure, fast, and constant-time, even without hardware support ([unlike AES-GCM, which is either just slower or it even leaks your encryption keys in cache timing](https://soatok.blog/2020/07/12/comparison-of-symmetric-encryption-methods)). If `secretData` is bigger than `2^38 - 64` bytes (approximately 256 GiB, [the maximum safe message length for ChaCha20-Poly1305](https://soatok.blog/2020/12/24/cryptographic-wear-out-for-symmetric-encryption)), an exception is thrown. As each `lockSafe` operation generates a fresh key-nonce pair, there are no other restrictions.

## License

MIT
