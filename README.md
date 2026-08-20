# Azure Key Vault independent rotation proof

## Summary

This repository contains two tests of the same disaster recovery design.

The design starts with one RSA private key created outside Azure Key Vault. The
same key is imported into two separate vaults. As long as both vaults hold the
same key material, either vault can process data protected by the other vault.

The tests then rotate the key in vault A only. Rotation creates a new RSA
private key in vault A. Vault B does not receive that key. From that point, vault
B cannot process new data protected by the rotated key in vault A.

Both tests reached the same result through different Azure Key Vault operations.

## Design under test

```text
Initial state

Vault A, version 1  ==  Vault B, version 1
         Same imported RSA key
         Cross-vault operations work

After vault A rotates

Vault A, version 2  !=  Vault B, version 1
         Different RSA keys
         Cross-vault operations fail for new data
```

Each script also imports a second shared RSA key into both vaults. This restores
cross-vault use for data protected with the second shared key. It does not add
the missing A-only rotated key to vault B.

The scripts generate RSA-2048 test keys locally for repeatable testing. A real
offline key ceremony can supply the imported keys without changing the Key
Vault behavior tested here.

## Proof 1: encrypt and decrypt

Script: [`kv-fork-proof.sh`](./kv-fork-proof.sh)

This proof uses the Azure CLI `key encrypt` and `key decrypt` commands with
`RSA-OAEP`. It encrypts a small DEK-like test value in one vault and tries to
decrypt it in the other vault.

The Azure CLI marked these two commands as preview when the test ran. Proof 2
was added to repeat the result through the native Key Vault REST operations.

The test ran on 20 August 2026.

### Procedure

1. Generate two different RSA-2048 private keys locally.
2. Import the first RSA key into vault A and vault B.
3. Encrypt the test value with vault A version 1.
4. Decrypt it with vault B version 1.
5. Rotate the key in vault A only.
6. Encrypt the test value again with the rotated key in vault A.
7. Confirm the rotated key in vault A can decrypt its own value.
8. Confirm vault B can still decrypt the old value.
9. Ask vault B to decrypt the new value from vault A.
10. Import the second shared RSA key into both vaults and protect the value again.
11. Confirm that this second shared key cannot decrypt the earlier A-only value.

### Recorded results

| Check | Result |
| --- | --- |
| First imported key matched in both vaults | Pass |
| Vault B decrypted the value from vault A before rotation | Pass |
| Rotation in vault A created different key material | Pass |
| Rotated vault A key decrypted its own value | Pass |
| Vault B still decrypted the old control value | Pass |
| Vault B decrypted the value from rotated vault A | Failed as expected |
| Old vault A version still decrypted the old value | Pass |
| Second shared key worked after the value was protected again | Pass |
| Second shared key in vault B decrypted the A-only rotated value | Failed as expected |

The public-key hashes recorded by the script were:

| Key | SHA-256 of RSA public modulus |
| --- | --- |
| First key imported into both vaults | `8bbb8d32341c082592844c263619755503aa3619b0b9a88b0da4e5af3e5da5d3` |
| Key created by rotation in vault A only | `d11341ad09cc0c3f1de2cac9c9e3a314e06d447bf76a025a4e8901f2d51c9617` |
| Second shared key imported into both vaults | `c55216b5a1b70411dd5f2b404722ce7a1257e7602c9816109f92fa99f361f50a` |

The matching first hash proves that both vaults started with the same RSA public
key. The changed hash after rotation proves that vault A created a different
key. Before cleanup, vault A had three versions and vault B had two. The extra
version was the private rotation in vault A.

The local evidence report is
`kv-fork-proof-evidence-20260820T162418Z-22820.md`.

```text
Report SHA-256
e09602ea08ed3556ab6da1294f3b54e5424157b631bb3b2748c964fe2a99b48d
```

## Proof 2: native wrapKey and unwrapKey

Script: [`kv-wrap-unwrap-proof.sh`](./kv-wrap-unwrap-proof.sh)

This proof uses the native Azure Key Vault REST `wrapkey` and `unwrapkey`
operations. It uses `RSA-OAEP-256` and Key Vault REST API version `7.6`.

This is the closer test for envelope encryption. A service encrypts its data
with a data encryption key, called a DEK. The RSA key in Key Vault wraps and
unwraps that DEK.

The test ran on 20 August 2026.

### Procedure

1. Generate two different RSA-2048 private keys locally.
2. Generate a random 256-bit DEK.
3. Import the first RSA key into vault A and vault B.
4. Wrap the DEK with vault A version 1.
5. Unwrap it with vault B version 1.
6. Rotate the key in vault A only.
7. Wrap the DEK with the rotated key in vault A.
8. Confirm the rotated key in vault A can unwrap its own value.
9. Confirm vault B can still unwrap the old control value.
10. Ask vault B to unwrap the new value from vault A.
11. Import the second shared RSA key into both vaults and wrap the DEK again.
12. Confirm that this second shared key cannot unwrap the earlier A-only value.

### Recorded results

| Check | Result |
| --- | --- |
| First imported key matched in both vaults | Pass |
| Vault B unwrapped the DEK from vault A before rotation | Pass |
| Rotation in vault A created different key material | Pass |
| Rotated vault A key unwrapped its own value | Pass |
| Vault B still unwrapped the old control value | Pass |
| Vault B unwrapped the value from rotated vault A | Failed as expected |
| Second shared key worked after the DEK was wrapped again | Pass |
| Second shared key in vault B unwrapped the A-only rotated value | Failed as expected |

Azure returned `BadParameter` for the expected cross-vault failure. Control
checks ran before and after it. Those checks showed that vault B was available
and its original key still worked. The failure came from the key mismatch.

The public-key hashes recorded by the script were:

| Key | SHA-256 of RSA public modulus |
| --- | --- |
| First key imported into both vaults | `49140b9d44eea11149799999c01d39ec9b823b65bfb7f21101c335a0f5798099` |
| Key created by rotation in vault A only | `49972950e3c4770f5fa3382291387c8e1532db430e5fc87a89d1deee339afa17` |
| Second shared key imported into both vaults | `cafbc58bff29b75d688a9c4be9cf23249d3fe777fb73167717c9498bcc0cb350` |

Before cleanup, vault A had three versions and vault B had two. Again, the
extra version was the private rotation in vault A.

The local evidence report is
`kv-wrap-unwrap-evidence-20260820T163713Z-25588.md`.

```text
Report SHA-256
caa7ee96d2020b668e6e49fd2ccdb46f9e69daf55102e2aff17179fed4c25f2c
```

## Combined result

The scripts used separate test keys, so their public-key hashes are not meant
to match each other. The important comparison happens inside each proof.

| Observation | Proof 1 | Proof 2 |
| --- | --- | --- |
| Both vaults started with the same imported RSA key | Confirmed | Confirmed |
| Cross-vault operation worked before rotation | Confirmed | Confirmed |
| Rotating vault A changed its RSA key | Confirmed | Confirmed |
| Vault B remained healthy on the old key | Confirmed | Confirmed |
| Vault B rejected data protected by rotated vault A | Confirmed | Confirmed |
| A later shared import worked after re-protection | Confirmed | Confirmed |
| A later shared import recovered the missing A-only key | No | No |

The two independent proofs show the same key fork. Importing identical material
creates compatible keys in separate vaults. Rotating one vault creates new key
material in that vault only.

## Technical conclusion

A disaster recovery design based on identical imported keys cannot use
independent in-vault rotation and still treat both vaults as interchangeable.
Once either vault rotates alone, it can protect data with a private key that the
other vault has never held.

Disabling independent auto-rotation prevents an unplanned key fork, but it is
only one part of the process. A controlled rotation should:

1. Generate the next RSA key outside both vaults.
2. Import the same key into every target vault.
3. Confirm the public-key hashes match.
4. Move each service to the new shared key version.
5. Rewrap or protect the DEK with that version.
6. Keep every old key version needed by live data and backups.

The exact key-version ID used for encryption or wrapping should be recorded.
Using only a key name can hide which version protected the data.

## Evidence and cleanup

Both scripts create timestamped Markdown reports and SHA-256 checksum files.
The full reports stay out of Git because they contain real Azure account, vault,
and key-version IDs.

The reports do not contain private RSA keys, Azure access tokens, plaintext
DEKs, ciphertext, or wrapped DEKs. Temporary private keys are deleted on every
exit path. Both test runs soft-deleted their test keys from both vaults. Neither
script purges keys.

## Run both proofs

You need Bash, Azure CLI, OpenSSL, `jq`, `awk`, `sed`, `tr`, and `mktemp`. Your
Azure identity needs permission to import, read, rotate, encrypt, decrypt, wrap,
unwrap, list, and delete keys in both test vaults.

Select the intended subscription first:

```bash
az login
az account set --subscription '<subscription-id-or-name>'
az account show --output table
```

Run proof 1:

```bash
./kv-fork-proof.sh <vault-a> <vault-b>
```

Run proof 2:

```bash
./kv-wrap-unwrap-proof.sh <vault-a> <vault-b>
```

Use test vaults. Each script creates a unique key name and asks whether to
soft-delete it when the test finishes.
