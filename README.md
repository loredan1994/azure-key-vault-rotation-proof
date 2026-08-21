# Azure Key Vault independent rotation proof

## Result

Rotating an Azure Key Vault key creates a new key version with new key
material. For RSA, this means a new public and private key pair.

If two independent vaults start with the same RSA key and only vault A rotates,
their current keys become different:

```text
Before rotation

Vault A version 1  ==  Vault B version 1
Cross-vault decrypt and unwrap work

After rotating vault A

Vault A version 2  !=  Vault B version 1
Cross-vault decrypt and unwrap fail for data protected by A version 2
```

The old version in vault A is not changed or removed. Rotation adds a new
version under the same logical key name.

## Why we tested this

The proposed disaster recovery design is:

1. Create an RSA key in vault A.
2. Back up the key through Azure Key Vault.
3. Restore the backup into vault B.
4. Use either vault for the same protected data.

A restored version in vault B contains the same cryptographic material as the
matching version in vault A. The vault URI is different, but the RSA key pair is
the same.

The scripts in this repository create the same starting condition by generating
one RSA key locally and importing it into both vaults. They then test what
happens when vault A rotates independently.

## Key name and key version

Azure uses the word "key" for both a logical key and its versions. They are not
the same thing.

```text
sql-cmk                         Logical key name
├── version 1                  RSA key pair 1
├── version 2                  RSA key pair 2
└── version 3                  RSA key pair 3
```

Each version is a different cryptographic key pair. A versioned key URI points
to one exact key pair. A versionless URI points to the current version.

## Two independent proofs

We ran two scripts against the same two test vaults on 20 August 2026. Each
script used a separate test key and completed successfully.

| Proof | Script | Azure operation | Algorithm |
| --- | --- | --- | --- |
| 1 | [`kv-fork-proof.sh`](./kv-fork-proof.sh) | Azure CLI encrypt and decrypt | `RSA-OAEP` |
| 2 | [`kv-wrap-unwrap-proof.sh`](./kv-wrap-unwrap-proof.sh) | Native REST wrapKey and unwrapKey | `RSA-OAEP-256` |

Proof 1 checks direct RSA encryption and decryption. Proof 2 wraps and unwraps a
random 256-bit data encryption key, called a DEK. The second operation matches
the way envelope encryption protects a DEK.

### Common test sequence

Both proofs used the same controls:

1. Generate an RSA-2048 key.
2. Import the same private key into vault A and vault B.
3. Confirm that both public-key fingerprints match.
4. Protect a test value with vault A version 1.
5. Recover it with vault B version 1.
6. Rotate vault A only.
7. Confirm that the new public-key fingerprint in vault A is different.
8. Confirm that vault A can recover data protected by its new version.
9. Confirm that vault B still works with the old control value.
10. Confirm that vault B cannot recover data protected by A's new version.
11. Import a second shared key into both vaults and protect the value again.
12. Confirm that the second shared key works for newly protected data but cannot
    recover the value protected by the missing A-only version.

### Results

| Check | Proof 1 | Proof 2 |
| --- | --- | --- |
| Initial fingerprints matched | Pass | Pass |
| Cross-vault operation worked before rotation | Pass | Pass |
| Rotation changed the RSA public key in vault A | Pass | Pass |
| Rotated vault A key recovered its own value | Pass | Pass |
| Vault B remained healthy on the old version | Pass | Pass |
| Vault B recovered data protected by rotated vault A | Failed as expected | Failed as expected |
| Second shared key worked after re-protection | Pass | Pass |
| Second shared key recovered the missing A-only value | Failed as expected | Failed as expected |

The positive controls matter. Vault B successfully processed the old value
immediately before and after rejecting the new value. This rules out a vault
outage or permission error. Vault B rejected the new value because it did not
have the rotated key material from vault A.

## Recorded key fingerprints

The scripts calculated a SHA-256 fingerprint from each RSA public modulus.
Matching fingerprints mean matching public keys. A changed fingerprint means
that rotation created a different key pair.

### Proof 1 fingerprints

| Key | SHA-256 |
| --- | --- |
| Initial key in both vaults | `8bbb8d32341c082592844c263619755503aa3619b0b9a88b0da4e5af3e5da5d3` |
| A-only rotated key | `d11341ad09cc0c3f1de2cac9c9e3a314e06d447bf76a025a4e8901f2d51c9617` |
| Second shared key | `c55216b5a1b70411dd5f2b404722ce7a1257e7602c9816109f92fa99f361f50a` |

### Proof 2 fingerprints

| Key | SHA-256 |
| --- | --- |
| Initial key in both vaults | `49140b9d44eea11149799999c01d39ec9b823b65bfb7f21101c335a0f5798099` |
| A-only rotated key | `49972950e3c4770f5fa3382291387c8e1532db430e5fc87a89d1deee339afa17` |
| Second shared key | `cafbc58bff29b75d688a9c4be9cf23249d3fe777fb73167717c9498bcc0cb350` |

The two proofs used different generated keys, so fingerprints from proof 1 are
not expected to match fingerprints from proof 2. The comparison happens within
each proof.

Before cleanup, vault A had three versions and vault B had two in both tests.
The extra version in vault A was the key created by its independent rotation.

## Evidence records

Each script created a detailed local report and a SHA-256 checksum. The reports
contain real Azure subscription, tenant, vault, and key-version identifiers, so
they are excluded from Git.

| Proof | Local report checksum |
| --- | --- |
| 1 | `e09602ea08ed3556ab6da1294f3b54e5424157b631bb3b2748c964fe2a99b48d` |
| 2 | `caa7ee96d2020b668e6e49fd2ccdb46f9e69daf55102e2aff17179fed4c25f2c` |

The reports do not contain private RSA keys, Azure tokens, plaintext DEKs,
ciphertext, or wrapped DEKs. Both tests soft-deleted their test keys after the
checks completed. Neither script purges keys.

## Conclusion for the DR design

Backup and restore can give vault A and vault B matching key material at the
starting point. The restored objects are independent after that point.

If vault A rotates by itself, it creates a new version that vault B does not
have. The two vaults can still use matching old versions, but their current
versions are no longer interchangeable.

A controlled rotation for this design must create one new shared key, place the
same material in both vaults, verify the fingerprints, move the service to that
key, and retain every old version required by live data or backups. Independent
auto-rotation must remain disabled on both copies.

Microsoft's documentation describes rotation as creating a new version with
new key material. It also states that a restored key becomes independent of the
source key:

- [Configure cryptographic key rotation](https://learn.microsoft.com/azure/key-vault/keys/how-to-configure-key-rotation)
- [Back up and restore Key Vault objects](https://learn.microsoft.com/azure/key-vault/general/backup)

## Run the proofs

Requirements:

- Bash
- Azure CLI
- OpenSSL
- `jq`, `awk`, `sed`, `tr`, and `mktemp`
- Key permissions for import, read, rotate, encrypt, decrypt, wrap, unwrap,
  list, and delete in both test vaults

Select the intended Azure subscription:

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

Use isolated test vaults. Each script creates a unique key name and asks whether
to soft-delete it when the test finishes.
