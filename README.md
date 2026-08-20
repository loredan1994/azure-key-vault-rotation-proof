# Azure Key Vault rotation test

This project tests a simple disaster recovery idea.

1. Create one RSA key outside Azure Key Vault.
2. Import the same key into two separate vaults.
3. Use vault A to wrap a small test key.
4. Use vault B to unwrap it.
5. Rotate the RSA key in vault A only.
6. Try the same cross-vault operation again.

The first cross-vault test worked. The test after rotation failed.

## Why this matters

Many services do not encrypt all data directly with the RSA key in Key Vault.
They encrypt the data with a smaller data encryption key, called a DEK. The RSA
key wraps and unwraps that DEK.

At the start of this test, both vaults held the same RSA private key. They had
different Azure key IDs, but the key material was the same. This meant vault B
could unwrap a DEK wrapped by vault A.

Rotating the key in vault A made a new private key inside vault A. Azure did not
copy that new private key to vault B. Vault B still worked with the old key, but
it could not unwrap anything protected by the new key in vault A.

In short:

```text
Before rotation
Vault A key v1 == Vault B key v1
Cross-vault unwrap works

After rotating vault A only
Vault A key v2 != Vault B key v1
Cross-vault unwrap fails
```

## What we tested

The main script is [`kv-wrap-unwrap-proof.sh`](./kv-wrap-unwrap-proof.sh). It
uses the native Azure Key Vault `wrapkey` and `unwrapkey` REST operations. The
test used `RSA-OAEP-256` and Key Vault REST API version `7.6`.

The script generated two RSA-2048 keypairs outside Key Vault. It also generated
a random 256-bit DEK for the wrap and unwrap checks. The private keys and DEK
were removed when the script finished.

The test ran on 20 August 2026. The script completed all checks. Two unwrap
attempts failed as expected because the vaults held different keys.

| Check | Result |
| --- | --- |
| Import the same first RSA key into both vaults | Pass |
| Wrap with vault A version 1 and unwrap with vault B version 1 | Pass |
| Rotate vault A only | Pass |
| Use the rotated vault A key to unwrap its own value | Pass |
| Confirm vault B can still unwrap the old test value | Pass |
| Ask vault B to unwrap the value from rotated vault A | Failed as expected |
| Import a new shared key into both vaults and rewrap the DEK | Pass |
| Ask the new shared key in vault B to unwrap the earlier forked value | Failed as expected |

Azure returned `BadParameter` when vault B tried to unwrap the value protected
by the private rotation in vault A. The checks before and after this failure
proved that vault B was working. It simply had the wrong key material.

## Public key evidence

The script hashed each RSA public modulus with SHA-256. Matching hashes mean the
vaults have the same RSA public key. Different hashes mean the keys differ.

| Key generation | SHA-256 |
| --- | --- |
| First key imported into both vaults | `49140b9d44eea11149799999c01d39ec9b823b65bfb7f21101c335a0f5798099` |
| Key created by rotation in vault A only | `49972950e3c4770f5fa3382291387c8e1532db430e5fc87a89d1deee339afa17` |
| Second shared key imported into both vaults | `cafbc58bff29b75d688a9c4be9cf23249d3fe777fb73167717c9498bcc0cb350` |

Before cleanup, vault A had three versions and vault B had two. The extra
version in vault A was the key created by its private rotation.

The full local report was named
`kv-wrap-unwrap-evidence-20260820T163713Z-25588.md`. Its SHA-256 was:

```text
caa7ee96d2020b668e6e49fd2ccdb46f9e69daf55102e2aff17179fed4c25f2c
```

The full report is not stored in Git because it contains real Azure account,
vault, and key-version IDs. The report contains no private keys, tokens, DEK,
or wrapped value.

## What this proves

This test proves that two separate vaults can use the same imported RSA key.
It also proves that rotating one copy does not rotate the other copy. Once one
vault rotates by itself, the two vaults no longer provide the same key.

Importing another shared key later does not recover the missing rotated key.
The application or Azure service must rewrap its DEK with the new shared key.

If both vaults must act as interchangeable copies, do not let them rotate their
keys independently. A controlled process can create the next key outside both
vaults, import it into both, update the service, and keep every old key version
needed for backups.

## What this does not prove

This was a key-level test. It did not test Azure SQL TDE, SQL geo-replication,
certificates, secrets, scheduled rotation, or a real regional outage. Those
need separate tests.

It also does not show that Azure Key Vault's own regional replication is
broken. It shows that two independent vaults do not copy a new private key when
only one vault rotates.

## Run the test

You need Bash, Azure CLI, OpenSSL, `jq`, `awk`, `sed`, `tr`, and `mktemp`. Your
Azure identity needs permission to import, read, rotate, wrap, unwrap, list,
and delete keys in both test vaults.

```bash
az login
az account set --subscription '<subscription-id-or-name>'
az account show --output table
./kv-wrap-unwrap-proof.sh <vault-a> <vault-b>
```

Use test vaults. The script creates a unique key name and asks whether to
soft-delete it at the end. It never purges keys.

The older [`kv-fork-proof.sh`](./kv-fork-proof.sh) runs a similar check with the
Azure CLI `encrypt` and `decrypt` commands. The native wrap and unwrap test is
the better match for DEK handling.
