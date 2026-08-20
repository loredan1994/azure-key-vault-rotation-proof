# Azure Key Vault rotation-fork proofs

Version: **1.0.0**

This repository contains controlled demonstrations of what happens when the
same externally generated RSA material is imported into two independent Azure
Key Vaults and only one vault rotates.

The bounded claim is:

> Independent rotation creates new key material in one vault. The other vault
> cannot decrypt or unwrap values protected by that new version, even though it
> remains healthy and can continue using the previously shared version.

This does not claim that Azure Key Vault's internal service-managed replication
is broken, nor does it by itself prove the behavior of a particular Azure
service such as Azure SQL TDE.

## Scripts

### `kv-wrap-unwrap-proof.sh`

The primary proof. It calls the native Key Vault REST `wrapkey` and `unwrapkey`
endpoints with `RSA-OAEP-256`. Authentication is handled internally by
`az rest --resource https://vault.azure.net`; the script never exports or
stores an OAuth bearer token.

It proves:

1. Identical imported material supports cross-vault wrap/unwrap.
2. Rotating only vault A changes its RSA public modulus.
3. A's rotated version can unwrap its own value.
4. Vault B remains healthy but rejects the value wrapped by A's rotated version.
5. A coordinated later import works only after explicit rewrapping.
6. The later import does not repair the missing historical generation.

### `kv-fork-proof.sh`

The original proof using Azure CLI `encrypt` and `decrypt`. Those CLI commands
are currently marked preview, so the native wrap/unwrap script provides the
stronger evidence for envelope-encryption behavior.

## Requirements

- Bash
- Azure CLI with an authenticated account
- OpenSSL
- `jq`, `awk`, `sed`, `tr`, and `mktemp`
- Key Vault Crypto Officer on both test vaults, or equivalent key permissions

Select the intended Azure subscription before running:

```bash
az login
az account set --subscription '<subscription-id-or-name>'
az account show --output table
```

Run the native proof:

```bash
./kv-wrap-unwrap-proof.sh <vault-a> <vault-b>
```

Both scripts use unique test-only key names and ask whether to soft-delete them
at the end. They never purge vault objects.

## Evidence and credential handling

Each run produces a timestamped Markdown evidence report and SHA-256 sidecar.
Live reports are intentionally excluded from Git because they contain real
subscription, tenant, key-version, and vault identifiers.

The scripts do not retain:

- RSA private PEM files;
- OAuth access tokens;
- synthetic DEK plaintext;
- ciphertext or wrapped DEK values;
- unexpired application credentials.

Temporary PEM files are created under a mode-0700 temporary directory and
removed on every exit path. A report checksum is not a formal signature. For
publication-grade attestation, sign the checksum with an independently managed
organizational signing key and retain it in an immutable evidence repository.

## Interpreting the result

The proof establishes a cryptographic property of two independent vaults. A
complete workload assessment should additionally test:

- scheduled rotation rather than only on-demand rotation;
- Azure Key Vault audit logs;
- the actual service consumer, such as database-level CMK with SQL
  geo-replication;
- recovery of historical backups that reference old protector generations.

## Safety

Use disposable vaults or clearly isolated test vaults. Never point these scripts
at production key names or production cryptographic material.
