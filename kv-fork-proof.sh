#!/usr/bin/env bash
#
# Prove that two independent Azure Key Vault keys initially containing the
# same imported RSA material diverge when one vault rotates independently.
#
# Usage:
#   ./kv-fork-proof.sh <vault-a> <vault-b>
#
# Before running:
#   az login
#   az account set --subscription <subscription-id-or-name>
#
# The signed-in identity needs Key Vault Crypto Officer on both vaults, or
# equivalent data-plane rights for list, import, get, encrypt, decrypt, rotate,
# list-versions, and delete if the optional cleanup is selected.
#
# The script:
#   - generates two temporary RSA private keys locally with OpenSSL;
#   - imports generation 1 into both vaults;
#   - rotates only vault A and proves the resulting cryptographic fork;
#   - imports generation 2 into both vaults and proves that compatibility is
#     restored only after data is explicitly reprotected;
#   - writes a Markdown evidence report and a SHA-256 checksum next to it;
#   - securely limits local file permissions and removes temporary PEM files;
#   - optionally soft-deletes the cloud test keys, but never purges them.
#
# This is a software-key proof using synthetic data. It is not an offline/HSM
# genesis ceremony, a formal third-party attestation, or an end-to-end TDE test.

set -Eeuo pipefail
umask 077

VAULT_A="${1:?usage: $0 <vault-a> <vault-b>}"
VAULT_B="${2:?usage: $0 <vault-a> <vault-b>}"
[ "$#" -eq 2 ] || {
  printf 'usage: %s <vault-a> <vault-b>\n' "$0" >&2
  exit 2
}

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-${RANDOM}"
KEY_NAME="dr-fork-proof-${RUN_ID}"
REPORT_PATH="$PWD/kv-fork-proof-evidence-${RUN_ID}.md"
CHECKSUM_PATH="${REPORT_PATH}.sha256"

TEMP_DIR=""
GENESIS_V1=""
GENESIS_V2=""
ERROR_LOG=""
CURRENT_STEP="initialization"
REPORT_READY=false
FINALIZED=false
CLOUD_CREATED_A=false
CLOUD_CREATED_B=false

utc_now() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

append_report() {
  printf '%s\n' "$*" >>"$REPORT_PATH"
}

step() {
  CURRENT_STEP="$1. $2"
  printf '\n=== %s ===\n' "$CURRENT_STEP"
  append_report "## $CURRENT_STEP"
  append_report ""
  append_report "$3"
  append_report ""
  append_report "- Started (UTC): $(utc_now)"
}

pass_step() {
  append_report "- Result: **PASS**"
  append_report "- Completed (UTC): $(utc_now)"
  while [ "$#" -gt 0 ]; do
    append_report "- $1"
    shift
  done
  append_report ""
  printf 'PASS: %s\n' "$CURRENT_STEP"
  CURRENT_STEP="between steps"
}

die() {
  local message="$*"
  printf 'ERROR: %s\n' "$message" >&2
  if [ "$REPORT_READY" = true ]; then
    append_report "- Result: **FAIL**"
    append_report "- Failed (UTC): $(utc_now)"
    append_report "- Failure: $message"
    append_report ""
  fi
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

assert_equal() {
  [ "$1" = "$2" ] || die "$3"
}

assert_different() {
  [ "$1" != "$2" ] || die "$3"
}

hash_stdin() {
  openssl dgst -sha256 | awk '{print $NF}'
}

hash_file() {
  openssl dgst -sha256 "$1" | awk '{print $NF}'
}

key_fingerprint() {
  # For this RSA-only proof, hash the base64url-encoded public modulus.
  local modulus
  modulus=$(az keyvault key show --id "$1" --query key.n -o tsv)
  [ -n "$modulus" ] || die "could not obtain RSA modulus for $1"
  printf '%s' "$modulus" | hash_stdin
}

pem_fingerprint() {
  openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | hash_stdin
}

encrypt_with() {
  local kid="$1"
  local value="$2"
  az keyvault key encrypt \
    --id "$kid" \
    --algorithm RSA-OAEP \
    --value "$value" \
    --data-type base64 \
    --query result \
    -o tsv
}

decrypt_with() {
  local kid="$1"
  local ciphertext="$2"
  az keyvault key decrypt \
    --id "$kid" \
    --algorithm RSA-OAEP \
    --value "$ciphertext" \
    --data-type base64 \
    --query result \
    -o tsv | tr -d '\r\n' | base64 -d
}

key_count() {
  local vault="$1"
  az keyvault key list \
    --vault-name "$vault" \
    --query "[?name=='${KEY_NAME}'] | length(@)" \
    -o tsv
}

cleanup_local() {
  if [ -n "$TEMP_DIR" ]; then
    rm -f -- "$GENESIS_V1" "$GENESIS_V2" "$ERROR_LOG"
    rmdir "$TEMP_DIR" 2>/dev/null || true
  fi
}

write_checksum() {
  local digest
  if [ -f "$REPORT_PATH" ] && command -v openssl >/dev/null 2>&1; then
    digest=$(hash_file "$REPORT_PATH")
    printf '%s  %s\n' "$digest" "$(basename "$REPORT_PATH")" >"$CHECKSUM_PATH"
  fi
}

on_exit() {
  local status=$?
  set +e

  if [ "$REPORT_READY" = true ] && [ "$FINALIZED" = false ]; then
    append_report "## Final outcome"
    append_report ""
    append_report "**INCOMPLETE/FAILED** at \`$CURRENT_STEP\` on $(utc_now)."
    append_report ""
  fi

  if [ "$status" -ne 0 ] &&
     { [ "$CLOUD_CREATED_A" = true ] || [ "$CLOUD_CREATED_B" = true ]; }; then
    printf '\nWARNING: the proof stopped after creating cloud key material.\n' >&2
    printf "Review and, if appropriate, soft-delete key '%s' from:\n" "$KEY_NAME" >&2
    [ "$CLOUD_CREATED_A" = true ] && printf '  %s\n' "$VAULT_A" >&2
    [ "$CLOUD_CREATED_B" = true ] && printf '  %s\n' "$VAULT_B" >&2
  fi

  cleanup_local
  write_checksum

  if [ "$REPORT_READY" = true ]; then
    printf '\nEvidence report: %s\n' "$REPORT_PATH"
    [ -f "$CHECKSUM_PATH" ] && printf 'Report checksum: %s\n' "$CHECKSUM_PATH"
  fi

  trap - EXIT
  exit "$status"
}
trap on_exit EXIT

# Create the report before cloud operations so failures are also documented.
: >"$REPORT_PATH"
REPORT_READY=true
append_report "# Azure Key Vault independent-rotation evidence report"
append_report ""
append_report "- Run ID: \`$RUN_ID\`"
append_report "- Generated (UTC): $(utc_now)"
append_report "- Vault A: \`$VAULT_A\`"
append_report "- Vault B: \`$VAULT_B\`"
append_report "- Test key name: \`$KEY_NAME\`"
append_report ""
append_report "## Scope and evidentiary limits"
append_report ""
append_report "This report records observations made automatically by the accompanying script."
append_report "It is self-generated evidence, not an independently witnessed or cryptographically"
append_report "signed attestation. The SHA-256 sidecar detects changes only when its expected digest"
append_report "is retained through a separately trusted channel."
append_report ""
append_report "The experiment uses OpenSSL-generated software RSA keys and synthetic plaintext."
append_report "It demonstrates key-material compatibility and divergence, not an offline/HSM"
append_report "ceremony and not an end-to-end Azure SQL TDE operation."
append_report ""

require_command az
require_command openssl
require_command base64
require_command awk
require_command tr
require_command sed
require_command mktemp

[ "$VAULT_A" != "$VAULT_B" ] || die "vault A and vault B must be different"
for vault in "$VAULT_A" "$VAULT_B"; do
  case "$vault" in
    ''|*[!A-Za-z0-9-]*) die "invalid Azure Key Vault name: $vault" ;;
  esac
done

TEMP_DIR=$(mktemp -d)
GENESIS_V1="$TEMP_DIR/genesis-v1.pem"
GENESIS_V2="$TEMP_DIR/genesis-v2.pem"
ERROR_LOG="$TEMP_DIR/expected-decrypt-error.log"

step "0" "Preflight" \
  "Confirm the selected Azure account, CLI capabilities, vault separation, and collision-free test name."

if ! SUBSCRIPTION_ID=$(az account show --query id -o tsv); then
  die "Azure CLI is not authenticated; run az login first"
fi
[ -n "$SUBSCRIPTION_ID" ] || die "Azure CLI returned no active subscription"
TENANT_ID=$(az account show --query tenantId -o tsv)
AZ_VERSION=$(az version --query '"azure-cli"' -o tsv 2>/dev/null || printf 'unknown')
OPENSSL_VERSION=$(openssl version)
az keyvault key rotate --help >/dev/null

COUNT_A=$(key_count "$VAULT_A")
COUNT_B=$(key_count "$VAULT_B")
assert_equal "$COUNT_A" "0" "generated test key unexpectedly exists in vault $VAULT_A"
assert_equal "$COUNT_B" "0" "generated test key unexpectedly exists in vault $VAULT_B"

pass_step \
  "Active subscription ID: \`$SUBSCRIPTION_ID\`" \
  "Tenant ID: \`$TENANT_ID\`" \
  "Azure CLI version: \`$AZ_VERSION\`" \
  "OpenSSL: \`$OPENSSL_VERSION\`" \
  "The generated test key name was absent from both vaults."

step "1" "Generate two local RSA generations" \
  "Generate distinct RSA private keys for the shared initial generation and the later coordinated replacement."

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$GENESIS_V1" 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$GENESIS_V2" 2>/dev/null

openssl rsa -in "$GENESIS_V1" -check -noout >/dev/null 2>&1 ||
  die "generated genesis v1 is not a valid RSA private key"
openssl rsa -in "$GENESIS_V2" -check -noout >/dev/null 2>&1 ||
  die "generated genesis v2 is not a valid RSA private key"

PEM_FP_V1=$(pem_fingerprint "$GENESIS_V1")
PEM_FP_V2=$(pem_fingerprint "$GENESIS_V2")
assert_different "$PEM_FP_V1" "$PEM_FP_V2" \
  "the two generated RSA keys unexpectedly have the same public fingerprint"

pass_step \
  "Generation 1 SPKI SHA-256: \`$PEM_FP_V1\`" \
  "Generation 2 SPKI SHA-256: \`$PEM_FP_V2\`" \
  "Private PEM files exist only in a mode-0700 temporary directory and are removed on exit." \
  "These keys were generated on the Azure CLI host, not on an offline system or HSM."

step "2" "Import identical generation 1 into both vaults" \
  "Import the same RSA private key into each independent vault and compare its public modulus."

KID_A_V1=$(az keyvault key import \
  --vault-name "$VAULT_A" \
  --name "$KEY_NAME" \
  --pem-file "$GENESIS_V1" \
  --protection software \
  --ops encrypt decrypt wrapKey unwrapKey \
  --query key.kid \
  -o tsv)
CLOUD_CREATED_A=true

KID_B_V1=$(az keyvault key import \
  --vault-name "$VAULT_B" \
  --name "$KEY_NAME" \
  --pem-file "$GENESIS_V1" \
  --protection software \
  --ops encrypt decrypt wrapKey unwrapKey \
  --query key.kid \
  -o tsv)
CLOUD_CREATED_B=true

[ -n "$KID_A_V1" ] || die "vault A import returned no versioned key ID"
[ -n "$KID_B_V1" ] || die "vault B import returned no versioned key ID"

FP_A_V1=$(key_fingerprint "$KID_A_V1")
FP_B_V1=$(key_fingerprint "$KID_B_V1")
assert_equal "$FP_A_V1" "$FP_B_V1" \
  "initial imports do not have matching RSA public material"

pass_step \
  "Vault A v1 key ID: \`$KID_A_V1\`" \
  "Vault B v1 key ID: \`$KID_B_V1\`" \
  "A modulus SHA-256: \`$FP_A_V1\`" \
  "B modulus SHA-256: \`$FP_B_V1\`" \
  "The matching modulus fingerprints show identical RSA public material."

step "3" "Prove cross-vault compatibility before rotation" \
  "Encrypt synthetic DEK-like plaintext with A v1 and decrypt it using the exact B v1 key ID."

PLAINTEXT="DEK-simulation-$(openssl rand -hex 32)"
B64=$(printf '%s' "$PLAINTEXT" | base64 | tr -d '\r\n')
CT_V1=$(encrypt_with "$KID_A_V1" "$B64")
OUT_V1=$(decrypt_with "$KID_B_V1" "$CT_V1")
assert_equal "$OUT_V1" "$PLAINTEXT" \
  "vault B v1 could not decrypt ciphertext created with vault A v1"

pass_step \
  "A v1 encryption succeeded." \
  "B v1 recovered the exact synthetic plaintext." \
  "No plaintext or ciphertext value is written to this report."

step "4" "Rotate vault A only" \
  "Invoke Key Vault rotation only in A, pin the returned version ID, and confirm B did not change."

KID_A_ROTATED=$(az keyvault key rotate \
  --vault-name "$VAULT_A" \
  --name "$KEY_NAME" \
  --query key.kid \
  -o tsv)
[ -n "$KID_A_ROTATED" ] || die "rotation returned no versioned key ID"
assert_different "$KID_A_V1" "$KID_A_ROTATED" \
  "rotation did not create a new versioned key ID"

KID_B_CURRENT=$(az keyvault key show \
  --vault-name "$VAULT_B" \
  --name "$KEY_NAME" \
  --query key.kid \
  -o tsv)
assert_equal "$KID_B_CURRENT" "$KID_B_V1" \
  "vault B changed concurrently; the experiment is no longer isolated"

FP_A_ROTATED=$(key_fingerprint "$KID_A_ROTATED")
assert_different "$FP_A_ROTATED" "$FP_B_V1" \
  "rotation unexpectedly produced material matching vault B v1"

pass_step \
  "A rotated key ID: \`$KID_A_ROTATED\`" \
  "A rotated modulus SHA-256: \`$FP_A_ROTATED\`" \
  "B remained on: \`$KID_B_V1\`" \
  "The public material now differs between A's current version and B's current version."

step "5" "Prove the post-rotation cryptographic fork" \
  "Use positive controls to show that A's new ciphertext is valid and B is healthy before attributing B's rejection to different key material."

CT_ROTATED=$(encrypt_with "$KID_A_ROTATED" "$B64")
OUT_A_ROTATED=$(decrypt_with "$KID_A_ROTATED" "$CT_ROTATED")
assert_equal "$OUT_A_ROTATED" "$PLAINTEXT" \
  "positive control failed: A's rotated key could not decrypt its ciphertext"

OUT_B_PRE_CONTROL=$(decrypt_with "$KID_B_V1" "$CT_V1")
assert_equal "$OUT_B_PRE_CONTROL" "$PLAINTEXT" \
  "B health control failed before the expected mismatch"

if decrypt_with "$KID_B_V1" "$CT_ROTATED" >/dev/null 2>"$ERROR_LOG"; then
  die "unexpected success: B v1 decrypted ciphertext created under A's rotated key"
fi

OUT_B_POST_CONTROL=$(decrypt_with "$KID_B_V1" "$CT_V1")
assert_equal "$OUT_B_POST_CONTROL" "$PLAINTEXT" \
  "B health control failed after the expected mismatch"

EXPECTED_ERROR_DIGEST=$(hash_file "$ERROR_LOG")
EXPECTED_ERROR_FIRST_LINE=$(sed '/^WARNING:/d; /^[[:space:]]*$/d' "$ERROR_LOG" |
  sed -n '1p' | tr -d '\r')
[ -n "$EXPECTED_ERROR_FIRST_LINE" ] || EXPECTED_ERROR_FIRST_LINE="Azure CLI returned a nonzero status without stderr text."

pass_step \
  "A's rotated key successfully decrypted its own ciphertext." \
  "B v1 successfully decrypted the known-good v1 ciphertext immediately before and after the mismatch test." \
  "B v1 returned a nonzero status for A's rotated ciphertext, demonstrating incompatibility." \
  "Expected-error log SHA-256: \`$EXPECTED_ERROR_DIGEST\`" \
  "Azure CLI error excerpt: $EXPECTED_ERROR_FIRST_LINE"

step "6" "Prove the old version remains necessary" \
  "Use the exact A v1 key ID to decrypt the pre-rotation ciphertext, demonstrating why historical protectors must be retained."

OUT_A_OLD=$(decrypt_with "$KID_A_V1" "$CT_V1")
assert_equal "$OUT_A_OLD" "$PLAINTEXT" \
  "A v1 could not decrypt its pre-rotation ciphertext"

pass_step \
  "A v1 still decrypted the v1 ciphertext." \
  "The result illustrates why retained backups can continue to depend on old protector generations."

step "7" "Import a coordinated generation 2 and re-protect" \
  "Import the same new external material into B and then A, re-protect the synthetic value, and show both the forward recovery and its historical limitation."

KID_B_SYNC=$(az keyvault key import \
  --vault-name "$VAULT_B" \
  --name "$KEY_NAME" \
  --pem-file "$GENESIS_V2" \
  --protection software \
  --ops encrypt decrypt wrapKey unwrapKey \
  --query key.kid \
  -o tsv)

KID_A_SYNC=$(az keyvault key import \
  --vault-name "$VAULT_A" \
  --name "$KEY_NAME" \
  --pem-file "$GENESIS_V2" \
  --protection software \
  --ops encrypt decrypt wrapKey unwrapKey \
  --query key.kid \
  -o tsv)

FP_A_SYNC=$(key_fingerprint "$KID_A_SYNC")
FP_B_SYNC=$(key_fingerprint "$KID_B_SYNC")
assert_equal "$FP_A_SYNC" "$FP_B_SYNC" \
  "coordinated generation 2 imports do not contain matching material"

RECOVERED=$(decrypt_with "$KID_A_ROTATED" "$CT_ROTATED")
RECOVERED_B64=$(printf '%s' "$RECOVERED" | base64 | tr -d '\r\n')
CT_SYNC=$(encrypt_with "$KID_A_SYNC" "$RECOVERED_B64")
OUT_B_SYNC=$(decrypt_with "$KID_B_SYNC" "$CT_SYNC")
assert_equal "$OUT_B_SYNC" "$PLAINTEXT" \
  "B could not decrypt data reprotected under the synchronized generation"

if decrypt_with "$KID_B_SYNC" "$CT_ROTATED" >/dev/null 2>"$ERROR_LOG"; then
  die "unexpected success: generation 2 decrypted A's earlier private rotation"
fi

# Confirm B remains healthy after rejecting the historical forked ciphertext.
OUT_B_SYNC_CONTROL=$(decrypt_with "$KID_B_SYNC" "$CT_SYNC")
assert_equal "$OUT_B_SYNC_CONTROL" "$PLAINTEXT" \
  "B synchronized-generation health control failed"

A_VERSION_COUNT=$(az keyvault key list-versions \
  --vault-name "$VAULT_A" --name "$KEY_NAME" --query 'length(@)' -o tsv)
B_VERSION_COUNT=$(az keyvault key list-versions \
  --vault-name "$VAULT_B" --name "$KEY_NAME" --query 'length(@)' -o tsv)
assert_equal "$A_VERSION_COUNT" "3" "vault A did not contain the expected three versions"
assert_equal "$B_VERSION_COUNT" "2" "vault B did not contain the expected two versions"

pass_step \
  "A synchronized key ID: \`$KID_A_SYNC\`" \
  "B synchronized key ID: \`$KID_B_SYNC\`" \
  "Synchronized modulus SHA-256: \`$FP_A_SYNC\`" \
  "Data explicitly reprotected under generation 2 was usable in B." \
  "The original A-only rotated ciphertext remained unusable with B generation 2." \
  "Vault A version count: $A_VERSION_COUNT; vault B version count: $B_VERSION_COUNT." \
  "A therefore retains one historical version that B never possessed."

step "8" "Optional cloud cleanup" \
  "Record whether the test key objects are retained or soft-deleted. No purge operation is performed."

ANSWER=n
if read -r -p "soft-delete demo key '$KEY_NAME' from both vaults? [y/N] " ANSWER; then
  :
fi

case "$ANSWER" in
  y|Y|yes|YES)
    az keyvault key delete --vault-name "$VAULT_A" --name "$KEY_NAME" -o none
    CLOUD_CREATED_A=false
    az keyvault key delete --vault-name "$VAULT_B" --name "$KEY_NAME" -o none
    CLOUD_CREATED_B=false
    pass_step \
      "The test key objects were soft-deleted from both vaults." \
      "No purge operation was attempted; normal vault retention controls remain in force."
    ;;
  *)
    pass_step \
      "The test key objects were retained in both vaults." \
      "Key name: \`$KEY_NAME\`"
    ;;
esac

append_report "## Final conclusion"
append_report ""
append_report "**SUCCESS.** All proof assertions completed on $(utc_now)."
append_report ""
append_report "The observed evidence supports this bounded conclusion: independently rotating"
append_report "one of two vaults that initially contain identical imported key material creates"
append_report "a cryptographic fork. A later coordinated import restores compatibility only for"
append_report "data explicitly reprotected under the synchronized generation; it does not make"
append_report "the missing historical rotated material appear in the other vault."
append_report ""
append_report "Accordingly, a duplicated-material design requires coordinated external generation,"
append_report "import into every target vault, controlled consumer cutover, and retention of every"
append_report "generation needed by historical data or backups. Independent in-vault rotation is"
append_report "incompatible with that design."
append_report ""
append_report "## Verification"
append_report ""
append_report "A SHA-256 checksum is written to \`$(basename "$CHECKSUM_PATH")\`. For formal"
append_report "attestation, sign the final report or checksum with an independently controlled"
append_report "organizational signing key and retain it in an immutable evidence repository."
append_report ""

FINALIZED=true
printf '\nPROOF COMPLETED SUCCESSFULLY\n'
