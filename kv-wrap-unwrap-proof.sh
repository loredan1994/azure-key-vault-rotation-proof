#!/usr/bin/env bash
# Versioned native Key Vault wrapKey/unwrapKey rotation-fork proof.
#
# Usage:
#   ./kv-wrap-unwrap-proof.sh <vault-a> <vault-b>
#
# Before running:
#   az login
#   az account set --subscription <subscription-id-or-name>
#
# The signed-in identity needs Key Vault Crypto Officer on both vaults, or
# equivalent key permissions for list, import, get, wrapKey, unwrapKey, rotate,
# list-versions, and delete if optional cleanup is selected.
#
# This script uses native Key Vault REST data-plane wrapkey/unwrapkey endpoints.
# It never obtains, prints, or stores an OAuth bearer token itself; `az rest`
# handles authentication through the existing Azure CLI session.

set -Eeuo pipefail
umask 077

readonly SCRIPT_NAME="kv-wrap-unwrap-proof"
readonly SCRIPT_VERSION="1.0.0"
readonly KEY_VAULT_API_VERSION="7.6"
readonly WRAP_ALGORITHM="RSA-OAEP-256"

VAULT_A="${1:?usage: $0 <vault-a> <vault-b>}"
VAULT_B="${2:?usage: $0 <vault-a> <vault-b>}"
[ "$#" -eq 2 ] || {
  printf 'usage: %s <vault-a> <vault-b>\n' "$0" >&2
  exit 2
}

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-${RANDOM}"
KEY_NAME="dr-wrap-proof-${RUN_ID}"
REPORT_PATH="$PWD/kv-wrap-unwrap-evidence-${RUN_ID}.md"
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

pem_fingerprint() {
  openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | hash_stdin
}

key_fingerprint() {
  local modulus
  modulus=$(az keyvault key show --id "$1" --query key.n -o tsv)
  [ -n "$modulus" ] || die "could not obtain RSA modulus for $1"
  printf '%s' "$modulus" | hash_stdin
}

base64url_random_256() {
  openssl rand -base64 32 | tr -d '\r\n' | tr '+/' '-_' | sed 's/=*$//'
}

wrap_key() {
  local kid="$1"
  local value="$2"
  local body
  body=$(jq -cn \
    --arg alg "$WRAP_ALGORITHM" \
    --arg value "$value" \
    '{alg: $alg, value: $value}')

  az rest \
    --resource 'https://vault.azure.net' \
    --method post \
    --url "${kid}/wrapkey?api-version=${KEY_VAULT_API_VERSION}" \
    --headers 'Content-Type=application/json' \
    --body "$body" \
    --query value \
    --output tsv
}

unwrap_key() {
  local kid="$1"
  local wrapped_value="$2"
  local body
  body=$(jq -cn \
    --arg alg "$WRAP_ALGORITHM" \
    --arg value "$wrapped_value" \
    '{alg: $alg, value: $value}')

  az rest \
    --resource 'https://vault.azure.net' \
    --method post \
    --url "${kid}/unwrapkey?api-version=${KEY_VAULT_API_VERSION}" \
    --headers 'Content-Type=application/json' \
    --body "$body" \
    --query value \
    --output tsv
}

key_count() {
  local vault="$1"
  az keyvault key list \
    --vault-name "$vault" \
    --query "[?name=='${KEY_NAME}'] | length(@)" \
    --output tsv
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

: >"$REPORT_PATH"
REPORT_READY=true
append_report "# Native Azure Key Vault wrap/unwrap rotation evidence"
append_report ""
append_report "- Script: \`$SCRIPT_NAME\`"
append_report "- Script version: \`$SCRIPT_VERSION\`"
append_report "- Key Vault REST API: \`$KEY_VAULT_API_VERSION\`"
append_report "- Wrap algorithm: \`$WRAP_ALGORITHM\`"
append_report "- Run ID: \`$RUN_ID\`"
append_report "- Generated (UTC): $(utc_now)"
append_report "- Vault A: \`$VAULT_A\`"
append_report "- Vault B: \`$VAULT_B\`"
append_report "- Test key: \`$KEY_NAME\`"
append_report ""
append_report "## Scope and limits"
append_report ""
append_report "This proof calls the native Key Vault REST wrapkey and unwrapkey endpoints."
append_report "It records key identifiers, public-key fingerprints, timestamps, and assertion"
append_report "outcomes. It does not retain private keys, bearer tokens, DEK plaintext, wrapped"
append_report "values, or other live credentials."
append_report ""
append_report "This is self-generated evidence rather than an independently signed attestation."
append_report "It demonstrates the cryptographic primitive used by envelope encryption, but it"
append_report "does not by itself prove the behavior of a specific Azure service such as SQL TDE."
append_report ""

require_command az
require_command openssl
require_command jq
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
ERROR_LOG="$TEMP_DIR/expected-unwrap-error.log"

step "0" "Preflight" \
  "Confirm the Azure context, REST authentication path, vault separation, and collision-free key name."

if ! SUBSCRIPTION_ID=$(az account show --query id --output tsv); then
  die "Azure CLI is not authenticated; run az login first"
fi
[ -n "$SUBSCRIPTION_ID" ] || die "Azure CLI returned no active subscription"
TENANT_ID=$(az account show --query tenantId --output tsv)
AZ_VERSION=$(az version --query '"azure-cli"' --output tsv 2>/dev/null || printf 'unknown')
OPENSSL_VERSION=$(openssl version)

# Read-only native data-plane request confirms the OAuth audience and endpoint.
az rest \
  --resource 'https://vault.azure.net' \
  --method get \
  --url "https://${VAULT_A}.vault.azure.net/keys?api-version=${KEY_VAULT_API_VERSION}&maxresults=1" \
  --query 'value | length(@)' \
  --output tsv >/dev/null

COUNT_A=$(key_count "$VAULT_A")
COUNT_B=$(key_count "$VAULT_B")
assert_equal "$COUNT_A" "0" "generated test key unexpectedly exists in vault $VAULT_A"
assert_equal "$COUNT_B" "0" "generated test key unexpectedly exists in vault $VAULT_B"

pass_step \
  "Active subscription ID: \`$SUBSCRIPTION_ID\`" \
  "Tenant ID: \`$TENANT_ID\`" \
  "Azure CLI version: \`$AZ_VERSION\`" \
  "OpenSSL: \`$OPENSSL_VERSION\`" \
  "Native Key Vault REST authentication succeeded without exporting a token." \
  "The generated key name was absent from both vaults."

step "1" "Generate local RSA generations and a synthetic DEK" \
  "Generate two distinct RSA-2048 keypairs and a random 256-bit DEK in the process-local temporary workspace."

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$GENESIS_V1" 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$GENESIS_V2" 2>/dev/null
openssl rsa -in "$GENESIS_V1" -check -noout >/dev/null 2>&1 ||
  die "generated generation 1 is not a valid RSA private key"
openssl rsa -in "$GENESIS_V2" -check -noout >/dev/null 2>&1 ||
  die "generated generation 2 is not a valid RSA private key"

PEM_FP_V1=$(pem_fingerprint "$GENESIS_V1")
PEM_FP_V2=$(pem_fingerprint "$GENESIS_V2")
assert_different "$PEM_FP_V1" "$PEM_FP_V2" \
  "the generated RSA keypairs unexpectedly have the same public fingerprint"
DEK_B64URL=$(base64url_random_256)
[ -n "$DEK_B64URL" ] || die "failed to generate the synthetic DEK"

pass_step \
  "Generation 1 SPKI SHA-256: \`$PEM_FP_V1\`" \
  "Generation 2 SPKI SHA-256: \`$PEM_FP_V2\`" \
  "A random 256-bit DEK was generated but is not written to the report." \
  "Temporary private keys are removed on every exit path."

step "2" "Import identical generation 1" \
  "Import the same software RSA key into both independent vaults with wrapKey and unwrapKey operations."

KID_A_V1=$(az keyvault key import \
  --vault-name "$VAULT_A" \
  --name "$KEY_NAME" \
  --pem-file "$GENESIS_V1" \
  --protection software \
  --ops wrapKey unwrapKey \
  --query key.kid \
  --output tsv)
CLOUD_CREATED_A=true

KID_B_V1=$(az keyvault key import \
  --vault-name "$VAULT_B" \
  --name "$KEY_NAME" \
  --pem-file "$GENESIS_V1" \
  --protection software \
  --ops wrapKey unwrapKey \
  --query key.kid \
  --output tsv)
CLOUD_CREATED_B=true

FP_A_V1=$(key_fingerprint "$KID_A_V1")
FP_B_V1=$(key_fingerprint "$KID_B_V1")
assert_equal "$FP_A_V1" "$FP_B_V1" \
  "initial imports do not have matching RSA public material"

pass_step \
  "Vault A v1: \`$KID_A_V1\`" \
  "Vault B v1: \`$KID_B_V1\`" \
  "Shared modulus SHA-256: \`$FP_A_V1\`"

step "3" "Native cross-vault unwrap before rotation" \
  "Wrap the synthetic DEK with A v1 and unwrap the result with the exact B v1 key version."

WRAPPED_V1=$(wrap_key "$KID_A_V1" "$DEK_B64URL")
UNWRAPPED_B_V1=$(unwrap_key "$KID_B_V1" "$WRAPPED_V1")
assert_equal "$UNWRAPPED_B_V1" "$DEK_B64URL" \
  "B v1 did not unwrap the exact DEK wrapped by A v1"

pass_step \
  "A v1 wrapkey returned successfully." \
  "B v1 unwrapkey recovered the exact 256-bit DEK." \
  "The DEK and wrapped value are intentionally omitted from evidence."

step "4" "Rotate vault A only" \
  "Invoke rotation only in A and prove that A's new public key differs while B remains unchanged."

KID_A_ROTATED=$(az keyvault key rotate \
  --vault-name "$VAULT_A" \
  --name "$KEY_NAME" \
  --query key.kid \
  --output tsv)
[ -n "$KID_A_ROTATED" ] || die "rotation returned no versioned key ID"
KID_B_CURRENT=$(az keyvault key show \
  --vault-name "$VAULT_B" \
  --name "$KEY_NAME" \
  --query key.kid \
  --output tsv)
assert_equal "$KID_B_CURRENT" "$KID_B_V1" \
  "vault B changed concurrently; the experiment is no longer isolated"

FP_A_ROTATED=$(key_fingerprint "$KID_A_ROTATED")
assert_different "$FP_A_ROTATED" "$FP_B_V1" \
  "A rotation unexpectedly produced material matching B v1"

pass_step \
  "A rotated version: \`$KID_A_ROTATED\`" \
  "A rotated modulus SHA-256: \`$FP_A_ROTATED\`" \
  "B remained on: \`$KID_B_V1\`"

step "5" "Native wrap/unwrap fork proof" \
  "Bracket the expected B failure with successful native unwrap controls to isolate the key-material mismatch."

WRAPPED_ROTATED=$(wrap_key "$KID_A_ROTATED" "$DEK_B64URL")
UNWRAPPED_A_ROTATED=$(unwrap_key "$KID_A_ROTATED" "$WRAPPED_ROTATED")
assert_equal "$UNWRAPPED_A_ROTATED" "$DEK_B64URL" \
  "A's rotated version could not unwrap its own wrapped DEK"

UNWRAPPED_B_PRE=$(unwrap_key "$KID_B_V1" "$WRAPPED_V1")
assert_equal "$UNWRAPPED_B_PRE" "$DEK_B64URL" \
  "B v1 health control failed before the mismatch test"

if unwrap_key "$KID_B_V1" "$WRAPPED_ROTATED" >/dev/null 2>"$ERROR_LOG"; then
  die "unexpected success: B v1 unwrapped a DEK wrapped by A's rotated key"
fi

UNWRAPPED_B_POST=$(unwrap_key "$KID_B_V1" "$WRAPPED_V1")
assert_equal "$UNWRAPPED_B_POST" "$DEK_B64URL" \
  "B v1 health control failed after the mismatch test"

ERROR_DIGEST=$(hash_file "$ERROR_LOG")
ERROR_EXCERPT=$(sed '/^WARNING:/d; /^[[:space:]]*$/d' "$ERROR_LOG" |
  sed -n '1p' | tr -d '\r')
[ -n "$ERROR_EXCERPT" ] || ERROR_EXCERPT="Native unwrap returned nonzero without stderr text."

pass_step \
  "A's rotated version successfully unwrapped its own wrapped DEK." \
  "B v1 successfully unwrapped the known-good v1 value before and after the mismatch test." \
  "B v1 rejected the DEK wrapped under A's rotated version." \
  "Expected-error log SHA-256: \`$ERROR_DIGEST\`" \
  "Native API error excerpt: $ERROR_EXCERPT"

step "6" "Coordinated generation 2 and explicit rewrap" \
  "Import shared generation 2 into B and A, wrap the DEK again, and prove both forward compatibility and the unrepaired historical gap."

KID_B_SYNC=$(az keyvault key import \
  --vault-name "$VAULT_B" \
  --name "$KEY_NAME" \
  --pem-file "$GENESIS_V2" \
  --protection software \
  --ops wrapKey unwrapKey \
  --query key.kid \
  --output tsv)
KID_A_SYNC=$(az keyvault key import \
  --vault-name "$VAULT_A" \
  --name "$KEY_NAME" \
  --pem-file "$GENESIS_V2" \
  --protection software \
  --ops wrapKey unwrapKey \
  --query key.kid \
  --output tsv)

FP_A_SYNC=$(key_fingerprint "$KID_A_SYNC")
FP_B_SYNC=$(key_fingerprint "$KID_B_SYNC")
assert_equal "$FP_A_SYNC" "$FP_B_SYNC" \
  "coordinated generation 2 imports do not match"

WRAPPED_SYNC=$(wrap_key "$KID_A_SYNC" "$DEK_B64URL")
UNWRAPPED_B_SYNC=$(unwrap_key "$KID_B_SYNC" "$WRAPPED_SYNC")
assert_equal "$UNWRAPPED_B_SYNC" "$DEK_B64URL" \
  "B generation 2 could not unwrap the rewrapped DEK"

if unwrap_key "$KID_B_SYNC" "$WRAPPED_ROTATED" >/dev/null 2>"$ERROR_LOG"; then
  die "unexpected success: B generation 2 unwrapped A's earlier forked value"
fi

UNWRAPPED_B_SYNC_CONTROL=$(unwrap_key "$KID_B_SYNC" "$WRAPPED_SYNC")
assert_equal "$UNWRAPPED_B_SYNC_CONTROL" "$DEK_B64URL" \
  "B generation 2 health control failed"

A_VERSION_COUNT=$(az keyvault key list-versions \
  --vault-name "$VAULT_A" --name "$KEY_NAME" --query 'length(@)' --output tsv)
B_VERSION_COUNT=$(az keyvault key list-versions \
  --vault-name "$VAULT_B" --name "$KEY_NAME" --query 'length(@)' --output tsv)
assert_equal "$A_VERSION_COUNT" "3" "vault A did not contain three expected versions"
assert_equal "$B_VERSION_COUNT" "2" "vault B did not contain two expected versions"

pass_step \
  "A synchronized version: \`$KID_A_SYNC\`" \
  "B synchronized version: \`$KID_B_SYNC\`" \
  "Synchronized modulus SHA-256: \`$FP_A_SYNC\`" \
  "B unwrapped the DEK after it was explicitly rewrapped under generation 2." \
  "B generation 2 still rejected the value wrapped by A's private rotated version." \
  "Vault A versions: $A_VERSION_COUNT; vault B versions: $B_VERSION_COUNT."

step "7" "Optional cloud cleanup" \
  "Record whether the unique test objects are retained or soft-deleted; never purge them."

ANSWER=n
if read -r -p "soft-delete demo key '$KEY_NAME' from both vaults? [y/N] " ANSWER; then
  :
fi

case "$ANSWER" in
  y|Y|yes|YES)
    az keyvault key delete --vault-name "$VAULT_A" --name "$KEY_NAME" --output none
    CLOUD_CREATED_A=false
    az keyvault key delete --vault-name "$VAULT_B" --name "$KEY_NAME" --output none
    CLOUD_CREATED_B=false
    pass_step \
      "Both test key objects were soft-deleted." \
      "No purge operation was performed."
    ;;
  *)
    pass_step \
      "Both test key objects were retained." \
      "Key name: \`$KEY_NAME\`"
    ;;
esac

append_report "## Final conclusion"
append_report ""
append_report "**SUCCESS.** All native wrapKey/unwrapKey assertions completed on $(utc_now)."
append_report ""
append_report "The observed evidence supports this bounded conclusion: two independent vaults"
append_report "can unwrap one another's values while they contain identical imported material."
append_report "Rotating only one vault creates fresh material that the other vault cannot use."
append_report "A later coordinated import restores compatibility only after the DEK is explicitly"
append_report "rewrapped; it does not reproduce or repair the missing historical rotation."
append_report ""
append_report "No OAuth token, private key, DEK, or wrapped DEK is retained by this report."
append_report "A SHA-256 sidecar is produced for integrity checking; formal attestation requires"
append_report "signing that digest through an independently controlled signing process."
append_report ""

FINALIZED=true
printf '\nNATIVE WRAP/UNWRAP PROOF COMPLETED SUCCESSFULLY\n'
