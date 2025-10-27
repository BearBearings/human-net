#!/usr/bin/env bash
set -euo pipefail

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: missing required command '$1'" >&2
    exit 1
  fi
}

require_cmd hn
require_cmd jq

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/hn-m4-s4-XXXXXX")
PRIMARY_HOME="$WORKDIR/primary"
SECONDARY_HOME="$WORKDIR/secondary"
BUNDLE_FILE="$WORKDIR/alice.bundle"
mkdir -p "$PRIMARY_HOME" "$SECONDARY_HOME"

cleanup() {
  if [[ -z "${KEEP_WORKDIR:-}" ]]; then
    rm -rf "$WORKDIR"
  else
    echo "keeping workdir: $WORKDIR"
  fi
}
trap 'status=$?; trap - EXIT; cleanup; exit $status' EXIT

echo "Using workdir: $WORKDIR"

hn_with_home() {
  local home=$1
  shift
  HN_HOME="$home" hn "$@"
}

echo "→ Initialising primary identity"
hn_with_home "$PRIMARY_HOME" id create alice --yes
hn_with_home "$PRIMARY_HOME" id use alice

echo "→ Importing sample doc"
DOC_JSON=$(HN_HOME="$PRIMARY_HOME" hn doc import \
  --type folder@1 \
  --file "$PWD/samples/docs/folder.json" \
  --output json)
DOC_ID=$(printf '%s\n' "$DOC_JSON" | jq -r '.id')
DOC_HASH=$(printf '%s\n' "$DOC_JSON" | jq -r '.canonical_hash')

echo "→ Creating view definition"
HN_HOME="$PRIMARY_HOME" hn doc view create finance --rule 'type=folder@1 AND tags:"finance"' >/dev/null

echo "→ Materialising view via hn view run"
RUN_JSON=$(HN_HOME="$PRIMARY_HOME" hn view run finance --output json)
printf '%s\n' "$RUN_JSON" | jq -e '.snapshot.canonical_hash | length > 0' >/dev/null
printf '%s\n' "$RUN_JSON" | jq -e '.receipt.signature | length > 0' >/dev/null

echo "→ Verifying latest receipt"
VERIFY_JSON=$(HN_HOME="$PRIMARY_HOME" hn view verify finance --output json)
printf '%s\n' "$VERIFY_JSON" | jq -e '.signature_valid == true' >/dev/null
printf '%s\n' "$VERIFY_JSON" | jq -e '.matches_current == true' >/dev/null

echo "→ Exporting identity bundle"
HN_HOME="$PRIMARY_HOME" hn id export alice --file "$BUNDLE_FILE" --password passphrase >/dev/null

echo "→ Recovering identity on secondary device"
hn_with_home "$SECONDARY_HOME" id recover "$BUNDLE_FILE" --password passphrase --alias alice >/dev/null
hn_with_home "$SECONDARY_HOME" id use alice

echo "→ Pairing primary and secondary vaults"
PREP_JSON=$(HN_HOME="$PRIMARY_HOME" hn sync pair --qr --output json)
TICKET=$(printf '%s\n' "$PREP_JSON" | jq -r '.ticket')

ACCEPT_JSON=$(HN_HOME="$SECONDARY_HOME" hn sync pair --qr --token "$TICKET" --output json)
RESPONSE=$(printf '%s\n' "$ACCEPT_JSON" | jq -r '.response')
SECONDARY_INBOX=$(printf '%s\n' "$ACCEPT_JSON" | jq -r '.pair.inbox_dir')

FINALIZE_JSON=$(HN_HOME="$PRIMARY_HOME" hn sync pair --qr --token "$RESPONSE" --output json)
printf '%s\n' "$FINALIZE_JSON" | jq -e '.pair.id | length > 0' >/dev/null

echo "→ Pushing sync bundle from primary"
PUSH_JSON=$(HN_HOME="$PRIMARY_HOME" hn sync push --output json)
printf '%s\n' "$PUSH_JSON" | jq -e '.bundles | length == 1' >/dev/null
BUNDLE_PATH=$(printf '%s\n' "$PUSH_JSON" | jq -r '.bundles[0].bundle_path')

if [[ ! -f "$BUNDLE_PATH" ]]; then
  echo "error: bundle not found at $BUNDLE_PATH" >&2
  exit 1
fi

echo "→ Delivering bundle to secondary inbox"
cp "$BUNDLE_PATH" "$SECONDARY_INBOX/"

echo "→ Pulling bundle on secondary"
PULL_JSON=$(HN_HOME="$SECONDARY_HOME" hn sync pull --output json)
printf '%s\n' "$PULL_JSON" | jq -e '.bundles | length == 1' >/dev/null
printf '%s\n' "$PULL_JSON" | jq -e '.bundles[0].docs_applied > 0' >/dev/null

echo "→ Verifying replicated doc canonical hash"
SECONDARY_DOC=$(HN_HOME="$SECONDARY_HOME" hn doc get "$DOC_ID" --output json)
SECONDARY_HASH=$(printf '%s\n' "$SECONDARY_DOC" | jq -r '.canonical_hash')
if [[ "$SECONDARY_HASH" != "$DOC_HASH" ]]; then
  echo "error: canonical hash mismatch after sync" >&2
  exit 1
fi

echo "✔ M4 S4 sync and view smoke completed successfully"
