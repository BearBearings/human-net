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
require_cmd python3

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/hn-m4-s3-XXXXXX")
ALICE_HOME="$WORKDIR/alice"
BOB_HOME="$WORKDIR/bob"
mkdir -p "$ALICE_HOME" "$BOB_HOME"

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

decode_multibase_to_base64() {
  local identity_json=$1
  python3 - "$identity_json" <<'PY'
import base64
import json
import sys

alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def b58decode(data: str) -> bytes:
    num = 0
    for char in data:
        num = num * 58 + alphabet.index(char)
    full = num.to_bytes((num.bit_length() + 7) // 8, 'big')
    leading = len(data) - len(data.lstrip('1'))
    return b'\x00' * leading + full

path = sys.argv[1]
payload = json.loads(open(path, 'r', encoding='utf-8').read())
mb = payload['did_document']['verificationMethod'][0]['publicKeyMultibase']
if not mb.startswith('z'):
    raise SystemExit('unsupported multibase: ' + mb)
raw = b58decode(mb[1:])
if len(raw) != 32:
    raise SystemExit(f'unexpected key length {len(raw)} (wanted 32)')
sys.stdout.write(base64.b64encode(raw).decode())
PY
}

echo "→ Initialising identities"
hn_with_home "$ALICE_HOME" id create alice --yes
hn_with_home "$ALICE_HOME" id use alice
hn_with_home "$ALICE_HOME" id verify --provider mock-entra

hn_with_home "$BOB_HOME" id create bob --yes
hn_with_home "$BOB_HOME" id use bob
hn_with_home "$BOB_HOME" id verify --provider mock-didkit

ALICE_IDENTITY="$ALICE_HOME/identities/alice/identity.json"
ALICE_DID=$(jq -r '.profile.id' "$ALICE_IDENTITY")
BOB_IDENTITY="$BOB_HOME/identities/bob/identity.json"
BOB_DID=$(jq -r '.profile.id' "$BOB_IDENTITY")

echo "→ Importing doc"
DOC_RESULT=$(HN_HOME="$ALICE_HOME" hn doc import --type folder@1 --file "$PWD/samples/docs/folder.json" --output json)
DOC_ID=$(printf '%s\n' "$DOC_RESULT" | jq -r '.id')

PROMPT="Offer my finance folder to Bob"

echo "→ Generating plan"
PLAN_JSON=$(HN_HOME="$ALICE_HOME" hn ai plan "$PROMPT" \
  --doc "$DOC_ID" \
  --audience "$BOB_DID" \
  --capability read \
  --output json)
PLAN_ID=$(printf '%s\n' "$PLAN_JSON" | jq -r '.plan.id')
PLAN_PATH=$(printf '%s\n' "$PLAN_JSON" | jq -r '.path')

if [[ ! -f "$PLAN_PATH" ]]; then
  echo "error: expected plan to be written to $PLAN_PATH" >&2
  exit 1
fi

echo "→ Listing plans"
LIST_JSON=$(HN_HOME="$ALICE_HOME" hn ai list --output json)
COUNT=$(printf '%s\n' "$LIST_JSON" | jq '.plans | length')
if [[ "$COUNT" -lt 1 ]]; then
  echo "error: expected at least one plan" >&2
  exit 1
fi

FOUND=$(printf '%s\n' "$LIST_JSON" | jq --arg id "$PLAN_ID" '.plans[] | select(.id==$id) | .id')
if [[ -z "$FOUND" ]]; then
  echo "error: plan $PLAN_ID not found in list" >&2
  exit 1
fi

echo "→ Dry-running plan"
DRY_JSON=$(HN_HOME="$ALICE_HOME" hn ai dry-run "$PLAN_ID" --output json)
printf '%s\n' "$DRY_JSON" | jq -e '.plan.steps | length == 2' >/dev/null

echo "→ Running plan (expected dry-run behaviour)"
RUN_JSON=$(HN_HOME="$ALICE_HOME" hn ai run "$PLAN_ID" --output json)
printf '%s\n' "$RUN_JSON" | jq -e '.plan.id == "'$PLAN_ID'"' >/dev/null

echo "✔ M4 S3 smoke test completed successfully"
