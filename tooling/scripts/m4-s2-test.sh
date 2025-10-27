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
require_cmd curl

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/hn-m4-s2-XXXXXX")
ALICE_HOME="$WORKDIR/alice"
BOB_HOME="$WORKDIR/bob"
STORAGE_DIR="$WORKDIR/mcp-storage"
PUBLISH_DIR="$WORKDIR/publish"
LOG_DIR="$WORKDIR/logs"
mkdir -p "$ALICE_HOME" "$BOB_HOME" "$STORAGE_DIR" "$PUBLISH_DIR" "$LOG_DIR"
MCP_LOG="$LOG_DIR/mcp.log"

cleanup() {
  if [[ -n "${MCP_PID:-}" ]]; then
    kill "$MCP_PID" >/dev/null 2>&1 || true
    wait "$MCP_PID" >/dev/null 2>&1 || true
  fi
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
hn_with_home "$BOB_HOME" id create bob --yes
hn_with_home "$BOB_HOME" id use bob
hn_with_home "$ALICE_HOME" id verify --provider mock-entra
hn_with_home "$BOB_HOME" id verify --provider mock-didkit

ALICE_IDENTITY="$ALICE_HOME/identities/alice/identity.json"
ALICE_DID=$(jq -r '.profile.id' "$ALICE_IDENTITY")
ALICE_PUB_BASE64=$(decode_multibase_to_base64 "$ALICE_IDENTITY")
BOB_IDENTITY="$BOB_HOME/identities/bob/identity.json"
BOB_DID=$(jq -r '.profile.id' "$BOB_IDENTITY")

echo "→ Creating doc, offer, contract, and fulfilment"
DOC_RESULT=$(HN_HOME="$ALICE_HOME" hn doc import --type folder@1 --file "$PWD/samples/docs/folder.json" --output json)
DOC_ID=$(printf '%s\n' "$DOC_RESULT" | jq -r '.id')

OFFER_FILE="$WORKDIR/offer.json"
HN_HOME="$ALICE_HOME" hn contract offer create \
  --audience "$BOB_DID" \
  --doc "$DOC_ID" \
  --capability read \
  --policy-ref policy:doc.read \
  --emit "$OFFER_FILE" >/dev/null

CONTRACT_FILE="$WORKDIR/contract.json"
HN_HOME="$BOB_HOME" hn contract accept --offer "$OFFER_FILE" --emit "$CONTRACT_FILE" >/dev/null
CONTRACT_ID=$(jq -r '.id' "$CONTRACT_FILE")
CONTRACT_FILENAME="${CONTRACT_ID//[:\/ ]/_}.json"
mkdir -p "$ALICE_HOME/contracts/alice"
cp "$CONTRACT_FILE" "$ALICE_HOME/contracts/alice/$CONTRACT_FILENAME"

HN_HOME="$ALICE_HOME" hn contract fulfill \
  --contract-id "$CONTRACT_ID" \
  --payload "$PWD/samples/docs/folder.json" \
  --emit "$WORKDIR/contract-fulfilled.json" \
  --emit-shard "$WORKDIR/shard.json" >/dev/null
SHARD_ID=$(jq -r '.id' "$WORKDIR/shard.json")
ALICE_SHARD_FILE="$ALICE_HOME/shards/alice/${SHARD_ID//[:\/ ]/_}.json"

cat <<EOF2 >"$BOB_HOME/mcp.json"
{
  "listen": "127.0.0.1:0",
  "mode": "friends",
  "max_ttl_seconds": 604800,
  "storage": "$STORAGE_DIR",
  "allow": [
    {
      "did": "$ALICE_DID",
      "public_key": "$ALICE_PUB_BASE64"
    }
  ]
}
EOF2

echo "→ Selecting loopback port"
if PORT=$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
port = s.getsockname()[1]
s.close()
print(port)
PY
); then
  PORT=$(printf "%s" "$PORT" | tr -d '\n')
else
  PORT=7733
fi

start_mcp() {
  local presence_path=$1
  (
    export HN_HOME="$BOB_HOME"
    if [[ -n "$presence_path" ]]; then
      hn mcp serve --config "$BOB_HOME/mcp.json" --listen "127.0.0.1:$PORT" --presence-path "$presence_path"
    else
      hn mcp serve --config "$BOB_HOME/mcp.json" --listen "127.0.0.1:$PORT"
    fi
  ) >"$MCP_LOG" 2>&1 &
  MCP_PID=$!
  for _ in $(seq 1 50); do
    if curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  echo "error: MCP server failed to start (see $MCP_LOG)" >&2
  exit 1
}

stop_mcp() {
  if [[ -n "${MCP_PID:-}" ]]; then
    kill "$MCP_PID" >/dev/null 2>&1 || true
    wait "$MCP_PID" >/dev/null 2>&1 || true
    unset MCP_PID
  fi
}

echo "→ Seeding publish bundle locally"
LOCAL_PUBLISH_JSON=$(HN_HOME="$ALICE_HOME" hn shard publish \
  --target "$PUBLISH_DIR" \
  --alias alice \
  --output json)
printf '%s\n' "$LOCAL_PUBLISH_JSON" | jq -e '.counts.shards == 1' >/dev/null
MERKLE_ROOT=$(printf '%s\n' "$LOCAL_PUBLISH_JSON" | jq -r '.index.merkle_root')

echo "→ Publishing presence for bob"
PRESENCE_JSON=$(HN_HOME="$BOB_HOME" hn discover publish \
  --alias bob \
  --merkle-root "$MERKLE_ROOT" \
  --ttl-seconds 600 \
  --endpoint "mcp=http://127.0.0.1:$PORT" \
  --endpoint "presence=http://127.0.0.1:$PORT/presence" \
  --output json)
PRESENCE_PATH=$(printf '%s\n' "$PRESENCE_JSON" | jq -r '.path')

if [[ ! -f "$PRESENCE_PATH" ]]; then
  echo "error: presence document not found at $PRESENCE_PATH" >&2
  exit 1
fi

echo "→ Launching MCP server"
start_mcp "$PRESENCE_PATH"

echo "→ Publishing shard bundle via MCP"
REMOTE_PUBLISH_JSON=$(HN_HOME="$ALICE_HOME" hn shard publish \
  --target "$PUBLISH_DIR" \
  --alias alice \
  --mcp-url "http://127.0.0.1:$PORT" \
  --mcp-allow-http \
  --output json)
printf '%s\n' "$REMOTE_PUBLISH_JSON" | jq -e '.counts.shards == 1' >/dev/null
printf '%s\n' "$REMOTE_PUBLISH_JSON" | jq -e '.mcp.response.accepted == true' >/dev/null

echo "→ Refreshing presence from server"
REFRESH_JSON=$(HN_HOME="$ALICE_HOME" hn discover refresh \
  --did "$BOB_DID" \
  --url "http://127.0.0.1:$PORT/presence" \
  --output json)
printf '%s\n' "$REFRESH_JSON" | jq -e '.presence.did == "'$BOB_DID'"' >/dev/null

HINTS_COUNT=$(HN_HOME="$ALICE_HOME" hn discover list --hints --output json | jq '.presence | length')
if [[ "$HINTS_COUNT" -lt 1 ]]; then
  echo "error: expected presence hint to be stored" >&2
  exit 1
fi

echo "→ Subscribing from MCP using presence"
SUBSCRIBE_JSON=$(HN_HOME="$BOB_HOME" hn shard subscribe \
  --presence-did "$BOB_DID" \
  --alias bob \
  --no-import \
  --output json)
printf '%s\n' "$SUBSCRIBE_JSON" | jq -e '.processed.shards | length == 1' >/dev/null
printf '%s\n' "$SUBSCRIBE_JSON" | jq -e '.source.presence.did == "'$BOB_DID'"' >/dev/null

EXPECTED_SHARD="$BOB_HOME/shards/bob/${SHARD_ID//[:\/ ]/_}.json"
if [[ ! -f "$EXPECTED_SHARD" ]]; then
  echo "error: expected shard not materialised at $EXPECTED_SHARD" >&2
  exit 1
fi

if ! diff -q "$ALICE_SHARD_FILE" "$EXPECTED_SHARD" >/dev/null; then
  echo "error: shard content mismatch between publisher and subscriber" >&2
  exit 1
fi

echo "✔ M4 S2 smoke test completed successfully"
