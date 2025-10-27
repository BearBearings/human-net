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

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/hn-m4-s1-XXXXXX")
ALICE_HOME="$WORKDIR/alice"
BOB_HOME="$WORKDIR/bob"
CAROL_HOME="$WORKDIR/carol"
STORAGE_DIR="$WORKDIR/mcp-storage"
PUBLISH_DIR="$WORKDIR/publish"
LOG_DIR="$WORKDIR/logs"
mkdir -p "$ALICE_HOME" "$BOB_HOME" "$CAROL_HOME" "$STORAGE_DIR" "$PUBLISH_DIR" "$LOG_DIR"
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

generate_shard_fixture() {
  local target_file=$1
  local publisher_did=$2
  cat <<EOF >"$target_file"
{
  "id": "shard-demo",
  "contract_id": "contract-demo",
  "publisher": "$publisher_did",
  "created_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "algorithm": "ChaCha20Poly1305",
  "payload_cid": "cid-demo",
  "ciphertext": "ZGVtb0NpcGhlckJvZHk=",
  "enc": "ZGVtb0VuY0tleQ=="
}
EOF
}

echo "→ Initialising identities"
hn_with_home "$ALICE_HOME" id create alice --yes
hn_with_home "$ALICE_HOME" id use alice
hn_with_home "$BOB_HOME" id create bob --yes
hn_with_home "$BOB_HOME" id use bob
hn_with_home "$CAROL_HOME" id create carol --yes
hn_with_home "$CAROL_HOME" id use carol

ALICE_IDENTITY="$ALICE_HOME/identities/alice/identity.json"
ALICE_DID=$(jq -r '.profile.id' "$ALICE_IDENTITY")
ALICE_PUB_BASE64=$(decode_multibase_to_base64 "$ALICE_IDENTITY")

echo "→ Seeding shard fixture under $ALICE_HOME"
mkdir -p "$ALICE_HOME/shards/alice"
generate_shard_fixture "$ALICE_HOME/shards/alice/shard-demo.json" "$ALICE_DID"

cat <<EOF >"$BOB_HOME/mcp.json"
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
EOF

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

echo "→ Launching MCP server on port $PORT"
(
  export HN_HOME="$BOB_HOME"
  hn mcp serve --config "$BOB_HOME/mcp.json" --listen "127.0.0.1:$PORT"
) >"$MCP_LOG" 2>&1 &
MCP_PID=$!

for _ in $(seq 1 50); do
  if curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null; then
    break
  fi
  sleep 0.2
done

if ! curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null; then
  echo "error: MCP server failed to start (see $MCP_LOG)" >&2
  exit 1
fi

echo "→ Publishing shard bundle via MCP"
PUBLISH_JSON=$(HN_HOME="$ALICE_HOME" hn shard publish \
  --target "$PUBLISH_DIR" \
  --alias alice \
  --mcp-url "http://127.0.0.1:$PORT" \
  --mcp-allow-http \
  --output json)
printf '%s\n' "$PUBLISH_JSON" | jq -e '.counts.shards == 1' >/dev/null
printf '%s\n' "$PUBLISH_JSON" | jq -e '.mcp.response.accepted == true' >/dev/null

echo "→ Subscribing from MCP as carol"
SUBSCRIBE_JSON=$(HN_HOME="$CAROL_HOME" hn shard subscribe \
  --mcp-url "http://127.0.0.1:$PORT" \
  --alias carol \
  --output json)
printf '%s\n' "$SUBSCRIBE_JSON" | jq -e '.processed.shards | length == 1' >/dev/null

EXPECTED_SHARD="$CAROL_HOME/shards/carol/shard-demo.json"
if [[ ! -f "$EXPECTED_SHARD" ]]; then
  echo "error: expected shard not materialised at $EXPECTED_SHARD" >&2
  exit 1
fi

if ! diff -q "$ALICE_HOME/shards/alice/shard-demo.json" "$EXPECTED_SHARD" >/dev/null; then
  echo "error: shard content mismatch between publisher and subscriber" >&2
  exit 1
fi

echo "✔ M4 S1 smoke test completed successfully"
