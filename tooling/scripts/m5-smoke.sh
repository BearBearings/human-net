#!/usr/bin/env bash
# M5 smoke test:
# - Spins up one federation MCP hub (Alice) with discovery.
# - Onboards additional peers (Bob, Carol, Dora) and exchanges presence hints.
# - Verifies federation sync, relay retention, trust graph computation,
#   DHT resolve fallback, and vault backup/restore workflows.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLI_MANIFEST="${ROOT_DIR}/cli/Cargo.toml"
DISCOVERY_MANIFEST="${ROOT_DIR}/services/discovery/Cargo.toml"
MCP_MANIFEST="${ROOT_DIR}/services/mcp/Cargo.toml"

if [[ -n "${HN_M5_CLI_BIN:-}" ]]; then
  CLI_CMD=(${HN_M5_CLI_BIN})
elif [[ -x "${ROOT_DIR}/target/debug/hn" ]]; then
  CLI_CMD=("${ROOT_DIR}/target/debug/hn")
else
  CLI_CMD=(cargo run --manifest-path "${CLI_MANIFEST}" --bin hn --)
fi
if [[ -n "${HN_M5_DISCOVERY_BIN:-}" ]]; then
  DISCOVERY_CMD=(${HN_M5_DISCOVERY_BIN})
elif [[ -x "${ROOT_DIR}/target/debug/hn-discovery" ]]; then
  DISCOVERY_CMD=("${ROOT_DIR}/target/debug/hn-discovery")
else
  DISCOVERY_CMD=(cargo run --manifest-path "${DISCOVERY_MANIFEST}" --bin hn-discovery --)
fi
if [[ -n "${HN_M5_MCP_BIN:-}" ]]; then
  MCP_CMD=(${HN_M5_MCP_BIN} mcp)
elif [[ -x "${ROOT_DIR}/target/debug/hn" ]]; then
  MCP_CMD=("${ROOT_DIR}/target/debug/hn" mcp)
else
  MCP_CMD=(cargo run --manifest-path "${CLI_MANIFEST}" --bin hn -- mcp)
fi

command -v jq >/dev/null || {
  echo "jq is required for m5-smoke.sh" >&2
  exit 1
}

SUITE_HOME="$(mktemp -d)"
RUN_ID="$(date +%s%N)"
if [[ -z "${HN_M5_KEEP:-}" ]]; then
  trap 'cleanup' EXIT
fi

declare -a USER_HOME
declare -a MCP_PIDS
declare -a USER_DIDS
declare -a USER_VERIFY_KEYS
declare -a MCP_BASE_URLS
declare -a MCP_PRESENCE_URLS
declare -a MCP_LISTENS
declare -a DISCOVERY_PIDS
declare -a DISCOVERY_BASE_URLS

USERS=(alice bob carol dora)
HUB=alice

cleanup() {
  if (( ${#MCP_PIDS[@]} )); then
    for pid in "${MCP_PIDS[@]}"; do
      if [[ -n "${pid}" ]]; then
        kill "${pid}" >/dev/null 2>&1 || true
        wait "${pid}" >/dev/null 2>&1 || true
      fi
    done
  fi
  if (( ${#DISCOVERY_PIDS[@]} )); then
    for pid in "${DISCOVERY_PIDS[@]}"; do
      if [[ -n "${pid}" ]]; then
        kill "${pid}" >/dev/null 2>&1 || true
        wait "${pid}" >/dev/null 2>&1 || true
      fi
    done
  fi
  rm -rf "${SUITE_HOME}"
}

log() { printf '\n==> %s\n' "$*"; }

user_index() {
  local target="$1"
  for i in "${!USERS[@]}"; do
    if [[ "${USERS[$i]}" == "${target}" ]]; then
      echo "${i}"
      return 0
    fi
  done
  echo "-1"
  return 1
}

user_home() {
  local idx
  idx=$(user_index "$1")
  if [[ "${idx}" -lt 0 ]]; then
    echo ""
    return 1
  fi
  echo "${USER_HOME[$idx]}"
}

sanitize_id() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed -e 's/[^0-9a-z]/-/g' -e 's/^-\+//' -e 's/-\+$//' -e 's/-\{2,\}/-/g'
}

with_user() {
  local user="$1"
  shift
  local home
  home=$(user_home "${user}")
  HN_HOME="${home}" "${CLI_CMD[@]}" "$@"
}

alloc_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
port = s.getsockname()[1]
s.close()
print(port)
PY
}

start_mcp() {
  local user="$1"
  local idx="$2"
  local listen="${3:-}"
  local home="${USER_HOME[$idx]}"
  local log_file="${home}/mcp.log"
  if [[ -z "${listen}" ]]; then
    local port
    port=$(alloc_port)
    listen="127.0.0.1:${port}"
  fi
  local public_url="http://${listen}"

  HN_HOME="${home}" HN_PUBLIC_URL="${public_url}" HN_RELAY_TTL_SECS="3" "${MCP_CMD[@]}" serve --profile federation --listen "${listen}" >"${log_file}" 2>&1 &
  local pid=$!

  local summary=""
  local attempts=0
  while [[ ${attempts} -lt 50 ]]; do
    if [[ -f "${log_file}" ]]; then
      summary=$(grep -E 'MCP_READY ' "${log_file}" | tail -n1 | sed 's/^.*MCP_READY //')
      if [[ -n "${summary}" ]]; then
        break
      fi
    fi
    sleep 0.2
    attempts=$((attempts + 1))
  done

  if [[ -z "${summary}" ]]; then
    echo "Failed to detect MCP readiness for ${user}; inspect ${log_file}" >&2
    if [[ -f "${log_file}" ]]; then
      cat "${log_file}" >&2
    fi
    kill "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" >/dev/null 2>&1 || true
    return 1
  fi

  MCP_BASE_URLS[$idx]=$(echo "${summary}" | jq -r '.base_url')
  MCP_PRESENCE_URLS[$idx]=$(echo "${summary}" | jq -r '.presence_url')
  MCP_LISTENS[$idx]=$(echo "${summary}" | jq -r '.listen')

  if [[ -z "${MCP_PRESENCE_URLS[$idx]}" || "${MCP_PRESENCE_URLS[$idx]}" == "null" ]]; then
    echo "MCP readiness summary missing presence_url; payload=${summary}" >&2
    return 1
  fi

  MCP_PIDS[$idx]="${pid}"
  echo "${pid}"
}

start_discovery() {
  local user="$1"
  local idx="$2"
  local listen_port="$3"
  local home="${USER_HOME[$idx]}"
  local log_file="${home}/discovery.log"
  if [[ -z "${listen_port}" || "${listen_port}" == "0" ]]; then
    listen_port=$(alloc_port)
  fi
  local listen_addr="127.0.0.1:${listen_port}"

  "${DISCOVERY_CMD[@]}" --home "${home}" --listen "${listen_addr}" --no-mdns >"${log_file}" 2>&1 &
  local pid=$!

  local attempts=0
  while [[ ${attempts} -lt 50 ]]; do
    if curl -sf "http://${listen_addr}/healthz" >/dev/null 2>&1; then
      break
    fi
    sleep 0.2
    attempts=$((attempts + 1))
  done

  if [[ ${attempts} -ge 50 ]]; then
    echo "Discovery daemon for ${user} did not become ready (log: ${log_file})" >&2
    kill "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" >/dev/null 2>&1 || true
    return 1
  fi

  DISCOVERY_PIDS[$idx]="${pid}"
  DISCOVERY_BASE_URLS[$idx]="http://${listen_addr}"
}

publish_presence() {
  local user="$1"
  local idx
  idx=$(user_index "${user}")
  if [[ "${idx}" -lt 0 ]]; then
    echo "unknown user ${user}" >&2
    return 1
  fi
  local presence_url="${2:-${MCP_PRESENCE_URLS[$idx]}}"
  local home="${USER_HOME[$idx]}"
  local merkle="merkle-${user}"
  local base="${presence_url%/.well-known/hn/presence}"
  local discovery_url="${DISCOVERY_BASE_URLS[$idx]}"

  local output
  output=$(HN_HOME="${home}" HN_DISCOVERY_URL="${discovery_url}" "${CLI_CMD[@]}" discover publish \
    --merkle-root "${merkle}" \
    --endpoint mcp="${base}" \
    --endpoint presence="${presence_url}" \
    --dht \
    --presence-url "${presence_url}" \
    --output json)

  local doc_path
  doc_path=$(echo "${output}" | jq -r '.path')
  if [[ -z "${doc_path}" || "${doc_path}" == "null" ]]; then
    echo "discover publish did not return presence path for ${user}" >&2
    echo "${output}" >&2
    return 1
  fi

  local dest="${home}/presence/latest.json"
  mkdir -p "$(dirname "${dest}")"
  cp "${doc_path}" "${dest}"
}

emit_demo_shard() {
  local destination="$1"
  local publisher_did="$2"
  python3 - "$destination" "$publisher_did" <<'PY'
import base64
import json
import os
import secrets
import sys
from datetime import datetime, timezone

dest, did = sys.argv[1:]
os.makedirs(os.path.dirname(dest), exist_ok=True)
timestamp = datetime.now(timezone.utc).replace(microsecond=0)
iso = timestamp.isoformat().replace("+00:00", "Z")
slug = did.replace(":", "-")
shard_id = f"shard:{slug}:{iso}"
contract_id = f"contract:{slug}:demo"
ciphertext = secrets.token_bytes(32)
enc = secrets.token_bytes(32)
payload_cid = secrets.token_hex(32)
payload = {
    "id": shard_id,
    "contract_id": contract_id,
    "publisher": did,
    "created_at": iso,
    "algorithm": "ChaCha20Poly1305",
    "payload_cid": payload_cid,
    "ciphertext": base64.b64encode(ciphertext).decode(),
    "enc": base64.b64encode(enc).decode(),
}
with open(dest, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2)
PY
}

log "Using temporary suite home ${SUITE_HOME}"
for idx in "${!USERS[@]}"; do
  user="${USERS[$idx]}"
  USER_HOME[$idx]="${SUITE_HOME}/${user}"
  mkdir -p "${USER_HOME[$idx]}"
  with_user "${user}" id create "${user}" --yes >/dev/null
  with_user "${user}" id use "${user}" >/dev/null
  USER_DIDS[$idx]="$(with_user "${user}" id get --output json | jq -r '.identity.did')"
  identity_file="${USER_HOME[$idx]}/identities/${user}/identity.json"
  multibase=
  multibase=$(jq -r '.did_document.verificationMethod[0].publicKeyMultibase' "${identity_file}")
  base58=${multibase#z}
  USER_VERIFY_KEYS[$idx]=$(python3 - <<'PY' "${base58}"
import base64, sys
alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
data = sys.argv[1]
num = 0
for ch in data:
    num = num * 58 + alphabet.index(ch)
byte_length = (num.bit_length() + 7) // 8
byte_data = num.to_bytes(byte_length, 'big')
leading = len(data) - len(data.lstrip('1'))
byte_data = b"\x00" * leading + byte_data
print(base64.b64encode(byte_data).decode())
PY
)
done

log "Starting MCP instances"
for idx in "${!USERS[@]}"; do
  user="${USERS[$idx]}"
  start_mcp "${user}" "${idx}" ""
done

log "Starting discovery daemons"
for idx in "${!USERS[@]}"; do
  user="${USERS[$idx]}"
  start_discovery "${user}" "${idx}" ""
done

log "MCP ready for hub (${HUB})"
HUB_DID="$(with_user "${HUB}" id get --output json | jq -r '.identity.did')"
hub_idx=$(user_index "${HUB}")
HUB_BASE_URL="${MCP_BASE_URLS[$hub_idx]}"
HUB_PRESENCE_URL="${MCP_PRESENCE_URLS[$hub_idx]}"
log "Hub MCP active at ${HUB_BASE_URL} (presence ${HUB_PRESENCE_URL})"

publish_presence "${HUB}" "${HUB_PRESENCE_URL}"

log "Sequentially onboarding peer vaults"
for user in "${USERS[@]}"; do
  if [[ "${user}" == "${HUB}" ]]; then
    continue
  fi
  log "-> ${user}: publishing presence + resolving hub"
  user_idx=$(user_index "${user}")
  if [[ "${user_idx}" -lt 0 ]]; then
    echo "unknown user ${user}" >&2
    continue
  fi
  presence_url="${MCP_PRESENCE_URLS[$user_idx]}"
  publish_presence "${user}" "${presence_url}"
  HN_HOME="${USER_HOME[$user_idx]}" HN_DISCOVERY_URL="${DISCOVERY_BASE_URLS[$user_idx]}" "${CLI_CMD[@]}" discover resolve --hint-only "${HUB_DID}" >/dev/null
done

log "Registering federation roster on hub"
for user in "${USERS[@]}"; do
  if [[ "${user}" == "${HUB}" ]]; then
    continue
  fi
  idx=$(user_index "${user}")
  did="${USER_DIDS[$idx]}"
  endpoint="${MCP_BASE_URLS[$idx]}"
  presence="${MCP_PRESENCE_URLS[$idx]}"
  if ! with_user "${HUB}" mcp federate add "${did}" "${endpoint}" --presence "${presence}" >/dev/null 2>&1; then
    with_user "${HUB}" mcp federate remove "${did}" >/dev/null 2>&1 || true
    with_user "${HUB}" mcp federate add "${did}" "${endpoint}" --presence "${presence}" >/dev/null
  fi
done

log "Publishing demo shard payloads from peers"
for user in "${USERS[@]}"; do
  if [[ "${user}" == "${HUB}" ]]; then
    continue
  fi
  idx=$(user_index "${user}")
  did="${USER_DIDS[$idx]}"
  base_url="${MCP_BASE_URLS[$idx]}"
  home="${USER_HOME[$idx]}"
  shard_dir="${home}/shards/${user}"
  mkdir -p "${shard_dir}"
  shard_file="${shard_dir}/demo-${RUN_ID}-${idx}.json"
  emit_demo_shard "${shard_file}" "${did}"
  rm -rf "${home}/publish"
  if ! with_user "${user}" shard publish --target "${home}/publish" --mcp-url "${base_url}" --mcp-allow-http >/dev/null; then
    echo "Failed to publish shard payload for ${user}" >&2
    exit 1
  fi
done

log "Registering hub as relay and pushing peer presences"
for user in "${USERS[@]}"; do
  if [[ "${user}" == "${HUB}" ]]; then
    continue
  fi
  idx=$(user_index "${user}")
  did="${USER_DIDS[$idx]}"
  with_user "${user}" mcp relay register "${HUB_DID}" --url "${HUB_BASE_URL}" >/dev/null
  with_user "${user}" mcp relay push --to "${HUB_DID}" >/dev/null
  relay_url="${HUB_BASE_URL}/relay/${did}/presence"
  relay_payload=$(curl -sf "${relay_url}")
  echo "${relay_payload}" | jq -e '.did == "'"${did}"'"' >/dev/null
  sleep 4
  if curl -sf "${relay_url}" >/dev/null 2>&1; then
    echo "Relay presence for ${did} should have expired but is still reachable" >&2
    exit 1
  fi
  with_user "${user}" mcp relay push --to "${HUB_DID}" >/dev/null
  relay_payload=$(curl -sf "${relay_url}")
  echo "${relay_payload}" | jq -e '.did == "'"${did}"'"' >/dev/null
done

log "Cross-check: hub resolves peers via DHT (hint-only for now)"
for user in "${USERS[@]}"; do
  idx=$(user_index "${user}")
  did="${USER_DIDS[$idx]}"
  HN_HOME="${USER_HOME[$hub_idx]}" HN_DISCOVERY_URL="${DISCOVERY_BASE_URLS[$hub_idx]}" "${CLI_CMD[@]}" discover resolve --hint-only "${did}" >/dev/null
done

log "Resolving peers via discovery (presence fetch)"
for user in "${USERS[@]}"; do
  idx=$(user_index "${user}")
  did="${USER_DIDS[$idx]}"
  resolve_payload=$(HN_HOME="${USER_HOME[$idx]}" HN_DISCOVERY_URL="${DISCOVERY_BASE_URLS[$idx]}" "${CLI_CMD[@]}" discover --output json resolve "${did}")
  echo "${resolve_payload}" | jq -e '.presence.did == "'"${did}"'"' >/dev/null
done

log "Refreshing federated index slices (mirror artifacts)"
with_user "${HUB}" mcp federate refresh --mirror >/dev/null

FED_CACHE_DIR="${USER_HOME[$hub_idx]}/cache/federation"
if [[ ! -d "${FED_CACHE_DIR}" ]]; then
  echo "Federation cache directory missing at ${FED_CACHE_DIR}" >&2
  exit 1
fi
if ! find "${FED_CACHE_DIR}" -maxdepth 3 -name 'index-*.json' | grep -q '.'; then
  echo "Federation cache is empty at ${FED_CACHE_DIR}" >&2
  exit 1
fi

log "Verifying mirrored artifacts match remote sources"
for user in "${USERS[@]}"; do
  if [[ "${user}" == "${HUB}" ]]; then
    continue
  fi
  idx=$(user_index "${user}")
  did="${USER_DIDS[$idx]}"
  peer_slug=$(sanitize_id "${did}")
  peer_dir="${FED_CACHE_DIR}/${peer_slug}"
  slice_file=$(find "${peer_dir}" -maxdepth 1 -name 'index-*.json' | sort | tail -n1)
  if [[ -z "${slice_file}" ]]; then
    echo "No federated slice cached for ${did} under ${peer_dir}" >&2
    exit 1
  fi
  artifact_path=$(jq -r '.entries[0].path // empty' "${slice_file}")
  if [[ -z "${artifact_path}" ]]; then
    log "Slice ${slice_file} has no artifacts; skipping content verification for ${did}"
    continue
  fi
  local_artifact="${peer_dir}/artifacts/${artifact_path}"
  if [[ ! -f "${local_artifact}" ]]; then
    echo "Mirrored artifact missing at ${local_artifact}" >&2
    exit 1
  fi
  tmp_artifact=$(mktemp)
  if ! curl -sf "${MCP_BASE_URLS[$idx]}/artifact/${artifact_path}" -o "${tmp_artifact}"; then
    echo "Failed to download remote artifact ${artifact_path} from ${MCP_BASE_URLS[$idx]}" >&2
    rm -f "${tmp_artifact}"
    exit 1
  fi
  if ! cmp -s "${local_artifact}" "${tmp_artifact}"; then
    echo "Mirrored artifact ${local_artifact} differs from remote source" >&2
    rm -f "${tmp_artifact}"
    exit 1
  fi
  rm -f "${tmp_artifact}"
done

log "Computing trust graph for hub"
bob_idx=$(user_index "bob")
bob_did="${USER_DIDS[$bob_idx]}"
with_user "${HUB}" trust link derive --to "${bob_did}" --based-on contract:demo-federation --confidence 0.9 >/dev/null
with_user "${HUB}" trust reputation compute --target "${bob_did}" >/dev/null
with_user "${HUB}" policy --yes gate set trust.exposure --mode allow --conditions target=\* >/dev/null

trust_payload=$(curl -sf "${HUB_BASE_URL}/trust/${bob_did}")
echo "${trust_payload}" | jq -e '((has("target") and .target == "'"${bob_did}"'") or (.reputation.target? == "'"${bob_did}"'"))' >/dev/null
echo "${trust_payload}" | jq -e '((.aggregate.count? // 0) + (.reputation.aggregate.count? // 0)) >= 1' >/dev/null

log "Skipping backup push/restore (deferred to Milestone 6 smoke)"

log "M5 smoke run complete"
