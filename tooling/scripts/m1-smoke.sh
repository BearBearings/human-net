#!/usr/bin/env bash
set -euo pipefail

alice_home=$(mktemp -d)
bob_home=$(mktemp -d)

cleanup() {
  HN_HOME=$alice_home hn service stop discovery --purge-node >/dev/null 2>&1 || true
  HN_HOME=$bob_home   hn service stop discovery --purge-node >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_ready() {
  local home=$1
  local attempts=30
  for ((i=0; i<attempts; i++)); do
    if HN_HOME=$home hn service status -o json \
        | jq -e '.running == true' >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  echo "Discovery did not become ready for $home" >&2
  return 1
}

echo "## Alice bootstrap"
HN_HOME=$alice_home hn id create alice \
  --capability unit:offer \
  --endpoint discovery=hn+mdns://alice.local \
  --yes -o json
HN_HOME=$alice_home hn id use alice -o json
HN_HOME=$alice_home hn service start discovery -o json
wait_ready "$alice_home"

echo "## Bob bootstrap"
HN_HOME=$bob_home hn id create bob \
  --capability unit:offer \
  --endpoint discovery=hn+mdns://bob.local \
  --yes -o json
HN_HOME=$bob_home hn id use bob -o json
HN_HOME=$bob_home hn service start discovery -o json
wait_ready "$bob_home"

echo "## Alice sees:"
HN_HOME=$alice_home hn peer list -o json
echo "## Bob sees:"
HN_HOME=$bob_home hn peer list -o json