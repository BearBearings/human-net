#!/usr/bin/env bash
set -euo pipefail

ALICE_HOME=$(mktemp -d "${TMPDIR:-/tmp}/hn-alice-XXXXXX")
BOB_HOME=$(mktemp -d "${TMPDIR:-/tmp}/hn-bob-XXXXXX")

echo "Using ALICE_HOME=$ALICE_HOME"
echo "Using BOB_HOME=$BOB_HOME"

# Alice identity + verification
export HN_HOME="$ALICE_HOME"
hn id create alice --capability unit:offer --capability contract:fulfill --endpoint discovery=hn+mdns://alice.local --yes
hn id use alice
hn id verify --provider mock-entra

# Capture Bob DID for offer audience
export HN_HOME="$BOB_HOME"
hn id create bob --capability contract:accept --endpoint discovery=hn+mdns://bob.local --yes
hn id use bob
hn id verify --provider mock-didkit
BOB_DID=$(hn id get --output json | jq -r '.identity.did')

# Alice issues offer
export HN_HOME="$ALICE_HOME"
hn contract offer create \
  --audience "$BOB_DID" \
  --doc doc:finance-folder@1 \
  --capability read \
  --policy-ref policy:doc.read \
  --emit /tmp/offer.json
hn contract offer list
OFFER_ID=$(jq -r '.id' /tmp/offer.json)

# Bob accepts offer
export HN_HOME="$BOB_HOME"
hn contract accept --offer /tmp/offer.json --emit /tmp/contract.json
CONTRACT_ID=$(jq -r '.id' /tmp/contract.json)
CONTRACT_FILE_NAME="${CONTRACT_ID//[:\/ ]/_}.json"
mkdir -p "$ALICE_HOME/contracts/alice"
cp /tmp/contract.json "$ALICE_HOME/contracts/alice/$CONTRACT_FILE_NAME"

# Alice fulfils contract with sample payload and publishes bundle
export HN_HOME="$ALICE_HOME"
hn contract fulfill \
  --contract-id "$CONTRACT_ID" \
  --payload "$PWD/samples/docs/folder.json" \
  --emit /tmp/contract.json \
  --emit-shard /tmp/shard.json
DROP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/hn-drop-XXXXXX")
hn shard publish --target "$DROP_DIR" --alias alice

# Verification & shard listing
hn contract verify --offer /tmp/offer.json --contract /tmp/contract.json --output json
hn shard list --alias alice --output json

# Bob subscribes to the drop and materialises the doc
export HN_HOME="$BOB_HOME"
hn shard subscribe --source "$DROP_DIR" --output json
hn doc list -o json | jq '.docs[] | select(.doc_type=="finance-folder@1")'

# Verify published index and receipts, plus standalone decrypt
hn shard verify --source "$DROP_DIR" --alias bob --output json
SHARD_FILE=$(ls "$DROP_DIR"/shards/*.json | head -n1)
hn shard fetch --from "$SHARD_FILE" --decrypt-out /tmp/decrypt-smoke.json --no-import --output json

echo "Artifacts written to $ALICE_HOME and $BOB_HOME"
