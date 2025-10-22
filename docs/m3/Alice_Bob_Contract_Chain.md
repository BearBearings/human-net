# M3 Demo Script — Alice ↔ Bob Contract Chain

> **M3 (Trust & Exchange)** — Human.Net enables verifiable, encrypted peer-to-peer data exchange. L2-verified identities create offers and sign contracts that grant capabilities over docs. Payloads are published as signed shards with Merkle-verified indices, and recipients decrypt with HPKE. Everything is offline-verifiable and audit-replayable.

This walkthrough sketches the end-to-end flow required for the M3 milestone.
It assumes the verified identity foundation (S1) is in place and the forthcoming
offer/contract tooling (S2/S3) implements the commands referenced below.

## Preconditions

1. Alice and Bob each have verified identities with fresh proofs:
   ```bash
   HN_HOME=~/.human-net-alice hn id verify --provider mock-entra
   HN_HOME=~/.human-net-bob   hn id verify --provider mock-didkit
   ```
2. Alice can generate an offer via:
   ```bash
   hn contract offer create \
     --audience did:hn:bob... \
     --doc doc:finance-folder@1 \
     --capability read \
     --policy-ref policy:doc.read \
     --emit /tmp/offer.json
   ```
   The command stores a copy under `~/.human-net/offers/<alice>/` and emits a shareable
   JSON artefact to `/tmp/offer.json` (or any chosen path).

## Flow

1. **Offer publication** — Alice shares the emitted offer file with Bob (LAN
   shard or secure file transfer).
2. **Acceptance** — Bob inspects the terms and accepts:
   ```bash
   HN_HOME=~/.human-net-bob hn contract offer show --id <offer-id>   # optional audit
   HN_HOME=~/.human-net-bob hn contract accept --offer /tmp/offer.json --emit /tmp/contract.json
   ```
   The CLI checks:
   - offer validity window
   - policy gates mapped from `policy_refs`
   - proof freshness via `proof_id`
3. **Reservation broadcast** — Bob emits a signed `event@1` while accepting the
   offer. The CLI records the event under
   `~/.human-net/events/<alias>/` and appends the entry to the contract’s
   `state_history` with signature + canonical hash.
4. **Verification (optional)** — Either party confirms digests & proofs:
   ```bash
   hn contract verify --offer /tmp/offer.json --contract /tmp/contract.json
   ```
5. **Fulfilment** — Alice packages the requested `doc@1` into a shard and wraps
   the symmetric key with Bob's DID key:
   ```bash
   HN_HOME=~/.human-net-alice hn contract fulfill \
     --contract-id contract:alice:bob:finance-folder:2025-01-10 \
     --payload samples/docs/folder.json \
     --emit-shard /tmp/shard.json
   ```
6. **Shard transfer** — Alice publishes the fulfilment bundle:
   ```bash
   hn shard publish --target ~/drops/alice-to-bob
   ```
   Bob runs the subscriber (one-off or `--watch` loop):
   ```bash
   HN_HOME=~/.human-net-bob hn shard subscribe \
     --source ~/drops/alice-to-bob \
     --watch --iterations 12 --interval-seconds 5
   ```
   The subscriber copies new events/contracts, imports shards, decrypts the
   payload with Bob’s HPKE secret, and stores the resulting `doc@1` via the
   local importer (policy gating enforced). Imported artifacts are tracked under
   `~/.human-net/sync/<alias>/` to avoid reprocessing.
   ```bash
   # Optional: verify the bundle + receipts
   HN_HOME=~/.human-net-bob hn shard verify --source ~/drops/alice-to-bob --alias bob

   # Standalone decrypt without mutating local storage
   HN_HOME=~/.human-net-bob hn shard fetch \
     --from ~/drops/alice-to-bob/shards/<shard-file>.json \
     --decrypt-out /tmp/decrypted.json --no-import
   ```
7. **Completion + reputation** — Alice’s fulfilment emits a signed
   `event@1` (`FULFILLED`). Bob’s subscriber imports the event, updates the
   contract state, and materialises the decrypted folder. Both parties can now
   attach `rep@1` entries or, if needed, revoke/expire the contract using the
   new CLI helpers:
   ```bash
   # Manual revocation (reason recorded in event metadata)
   hn contract revoke --contract-id <id> --reason "policy failure"

   # Sweep expired reservations (dry-run supported)
   hn contract expire sweep --dry-run

   # Plan/apply retention (emits archive@1 records)
   hn gc plan --contracts
   hn gc apply --contracts
   ```

## Artefacts Captured

- `proof@1` entries for each participant (identity layer)
- `offer@1` document shared from Alice
- `contract@1` document with event log
- Shard bundle containing the encrypted payload
- Optional `rep@1` records feeding future selection logic

Tracking these artefacts end-to-end is the acceptance bar for M3: recreating the
entire chain should be possible from the recorded documents without external
state. S3/S4 will add shard transport, fulfilment, and reputation on top of this
foundation.
