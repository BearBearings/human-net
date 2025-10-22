# event@1 — Contract State Transition Event

`event@1` captures a signed transition within the `contract@1` finite state
machine. Each event is immutable: signatures cover the canonical payload so a
replay can verify who drove a transition and when it occurred.

## Schema

```json
{
  "id": "event:contract-alias:seq:timestamp",
  "contract_id": "contract:…",
  "sequence": 2,
  "state": "FULFILLED",
  "actor": "did:hn:…",
  "proof_id": "proof:mock-entra-1234",
  "timestamp": "2025-10-22T15:53:35Z",
  "reason": "offer validity window elapsed",
  "metadata": {"shard_id": "shard:…", "payload_cid": "…"},
  "canonical_hash": "b94d27b9934d3e08a52e52d7da7dabfade",
  "signature": "MEQCIG…"
}
```

### Field Notes

| Field | Description |
| ----- | ----------- |
| `id` | Deterministic identifier (`event:<sanitized contract id>:<sequence>:<timestamp slug>`). |
| `contract_id` | Identifier of the owning contract. |
| `sequence` | Monotonic counter per contract (starts at `1`). |
| `state` | Target state after the transition (`ACCEPTED`, `FULFILLED`, `REVOKED`, `EXPIRED`). |
| `actor` | DID of the participant that emitted the event. |
| `proof_id` | Verification proof associated with the actor. |
| `timestamp` | RFC3339 emission time (UTC). |
| `reason` | Optional human-readable reason (revocations / expiries). |
| `metadata` | Optional machine data (shard identifiers, payload hashes, etc.). |
| `canonical_hash` | BLAKE3 hash of the canonical JCS payload. |
| `signature` | Ed25519 signature over the JCS payload using the actor’s signing key. |

### Canonical Payload

Canonicalization uses JSON Canonicalization Scheme (JCS). The signed view
includes:

```json
{
  "contract_id": "…",
  "sequence": 2,
  "state": "FULFILLED",
  "actor": "did:hn:…",
  "proof_id": "proof:…",
  "timestamp": "2025-10-22T15:53:35Z",
  "reason": "…",
  "metadata": {…}
}
```

Consumers recompute the canonical payload, verify the signature with the
emitter’s DID document, and compare the resulting BLAKE3 digest with
`canonical_hash`.

### Storage

Events live under `~/.human-net/events/<alias>/<event-id>.json` and every
`contract@1.state_history` entry references the corresponding `event@1` by id.

### Replay Guarantees

* Every event is signed by the actor that initiated the transition.
* Sequence numbers detect missing events or race conditions.
* `metadata` is application-defined but must keep personally identifiable
  information out of the shared payload.
