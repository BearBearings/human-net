# trust_link@1 — Verifiable Trust Relationship

## Purpose

`trust_link@1` records a signed assertion from one vault (`from`) about its collaborative
experience with another vault (`to`). Each link references concrete evidence
(contracts, payments, shard exchanges, receipts) so third parties can replay the
history before weighting the relationship.

## Fields

| Field        | Type        | Required | Description                                                        |
|--------------|-------------|----------|--------------------------------------------------------------------|
| `id`         | `string`    | Yes      | Canonical identifier (`trust_link:<from_slug>:<to_slug>:<timestamp>`) |
| `from`       | `string`    | Yes      | DID of the observer issuing the link                               |
| `to`         | `string`    | Yes      | DID of the counterparty being evaluated                            |
| `based_on`   | `array`     | Yes      | List of evidence IDs (`contract@1`, `payment@1`, `receipt@1`, etc.)|
| `confidence` | `number`    | Yes      | Normalized confidence score in `[0.0, 1.0]`                        |
| `context`    | `string`    | No       | Optional domain (e.g., `"micropay"`, `"repair-service"`)           |
| `last_seen`  | `RFC3339`   | Yes      | Timestamp of most recent supporting evidence                       |
| `ttl_seconds`| `integer`   | No       | Suggested time-to-live for consumers                               |
| `signature`  | `base64`    | Yes      | Ed25519 signature over the canonical payload                       |

## Canonical form & signing

The canonical payload (RFC 8785 JSON):

```json
{
  "based_on": [
    "contract:did:hn:alice-bike-2025",
    "payment:did:hn:alice:rep-0049"
  ],
  "confidence": 0.93,
  "context": "micropay",
  "from": "did:hn:alice",
  "id": "trust_link:alice:bob:2025-10-25T08:01:00Z",
  "last_seen": "2025-10-25T08:01:00Z",
  "to": "did:hn:bob"
}
```

Signature = `Base64(Ed25519Sign(private_key, canonical_json))`.

`confidence` is producer-defined but MUST remain deterministic given the same evidence set.
Implementations SHOULD reject values outside `[0.0, 1.0]`.

## Storage & indexing

Links are stored locally under:

```
$HN_HOME/trust/links/<alias>/<id>.json
```

Tools (CLI / MCP) index links by `to` peer and supporting evidence so they can be recomputed.
Consumers SHOULD recompute the canonical payload to verify `signature`.

## Evidence references

Pointers in `based_on` must be resolvable within the vault (or via shared history):

- `contract:<id>` — contract documents (`contracts/<alias>/`).
- `payment:<id>` — `payment@1` documents.
- `receipt:<id>` — `receipt@1`.
- `shard:<id>` — `shard@1` digests.

Reference types are open-set but must be registered in `policy.trust.allowed_types`.

## Expiry & refresh

Links inherit credibility from fresh evidence:

- Consumers ignore links where `now - last_seen > policy.trust.max_age`.
- Producers refresh by recomputing `confidence` and updating `last_seen` when new evidence arrives.

