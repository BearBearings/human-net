# reputation@1 — Aggregated Trust View

## Purpose

`reputation@1` aggregates a vault’s view of another peer (or community) based on
verified `trust_link@1` records. It enables lightweight discovery and policy
decisions (e.g., “only accept offers from peers with avg_confidence ≥ 0.8 and N ≥ 3”).

Unlike global scores, reputation documents are scoped to the observer and contain
only derived statistics plus references to the underlying links.

## Fields

| Field        | Type      | Required | Description                                                         |
|--------------|-----------|----------|---------------------------------------------------------------------|
| `id`         | `string`  | Yes      | Canonical identifier (`reputation:<observer_slug>:<target_slug>:<timestamp>`) |
| `observer`   | `string`  | Yes      | DID calculating the aggregate                                       |
| `target`     | `string`  | Yes      | DID (or community tag) being evaluated                              |
| `links`      | `array`   | Yes      | Referenced `trust_link@1` IDs included in the aggregate              |
| `aggregate`  | `object`  | Yes      | Summary statistics (see below)                                      |
| `policy_ref` | `string`  | No       | Policy or filter used during aggregation                            |
| `generated_at` | `RFC3339` | Yes    | Timestamp of computation                                            |
| `signature`  | `base64`  | Yes      | Ed25519 signature over canonical payload                            |

### Aggregate schema

```json
{
  "avg_confidence": 0.9,
  "count": 5,
  "min_confidence": 0.8,
  "max_confidence": 0.97,
  "stddev": 0.04
}
```

Fields are optional except `avg_confidence` and `count`. Additional metrics may be added
as needed (median, percentile buckets, decay weights, etc.).

## Canonical form & signing

Canonical payload (RFC 8785):

```json
{
  "aggregate": {
    "avg_confidence": 0.9,
    "count": 2
  },
  "generated_at": "2025-10-25T08:05:00Z",
  "id": "reputation:alice:bob:2025-10-25T08:05:00Z",
  "links": [
    "trust_link:alice:bob:2025-10-01T09:00:00Z",
    "trust_link:alice:bob:2025-10-25T08:01:00Z"
  ],
  "observer": "did:hn:alice",
  "target": "did:hn:bob"
}
```

Signature = `Base64(Ed25519Sign(private_key, canonical_json))`.

## Storage & exposure

Aggregates live under:

```
$HN_HOME/trust/reputation/<alias>/<id>.json
```

MCP nodes MAY expose `GET /trust/<target>` returning the signed aggregate for friends,
subject to policy gating (`policy.trust.exposure`). Aggregates SHOULD omit raw evidence
and only reference link IDs to avoid leaking sensitive detail.

## Recalculation

- A scheduled job recomputes reputation when underlying links change or expire.
- Observers can maintain multiple views (e.g., per domain) by encoding the context
  inside `policy_ref` or the `target` slug (`did:hn:bob#delivery`).

## Policy integration

Policies consume reputation via new clauses, e.g.:

```json
{
  "when": "offer.inbound",
  "require": {
    "reputation.avg_confidence": { "gte": 0.8 },
    "reputation.count": { "gte": 3 }
  }
}
```

The policy engine loads the latest local aggregate and evaluates the criteria.
If no aggregate exists, the requirement fails or defaults per policy configuration.

