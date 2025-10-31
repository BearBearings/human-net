# index@2 — Federated Shard Index Slice

## Purpose

`index@2` packages a signed, Merkle-verifiable slice of a publisher’s shard/catalog state for federation between MCP nodes. It links every slice back to the latest `presence@2` advertisement so operators can prove the data was produced by the advertised node before caching or relaying it.

## Fields

| Field                | Type        | Required | Description                                                                                           |
| -------------------- | ----------- | -------- | ----------------------------------------------------------------------------------------------------- |
| `id`                 | `string`    | Yes      | Canonical identifier (`index:<publisher did>:<timestamp>:<cursor>`)                                   |
| `publisher`          | `string`    | Yes      | DID of the publishing vault                                                                           |
| `publisher_public_key` | `base64`  | Yes      | Ed25519 verifying key for the publisher (base64, 32 bytes)                                            |
| `generated_at`       | `RFC3339`   | Yes      | Timestamp when this slice was generated                                                               |
| `source`             | `string`    | Yes      | HTTPS URL of the MCP endpoint that produced this slice                                                |
| `presence_digest`    | `string`    | Yes      | BLAKE3 hex digest of the canonical `presence@2` payload that authorised this publication              |
| `cursor`             | `string`    | Yes      | Stable pagination cursor for incremental federation (opaque string)                                   |
| `next_cursor`        | `string`    | No       | Cursor to request the following slice; omission signals “end of stream”                               |
| `entries`            | `array`     | Yes      | List of artefacts included in this slice (see entry structure below)                                  |
| `merkle_root`        | `string`    | Yes      | Merkle root over the ordered artefact digests within this slice                                       |
| `canonical_hash`     | `string`    | Yes      | BLAKE3 hex digest of the canonical signing payload                                                    |
| `signature`          | `base64`    | Yes      | Base64-encoded Ed25519 signature over the canonical payload                                           |

### Entry structure

```json
{
  "type": "shard|contract|event|presence|doc",
  "id": "shard:did-hn:alice:...",
  "path": "shards/shard_alice_2025-10-22T17_12_24.json",
  "digest": "d5100f78d0cfdf7c648021bf0b3b7c7b2d3e8f4fbb4c6579de79a80e5a9654ab",
  "metadata": {
    "contract_id": "contract:did-hn:alice-bike-2025",
    "state": "FULFILLED"
  }
}
```

* `type` — Logical artefact category.
* `id` — Canonical artefact identifier.
* `path` — Relative path expected under the publisher’s MCP `/artifact/*` endpoint.
* `digest` — BLAKE3 hex digest of the artefact bytes (used to recompute the slice Merkle root).
* `metadata` — Optional summary fields (purely informational; excluded from Merkle computation per entry).

## Canonical form & signing

`index@2` uses RFC 8785 (JCS) canonical JSON prior to signing. The canonical payload includes only the fields that participate in verification:

```json
{
  "cursor": "2025-10-22T17:12:24.814928Z#0001",
  "entries": [
    {
      "digest": "eee5d2449896d5709fc99002895fe6b30724d88ac8be3361529a5f0cf4d9e3a7",
      "id": "shard:did-hn:alice:2025-10-22T17:12:24Z",
      "metadata": {
        "contract_id": "contract:did-hn:alice-bike-2025"
      },
      "path": "shards/shard_alice_2025-10-22T17_12_24.json",
      "type": "shard"
    }
  ],
  "generated_at": "2025-10-22T17:12:24.814928Z",
  "merkle_root": "d5100f78d0cfdf7c648021bf0b3b7c7b2d3e8f4fbb4c6579de79a80e5a9654ab",
  "presence_digest": "a7904abbbef7c9e3d0a0c4d6f9f45a1f1f0ed5c4b8b621b5a1b899f5c8bd1234",
  "publisher": "did:hn:alice",
  "publisher_public_key": "N1Xo3sUu5h7i6gPfVjPW3k7YQtgr5Ze5j4O0C8GieQ4=",
  "source": "https://alice.example.net:7733",
  "next_cursor": "2025-10-22T17:13:10.002Z#0002"
}
```

Signature = `Base64(Ed25519Sign(private_key, canonical_json))`.

`canonical_hash` = `BLAKE3(canonical_json)` stored as lowercase hex. `id` is not part of the signed payload; consumers recompute it and ensure it matches the declared `publisher` + `cursor`.

## Storage & transport

Publishers expose slices at `GET /federate/index?cursor=<cursor>` and optionally push them via federation relays. Consumers persist raw slices under:

```
$HN_HOME/cache/federation/<publisher did>/index-<cursor>.json
```

Pruning is governed by policy (default: keep last 5 slices + any required for active proofs).

## Verification steps

1. Recompute the canonical payload using RFC 8785 rules and validate `canonical_hash`.
2. Verify the Ed25519 signature with `publisher_public_key`.
3. Ensure `presence_digest` matches the cached canonical hash of the current `presence@2` for `publisher`.
4. Recompute the Merkle root from entry digests (`compute_merkle_root(entries[].digest)`).
5. Confirm each artefact’s digest when fetching via `/artifact/*` prior to caching.
