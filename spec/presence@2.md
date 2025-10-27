# presence@2 — WAN Presence Advertisement

## Purpose

`presence@2` advertises a vault’s reachable endpoints (MCP, discovery hints), current index Merkle root, and freshness metadata so friends can discover and verify remote state before exchanging data.

## Fields

| Field            | Type          | Required | Description                                                                 |
| ---------------- | ------------- | -------- | --------------------------------------------------------------------------- |
| `id`             | `string`      | Yes      | Canonical identifier (`presence:<did>:<timestamp>`)                         |
| `did`            | `string`      | Yes      | Vault DID emitting the presence                                             |
| `endpoints`      | `object`      | Yes      | Map of endpoint name → URL (e.g. `{"mcp":"https://node.example.org:7733"}`) |
| `merkle_root`    | `string`      | Yes      | Latest published index Merkle root (`hn shard publish`)                     |
| `proof`          | `string`      | No       | Optional Merkle proof blob (base64)                                         |
| `expires_at`     | `RFC3339`     | Yes      | Expiry timestamp for this presence                                          |
| `issued_at`      | `RFC3339`     | Yes      | Timestamp presence was generated                                            |
| `ttl_seconds`    | `integer`     | No       | Recommended cache TTL                                                       |
| `signature`      | `base64`      | Yes      | Ed25519 signature over canonical payload                                    |

## Canonical form & signing

Canonical payload serialises as JSON (RFC 8785):

```json
{
  "did": "did:hn:alice",
  "endpoints": {
    "mcp": "https://alice.example.net:7733",
    "presence": "https://alice.example.net/.well-known/hn/presence"
  },
  "expires_at": "2025-01-01T12:00:00Z",
  "issued_at": "2025-01-01T11:50:00Z",
  "merkle_root": "sha256:…",
  "ttl_seconds": 600
}
```

Signature = `Base64(Ed25519Sign(private_key, canonical_json))`.

Storage layout: `$HN_HOME/presence/<alias>/<timestamp>.json`.

