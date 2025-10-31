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
| `relays`         | `array`       | No       | List of relay descriptors (`relay@1`, see below)                            |
| `expires_at`     | `RFC3339`     | Yes      | Expiry timestamp for this presence                                          |
| `issued_at`      | `RFC3339`     | Yes      | Timestamp presence was generated                                            |
| `ttl_seconds`    | `integer`     | No       | Recommended cache TTL                                                       |
| `signature`      | `base64`      | Yes      | Ed25519 signature over canonical payload                                    |

### Relay descriptor (`relay@1`)

Each entry inside `relays` describes a trusted MCP host that can proxy requests for this identity.

```json
{
  "host": "did:hn:relay123",
  "url": "https://relay.hn.net",
  "expires_at": "2025-01-01T12:10:00Z"
}
```

* `host` — DID of the relay MCP that will accept proxy requests.
* `url` — Base URL clients should use when contacting the relay.
* `expires_at` — Optional expiry timestamp for this delegation; omit for implicit TTL inherited from the presence document. Relay nodes may still apply local retention policies (`relay_ttl_seconds`) and will drop cached presence once the earliest expiry is reached.

## Canonical form & signing

Canonical payload serialises as JSON (RFC 8785):

```json
{
  "did": "did:hn:alice",
  "endpoints": {
    "mcp": "https://alice.example.net:7733",
    "presence": "https://alice.example.net/.well-known/hn/presence"
  },
  "relays": [
    {
      "host": "did:hn:relay123",
      "url": "https://relay.hn.net"
    }
  ],
  "expires_at": "2025-01-01T12:00:00Z",
  "issued_at": "2025-01-01T11:50:00Z",
  "merkle_root": "sha256:…",
  "ttl_seconds": 600
}
```

Signature = `Base64(Ed25519Sign(private_key, canonical_json))`.

Storage layout: `$HN_HOME/presence/<alias>/<timestamp>.json`.
