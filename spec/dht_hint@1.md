# dht_hint@1 — Distributed Presence Advertisement

## Purpose

`dht_hint@1` is the compact record announced into the Human.Net distributed hash table
so any peer can discover a vault’s public MCP endpoint without contacting a central
directory. The record carries a signed summary of the latest `presence@2` document
and the metadata required to verify freshness.

## Fields

| Field          | Type      | Required | Description                                                                 |
| -------------- | --------- | -------- | --------------------------------------------------------------------------- |
| `id`           | `string`  | Yes      | Canonical identifier (`dht_hint:<did_hash>:<timestamp>`)                    |
| `did`          | `string`  | Yes      | Vault DID being advertised                                                  |
| `presence_cid` | `string`  | Yes      | BLAKE3 digest of the canonical `presence@2` payload                         |
| `presence_url` | `string`  | Yes      | HTTPS URL where the full `presence@2` can be fetched                        |
| `expires_at`   | `RFC3339` | Yes      | Time after which the hint should be discarded                               |
| `relay`        | `string`  | No       | Optional relay DID that can proxy presence/requests                         |
| `signature`    | `base64`  | Yes      | Ed25519 signature over the canonical payload                                |

Additional fields MAY be added in future revisions; consumers MUST ignore unknown keys.

## Canonical form & signing

Canonical payload (RFC 8785 JSON):

```json
{
  "did": "did:hn:bob",
  "expires_at": "2025-02-01T12:00:00Z",
  "id": "dht_hint:q7xv4j…:2025-01-25T09:55:00Z",
  "presence_cid": "e5bd9bd1f4e2…",
  "presence_url": "https://bob.hn.net/.well-known/hn/presence"
}
```

Signature = `Base64(Ed25519Sign(private_key, canonical_json))`.

`did_hash` used in the identifier and DHT key is computed as:

```
did_hash = blake3("did:hn:bob")[:32]  // 32-byte prefix, hex encoded
```

## Storage & dissemination

- MCP nodes inject hints into a libp2p Kademlia DHT with key `did_hash`.
- Each DHT record contains the serialized `dht_hint@1` JSON (optionally compressed).
- Local cache stored under `$HN_HOME/discovery/dht/<did_hash>.json`.

## Verification flow

1. Resolver fetches `dht_hint@1` from DHT.
2. Validate signature with the DID’s `key-ed25519`.
3. Check `expires_at` is in the future.
4. Fetch `presence@2` from `presence_url`, validate its signature, recompute canonical hash, and ensure it matches `presence_cid`.
5. (Optional) Contact relay if direct MCP reachability fails.

## TTL & refresh

- Producers refresh hints whenever `presence@2` changes or reaches 75% of its TTL.
- DHT nodes should republish hints periodically to maintain availability.

