# receipt@1 — Shard Replay Receipt

`receipt@1` documents prove that a subscriber successfully imported and
decrypted a shard produced under a `contract@1`. Receipts are append-only,
signed microdocs stored under `~/.human-net/receipts/<alias>/` and referenced
by auditors via `hn shard verify`.

## Data Model

```json
{
  "id": "receipt:did-hn-h3dwn7h8prb1uhdyqojr2b6usvmlzwp18fjp1ttgevi:2025-10-22T17:12:25.015692Z",
  "shard_id": "shard:did-hn-6tpoy2reisksc3tqbmypswl43vaj7vaqqym7yhqmajvh:contract-did-hn-6tpoy2…:2025-10-22T17:12:24.814928Z",
  "contract_id": "contract:did-hn-6tpoy2reisksc3tqbmypswl43vaj7vaqqym7yhqmajvh:bob:doc-finance-folder-1:2025-10-22T17:12:24.798336Z",
  "payload_cid": "eee5d2449896d5709fc99002895fe6b30724d88ac8be3361529a5f0cf4d9e3a7",
  "publisher": "did:hn:6tpoy2reisksc3tqbmypswl43vaj7vaqqym7yhqmajvh",
  "index_id": "index:did-hn-6tpoy2reisksc3tqbmypswl43vaj7vaqqym7yhqmajvh:2025-10-22T17:12:24.814928Z",
  "merkle_root": "d5100f78d0cfdf7c648021bf0b3b7c7b2d3e8f4fbb4c6579de79a80e5a9654ab",
  "subscriber": "did:hn:h3dwn7h8prb1uhdyqojr2b6usvmlzwp18fjp1ttgevi",
  "subscriber_public_key": "mvCndpN/DQ50dEnXfeJmhI+0xy1HnX/0xqfRbiH3n1k=",
  "timestamp": "2025-10-22T17:12:25.015692Z",
  "canonical_hash": "f8e0e8fa3ef6a7cdbf5c92eb11938a7d8f10b7f67666d563a4e3d229e86d2cb3",
  "signature": "MEYCIQC+2x6d0n7bYp8s1jGObkGmJVA96Bq+Y1wZ2YNGCpXrVgIhAKNeGyhF5nJfQ0eX4jw2QLphO6ZL8bXlE82TQXE7ui1k"
}
```

### Field Notes

| Field | Description |
|-------|-------------|
| `id` | Deterministic identifier (`receipt:<subscriber slug>:<timestamp>`). |
| `shard_id` | Source shard being acknowledged. |
| `contract_id` | Contract under which the shard was produced. |
| `payload_cid` | Ciphertext digest echoed for integrity checks. |
| `publisher` | DID of the shard publisher (issuer). |
| `index_id` | Signed index that introduced the shard. |
| `merkle_root` | Merkle root from the index (proves inclusion). |
| `subscriber` | DID of the recipient emitting the receipt. |
| `subscriber_public_key` | Base64 Ed25519 public key used to verify the signature. |
| `timestamp` | UTC timestamp when the receipt was generated. |
| `canonical_hash` | BLAKE3 hash of the canonical payload (before signing). |
| `signature` | subscriber's Ed25519 signature over the canonical payload. |

Receipts allow auditors (or the counterparty) to prove that a shard was
successfully replayed and that the replay referenced a specific, signed index.
