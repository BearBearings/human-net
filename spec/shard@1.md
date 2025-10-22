# shard@1 — Fulfilment Shard Document

A `shard@1` document captures the encrypted payload published when a contract is
fulfilled. It is written under `~/.human-net/shards/<alias>/` and referenced by
`contract@1.encrypted_payload`.

## Data Model

```json
{
  "id": "shard:did-hn:contract-...:2025-10-22T15:53:35Z",
  "contract_id": "contract:did-hn:...",
  "publisher": "did:hn:alice...",
  "created_at": "2025-10-22T15:53:35Z",
  "algorithm": "ChaCha20Poly1305",
  "payload_cid": "05407d...",
  "ciphertext": "b64...",
  "enc": "b64..."
}
```

### Field Notes

| Field | Description |
|-------|-------------|
| `id` | Deterministic identifier (`shard:<publisher slug>:<contract slug>:<timestamp>`). |
| `contract_id` | The contract that produced this shard. |
| `publisher` | DID of the issuer fulfilling the contract. |
| `created_at` | UTC timestamp when the shard was generated. |
| `algorithm` | Payload cipher (`ChaCha20Poly1305` under HPKE). |
| `payload_cid` | BLAKE3 hex digest of the ciphertext (referenced from the contract). |
| `ciphertext` | Base64-encoded HPKE ciphertext of the payload. |
| `enc` | Base64-encoded HPKE encapsulated key used to derive the AEAD context. |

The shard stores the full HPKE ciphertext. The corresponding
`contract@1.encrypted_payload` keeps the same `payload_cid` plus the `enc`
value, allowing counterparties to validate provenance and decrypt.

## Fulfilment Flow

1. Issuer encrypts the payload with HPKE (X25519HkdfSha256 KEM + ChaCha20Poly1305 AEAD),
   using the counterparty's HPKE public key.
2. Ciphertext hash → `payload_cid` (stored on both shard and contract).
3. Shard JSON written to `~/.human-net/shards/<issuer alias>/<id>.json` and
   optionally shared with the counterparty.
4. Contract state transitions to `FULFILLED` with its `encrypted_payload`
   updated to point at the shard (`cid`, `enc`, `ciphertext`).

## Publish / Subscribe and Doc Import

`hn shard publish --target <dir>` collects the latest local `shard@1`,
`event@1`, and `contract@1` files into a shareable directory:

```
<dir>/index.json
<dir>/shards/*.json
<dir>/events/*.json
<dir>/contracts/*.json
```

Peers poll the drop via `hn shard subscribe --source <dir>` which:

1. Copies new events/contracts into `~/.human-net/events|contracts/<alias>/`.
2. Imports unseen shards, decrypts payloads, and stores the resulting
   `doc@1` via the local `DocStore` (policy gating applies).
3. Applies any accompanying `event@1` to the local `contract@1` state history.

Seen entries are tracked under `~/.human-net/sync/<alias>/seen.json` so repeated
polls or `--watch` loops only process deltas.

## Index (`shard_index@1`)

Publish emits a signed index describing every artefact included in the drop.
The publisher's Ed25519 key signs the canonical payload so subscribers can
verify provenance before trusting the files.

```json
{
  "id": "index:did-hn-6tpoy2reisksc3tqbmypswl43vaj7vaqqym7yhqmajvh:2025-10-22T17:12:24.814928Z",
  "publisher": "did:hn:6tpoy2reisksc3tqbmypswl43vaj7vaqqym7yhqmajvh",
  "publisher_public_key": "N1Xo3sUu5h7i6gPfVjPW3k7YQtgr5Ze5j4O0C8GieQ4=",
  "generated_at": "2025-10-22T17:12:24.814928Z",
  "entries": [
    {
      "type": "event",
      "id": "event:contract-…:2:2025-10-22T17:12:24.814928Z",
      "path": "events/event_contract-…_2_2025-10-22T17_12_24.814928Z.json",
      "digest": "529a95…",
      "metadata": {"state": "FULFILLED", "contract_id": "contract:…"}
    },
    {
      "type": "shard",
      "id": "shard:did-hn-6tpoy2…:2025-10-22T17:12:24.814928Z",
      "path": "shards/shard_did-hn-6tpoy2…_2025-10-22T17_12_24.814928Z.json",
      "digest": "eee5d2449896d5709fc99002895fe6b30724d88ac8be3361529a5f0cf4d9e3a7",
      "metadata": {"contract_id": "contract:…", "payload_cid": "eee5d244…"}
    }
  ],
  "merkle_root": "d5100f78d0cfdf7c648021bf0b3b7c7b2d3e8f4fbb4c6579de79a80e5a9654ab",
  "canonical_hash": "84647f…",
  "signature": "MEQCIFjURi…"
}
```

Subscribers recompute entry digests, validate the Merkle root, and verify the
index signature before importing artefacts. The publisher's public key is
included for offline verification.

## Receipt (`receipt@1`)

After decrypting a shard, subscribers emit a signed `receipt@1` acknowledging
successful replay. Receipts reference the source index and share the Merkle
root so auditors can prove inclusion.

```json
{
  "id": "receipt:did-hn-h3dwn7h8prb1uhdyqojr2b6usvmlzwp18fjp1ttgevi:2025-10-22T17:12:25.015692Z",
  "shard_id": "shard:did-hn-6tpoy2…:2025-10-22T17:12:24.814928Z",
  "contract_id": "contract:did-hn-6tpoy2…:2025-10-22T17:12:24.798336Z",
  "payload_cid": "eee5d2449896d5709fc99002895fe6b30724d88ac8be3361529a5f0cf4d9e3a7",
  "publisher": "did:hn:6tpoy2reisksc3tqbmypswl43vaj7vaqqym7yhqmajvh",
  "index_id": "index:did-hn-6tpoy2…:2025-10-22T17:12:24.814928Z",
  "merkle_root": "d5100f78d0cfdf7c648021bf0b3b7c7b2d3e8f4fbb4c6579de79a80e5a9654ab",
  "subscriber": "did:hn:h3dwn7h8prb1uhdyqojr2b6usvmlzwp18fjp1ttgevi",
  "subscriber_public_key": "mvCndpN/DQ50dEnXfeJmhI+0xy1HnX/0xqfRbiH3n1k=",
  "timestamp": "2025-10-22T17:12:25.015692Z",
  "canonical_hash": "f8e0e8…",
  "signature": "MEYCIQC+2…"
}
```

Both index and receipt documents are stored under `~/.human-net/{events,shards,archive}`
and can be verified with `hn shard verify`.
