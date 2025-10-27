# snapshot@1 — View Materialisation Snapshot & Receipt

Materialising a `view@1` definition yields two artefacts:

1. `snapshot@1` — immutable JSON listing the matching rows plus a canonical hash.
2. `receipt@view@1` — an Ed25519-signed acknowledgement binding the snapshot to a signer and data source.

Both artefacts are deterministic so that replay on another device produces the
same hashes.

## snapshot@1 Structure

```json
{
  "view": "finance-folders",
  "captured_at": "2024-05-22T19:24:03.417Z",
  "canonical_hash": "eb2a9c9f0a6a763e0d6c0d574ff4b6a4fb18847d1ab1dfef5f157a789ed0fe75",
  "rows": [
    {"id": "doc:a1", "type": "folder@1", "canonical_hash": "..."},
    {"id": "doc:a2", "type": "folder@1", "canonical_hash": "..."}
  ]
}
```

The canonical hash is computed from the canonical JSON payload (view name,
timestamp, and rows) using `serde_jcs` canonical ordering followed by BLAKE3.

## receipt@view@1 Structure

```json
{
  "id": "receipt:alice:finance-folders:2024-05-22T19-24-03Z",
  "view": "finance-folders",
  "snapshot_canonical_hash": "eb2a9c9f0a6a763e0d6c0d574ff4b6a4fb18847d1ab1dfef5f157a789ed0fe75",
  "rows": 2,
  "signer": "did:hn:alice",
  "source": ["did:hn:alice"],
  "captured_at": "2024-05-22T19:24:03.417Z",
  "canonical_hash": "0fb3dc1d33d2ed310a0c2cb2c632c3a5843b20a1a7a5b7e265da8c5c2662dde5",
  "signature": "MC4CFQDG..."
}
```

| Field                    | Description                                                          |
| ------------------------ | -------------------------------------------------------------------- |
| `id`                     | Deterministic slug `receipt:<alias>:<view>:<timestamp>`               |
| `snapshot_canonical_hash`| BLAKE3 hash of the referenced `snapshot@1` payload                    |
| `rows`                   | Number of rows captured in the snapshot                              |
| `signer`                 | DID of the identity that materialised the view                       |
| `source`                 | Data origins used (local DID today; remote DIDs when MCP is wired)   |
| `canonical_hash`         | BLAKE3 hash of the receipt canonical payload                         |
| `signature`              | Base64-encoded Ed25519 signature over the canonical payload          |

### Canonical Payload

Both snapshot and receipt canonical strings are produced via `serde_jcs`, ensuring
deterministic byte ordering. The receipt covers:

```
{
  "view": <string>,
  "snapshot_canonical_hash": <hex>,
  "rows": <usize>,
  "signer": <did>,
  "source": [<did>...],
  "captured_at": <RFC3339>,
  "merkle_proof": <optional>
}
```

`merkle_proof` is reserved for future MCP integrations where remote indices provide
authenticated proofs.

## Verification

`hn view verify <name>` performs three checks:

1. Loads the latest (or supplied) receipt and rebuilds the canonical payload.
2. Verifies the Ed25519 signature using the active identity's verifying key.
3. Replays the view definition to recompute `snapshot_canonical_hash` and compares
   against the recorded value.

The command reports `signature_valid` and `matches_current` booleans, ensuring
both cryptographic integrity and deterministic replay.
