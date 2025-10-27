# materialization@1 — View Snapshot Receipt

`materialization@1` defines the artefacts emitted when a `view@1` definition is
executed. The output is two microdocs stored side-by-side under
`~/.human-net/nodes/<alias>/views/<name>/`:

1. **snapshot@1** — immutable listing of the matching rows.
2. **receipt@view@1** — Ed25519-signed acknowledgement binding the snapshot hash
   to the signer and data source.

Both documents are canonical JSON serialised via `serde_jcs` so that hashes and
signatures replay deterministically on every device.

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

* `canonical_hash` is a BLAKE3 digest of the canonical payload shown above. The
  value doubles as an HTTP-style ETag when snapshots are downloaded via MCP or
  shared over sync bundles.

## receipt@view@1 Structure

```json
{
  "id": "receipt:alice:finance-folders:2024-05-22T19-24-03Z",
  "view": "finance-folders",
  "snapshot_canonical_hash": "eb2a9c9f0a6a763e0d6c0d574ff4b6a4fb18847d1ab1dfef5f157a789ed0fe75",
  "rows": 2,
  "signer": "did:hn:alice",
  "source": ["did:hn:alice"],
  "merkle_proof": null,
  "captured_at": "2024-05-22T19:24:03.417Z",
  "canonical_hash": "0fb3dc1d33d2ed310a0c2cb2c632c3a5843b20a1a7a5b7e265da8c5c2662dde5",
  "signature": "MEYCIQC..."
}
```

| Field                    | Notes                                                                 |
| ------------------------ | --------------------------------------------------------------------- |
| `snapshot_canonical_hash`| BLAKE3 hash of the paired `snapshot@1` document.                       |
| `rows`                   | Number of rows captured; helps detect partial materialisations.       |
| `signer`                 | DID of the vault that generated the receipt.                          |
| `source`                 | List of upstream DIDs consulted. Currently `[signer]`; WAN MCP sources
|                          | append remote DIDs.                                                   |
| `merkle_proof`           | Reserved for WAN indices. When present it stores a SHA-256 Merkle path
|                          | proving inclusion of the snapshot canonical hash in a remote index.   |
| `canonical_hash`         | BLAKE3 digest of the canonical receipt payload (see below). Serves as  |
|                          | the receipt ETag and replay key.                                      |
| `signature`              | Base64-encoded Ed25519 signature over the canonical payload.          |

### Canonical Payload and Signature

The receipt canonical payload is rendered with `serde_jcs` and contains:

```json
{
  "view": "finance-folders",
  "snapshot_canonical_hash": "eb2a9c9f0a6a763e0d6c0d574ff4b6a4fb18847d1ab1dfef5f157a789ed0fe75",
  "rows": 2,
  "signer": "did:hn:alice",
  "source": ["did:hn:alice"],
  "merkle_proof": null,
  "captured_at": "2024-05-22T19:24:03.417Z"
}
```

1. Compute `canonical_hash = blake3(canonical_payload)`.
2. Sign `canonical_payload` with the active identity’s Ed25519 signing key.
3. Store the Base64-encoded signature as `signature`.

## Verification Rules

`hn view verify <name>` performs:

1. Load the latest (or supplied) receipt and rebuild the canonical payload.
2. Verify the Ed25519 signature with the signer’s public key.
3. Re-run the `view@1` definition locally, recompute the snapshot canonical hash
   (using the same deterministic ordering), and compare it against the recorded
   `snapshot_canonical_hash`.

Verification reports `signature_valid` and `matches_current`. Consumers may
also use `canonical_hash` as a cache key/ETag when exchanging receipts over MCP
or sync channels.
