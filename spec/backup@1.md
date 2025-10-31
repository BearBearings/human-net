# backup@1 — Vault Snapshot Artifact

## Purpose

`backup@1` captures an encrypted, deterministic snapshot of a vault’s critical state,
allowing the owner to restore their environment (identities, documents, contracts,
events, and policy metadata) on any trusted node.

Backups are designed to be:

- **Verifiable** — each included file contributes to a Merkle root recorded in the header.
- **Encrypted** — payloads are sealed with HPKE for the designated recovery party (self or relay).
- **Incremental-friendly** — optional linkage to the previous backup enables delta streams.

## Fields

| Field               | Type        | Required | Description                                                                 |
| ------------------- | ----------- | -------- | --------------------------------------------------------------------------- |
| `id`                | `string`    | Yes      | Canonical identifier (`backup:<owner_did>:<timestamp>`)                     |
| `owner`             | `string`    | Yes      | Vault DID that produced the snapshot                                        |
| `target`            | `string`    | No       | Relay or peer DID intended to store this backup                             |
| `created_at`        | `RFC3339`   | Yes      | Timestamp when the snapshot was produced                                    |
| `scope`             | `string`    | Yes      | Snapshot scope (`full` or `delta`)                                          |
| `base_backup`       | `string`    | No       | Previous backup ID when `scope="delta"`                                    |
| `entries`           | `array`     | Yes      | File manifest (see below)                                                   |
| `merkle_root`       | `string`    | Yes      | Merkle root over entry digests (sorted lexicographically)                   |
| `payload_cid`       | `string`    | Yes      | BLAKE3 digest of the encrypted payload                                      |
| `algorithm`         | `string`    | Yes      | Payload algorithm (`tar+zstd@1` default)                                    |
| `enc`               | `string`    | Yes      | Base64 HPKE encapsulated key for the recipient                              |
| `ciphertext`        | `string`    | Yes      | Base64 payload (compressed + encrypted tarball or delta)                    |
| `signature`         | `base64`    | Yes      | Ed25519 signature over the canonical payload                                |

### Entry structure

```json
{
  "path": "personal/docs/note/note_2025-01-01.json",
  "digest": "f2e3…",
  "size": 1820,
  "mode": "file"
}
```

* `path` — POSIX-style relative path inside the vault home (`$HN_HOME`).
* `digest` — BLAKE3 hex digest of the plaintext file contents.
* `size` — Uncompressed size in bytes.
* `mode` — `"file"` or `"dir"` (directories are included when non-empty; digest is zero hash).

### Canonical form & signing

The canonical payload (RFC 8785 / JSON Canonicalization Scheme) omits `ciphertext`
to keep signatures stable even when the encrypted blob rotates.

```json
{
  "base_backup": "backup:did:2024-12-01T12:00:00Z",
  "created_at": "2025-01-10T08:45:00Z",
  "entries": [
    {
      "digest": "f2e3…",
      "mode": "file",
      "path": "personal/docs/note/note_2025-01-01.json",
      "size": 1820
    }
  ],
  "id": "backup:did:2025-01-10T08:45:00Z",
  "merkle_root": "7a9b…",
  "owner": "did:hn:alice",
  "payload_cid": "c9ff…",
  "scope": "full",
  "target": "did:hn:relay123"
}
```

Signature = `Base64(Ed25519Sign(private_key, canonical_json))`.

`ciphertext` is stored alongside the header (base64). Implementations SHOULD chunk
the encoded payload for transport (e.g., multipart upload).

## Payload format

Default payload is a zstd-compressed tar archive containing the selected files/directories
mirroring their relative path inside `$HN_HOME`. Delta backups MAY encode only changed files;
consumers reconstruct the Merkle root by applying `base_backup` + delta entries.

For encryption the producer:

1. Computes `payload = TarZstd(entries)`.
2. Encrypts using HPKE (X25519HkdfSha256 KEM + ChaCha20Poly1305 AEAD) with the target’s HPKE public key.
3. Records `enc` (base64 encapsulated key), `ciphertext` (base64 AEAD body), and `payload_cid`.

## MCP transport (`/backup`)

Relays and peers expose:

- `POST /backup` — accept a `backup@1` document payload (JSON body) with optional streaming of the ciphertext.
  * Authenticated with `X-HN-*` headers, same as `/publish`.
  * Stores metadata (JSON) and encrypted payload under `$MCP_HOME/backups/<owner>/<id>/`.
- `GET /backup/:id` — return stored `backup@1` header (without ciphertext unless `?include=payload`).
- `GET /backup/:id/blob` — stream the encrypted payload for restore.

## CLI workflow

```
hn vault backup create --target did:hn:relay123 --scope full
hn vault backup create --scope delta --base backup:... --target did:hn:relay123
hn vault backup restore --source did:hn:relay123 --id backup:... --into ~/.human-net
hn vault backup verify --path backup.json
```

- `create`:
  * Collects directories: `identities/`, `personal/`, `contracts/`, `events/`, `shards/`,
    `receipts/`, `presence/`, `config/`, `sync/`.
  * Excludes cache directories unless `--include-cache`.
  * Produces `backup@1` + encrypted payload, optionally pushes to relay via MCP `/backup`.
- `restore`:
  * Downloads header + payload, verifies signature and Merkle root, decrypts for the active identity,
    and writes files to a staging area before swapping into `$HN_HOME`.
  * Supports dry-run verification (`--verify-only`).
- `verify`:
  * Confirms signature, Merkle root, and payload digest for a local `backup@1` file.

## Determinism & replay

* File ordering inside the payload MUST be sorted lexicographically by path.
* Timestamps in tar headers are normalized to UTC seconds.
* Restores must reproduce identical file hashes; after restore, `hn vault backup verify`
  can rehash the live tree and compare against the stored Merkle root.

