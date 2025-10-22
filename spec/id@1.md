# id@1 — Identity (L1–L3) Spec

The `id@1` specification defines how Human.Net nodes describe and manage local
decentralized identifiers (DIDs) across three logical layers:

- **L1 (Keys & DID document)** — deterministic DID string, verification keys,
  and service endpoints used for discovery.
- **L2 (Profile)** — self-published metadata describing the peer and the units
  it is willing to transact on.
- **L3 (Credentials & hooks)** — verifiable credentials that extend trust
  relationships and drive policy decisions.

## DID Format

- Method: `did:hn:<slug>`, where `<slug>` is the lowercase base58btc encoding
  of the Ed25519 public key (`32` bytes).
- DID document is serialized with [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)
  JSON Canonicalization Scheme (JCS) before hashing or signing.
- Verification method entries:
  - `id`: `"#key-ed25519"`
  - `type`: `"Ed25519VerificationKey2020"`
  - `controller`: the DID itself
  - `publicKeyMultibase`: `z` + base58btc raw public key
- Service endpoints (all optional in M1):
  - `discovery`: `hn+mdns://<hostname>` (LAN mDNS announcement)
  - `mcp`: `hn+http://<addr>:<port>/mcp`

### Key Handling

- Keys are generated and stored locally inside the node vault.
- Export/import format: password-encrypted JSON (ChaCha20-Poly1305) containing
  the canonical DID document plus backup metadata (creation time, labels).
- Recovery validates the exported package checksum (`blake3`) before restoring.

## Profile@1 Overlay

L2 profile documents are stored as JSON in the vault and exposed through
`hn id get`:

```json
{
  "id": "did:hn:z8abc...",
  "alias": "shop-node",
  "capabilities": ["unit:offer", "contract:fulfill"],
  "endpoints": {
    "discovery": "hn+mdns://shop-node.local",
    "mcp": "hn+http://192.168.1.50:7711/mcp"
  },
  "updated_at": "2024-01-15T10:12:43Z"
}
```

- Fields are canonicalized with JCS before signing.
- `alias` must be unique per node vault; helpers exist to migrate aliases.
- Capabilities describe which contract states the node can emit or verify.

## Credential Hooks (L3)

- Credential store accepts W3C Verifiable Credential JWTs or LD proofs.
- Hooks defined per credential type (e.g. `know-your-peer@1`) run during
  `hn id verify` to check expirations, revocation lists, or issuer policies.
- Policy engine receives normalized credential facts:
  - `subject` (DID)
  - `issuer`
  - `claims` (flattened key-value pairs)
  - `proof` status
- Failing hooks surface actionable error codes so higher-level commands can
  return structured errors with `-o json`.
