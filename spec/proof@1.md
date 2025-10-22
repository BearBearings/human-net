# proof@1 — Sanitized Credential Snapshot

`proof@1` captures the **sanitized summary** of a verifiable credential issued
by an external authority. It is stored inside the identity vault under
`identities/<alias>/proofs/` whenever a verification provider refreshes an
attestation. Raw credentials (tokens, PII) remain encrypted elsewhere; the proof
document keeps only what downstream policy engines or contracts need to reason
about trust.

## Schema

```json
{
  "id": "proof:mock-entra-a1b2c3d4e5f6",
  "provider": "mock-entra",
  "issuer": "https://entra.mock/human-net",
  "subject": "did:hn:z82tFh...",
  "format": "mock_jwt",
  "claims": {
    "scope": "entra/basic",
    "token_snapshot": "ZXhhbXBsZS1iYXNlNjQtand0..."
  },
  "issued_at": "2025-01-05T10:25:43Z",
  "expires_at": "2025-02-04T10:25:43Z",
  "digest": "8b9e1a01d4b0d7..."
}
```

### Field Notes

| Field | Purpose |
|-------|---------|
| `id` | Deterministic handle (`proof:<provider>-<digest>`). |
| `provider` | Verification adapter that produced the proof (`mock-entra`, `mock-didkit`, …). |
| `issuer` | Upstream issuer URL or DID. |
| `subject` | DID of the identity the proof concerns. |
| `format` | Serialization hint for the underlying credential (JWT, LD proof, etc.). |
| `claims` | Redacted summary of the credential — no PII, only policy-relevant hints. |
| `issued_at` | UTC timestamp when the provider generated the proof. |
| `expires_at` | UTC expiry if the credential is time-bound; omitted when unbounded. |
| `digest` | BLAKE3 hash of the canonical payload used to derive `id`. |

The proof is **append-only**: new refreshes produce new identifiers, leaving old
proofs intact for replay and audit. Ledger entries in `id@2` reference a proof by
its `id`, allowing consumers to load supplementary context while keeping the
profile lean.

## Determinism & Privacy

- Digest + provider determine the proof ID, ensuring deterministic replays even
  across machines.
- `claims` should only contain anonymised or categorical data suitable for
  sharing; sensitive fields stay encrypted or are intentionally omitted.
- Mock providers hash a deterministic payload string (e.g. base64 token or
  normalized JSON). Future real providers should reuse the same strategy so the
  digest stays stable across replays.
