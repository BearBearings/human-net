# offer@1 — Capability Offer Document

An `offer@1` document invites a counterparty to enter into a contract over a
specific document or capability (`doc@1`, `folder@1`, service capability, etc.). The offer is a
signed, replayable microdoc that references the issuer's verified identity and
sets the terms the contract must respect.

## Data Model

```json
{
  "id": "offer:alice:doc-finance-folder-1:2025-10-22T15:53:35.806298Z",
  "issuer": "did:hn:3q6f6sfvbku5vqju3ntnhx1htuvbtwdwhwu2hrwn7la3",
  "audience": "did:hn:hhdfjnbrtzq8ysreqlormubfmze96mawxj4ekhvhdt4h",
  "doc": "doc:finance-folder@1",
  "capability": "read",
  "policy_refs": ["policy:doc.read"],
  "valid_from": "2025-10-22T15:53:35.806298Z",
  "valid_until": "2025-11-21T15:53:35.806298Z",
  "proof_id": "proof:mock-entra-ed9df68c8c65",
  "issuer_hpke_public_key": "L5sE42ExbiPH5SG61Qt6sfNKCPpCfIfHWdbK71njn1s=",
  "terms_digest": "bc2b5aaa4c4189e820d47f706c6c65bf53958f3d07cc287951529b5554b5ebd6",
  "state": "PROPOSED",
  "created_at": "2025-10-22T15:53:35.806298Z",
  "retention_days": 30
}
```

### Required Fields

| Field | Description |
|-------|-------------|
| `id` | Deterministic offer handle (issuer namespace + unit + timestamp). |
| `issuer` | DID of the party extending the offer. |
| `audience` | DID (or group alias) invited to accept. |
| `doc` | Resource identifier (e.g. `doc:<id>@<version>`). |
| `capability` | Capability being granted (`read`, `write`, `execute`, …). |
| `policy_refs` | Policy gates that must hold when the contract executes. |
| `valid_from` / `valid_until` | Temporal window for acceptance. |
| `proof_id` | Link back to issuer's verified credential (`proof@1`). |
| `issuer_hpke_public_key` | Base64 HPKE public key (X25519) for counterparty encryption. |
| `terms_digest` | BLAKE3 hash of the canonical offer body (used by contracts). |
| `retention_days` | Optional archive retention period applied when the contract is accepted. |

Optional fields such as `consideration`, `metadata`, or `tags` can enrich the
offer for discovery without affecting the deterministic digest (include them in
`OfferDigestView` if used).

## Relationship to `contract@1`

- Contracts reference the offer ID and replicate the `terms_digest` to ensure no
  drift occurred between proposal and acceptance.
- Offers record the HPKE public key that justified the issuer's eligibility; the
  acceptor's contract entry stores its own HPKE public key.
- Revocation of a contract does **not** mutate the offer; instead the contract
  emits a terminal state (`REVOKED`) that future offers can inspect via
  reputation.
