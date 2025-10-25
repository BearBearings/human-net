

# M3 Implementation Plan — Trust & Exchange

## Objective

Deliver verifiable peer-to-peer exchange by elevating identity to **L2**, introducing the **offer → contract** capability chain, and enabling **shard publishing** between trusted peers.

### Exit Proof

Two verified vaults exchange an encrypted `folder@1` through a signed `contract@1`; both sides decrypt, verify provenance, and demonstrate revocation.

## Guiding Principles

* **Backward compatible:** M1/M2 smoke tests must pass unchanged.
* **Local-first trust:** verification artifacts live in the vault; network calls only occur during credential verification.
* **Self-contained contracts:** every `contract@1` carries the keys, policies, and signatures required for offline validation.
* **Deterministic replay:** all new flows (proofs, offers, contracts, shards) reproduce bit-for-bit.

## Workstreams

### 1. Verified Identity (L2)

**Goal:** allow a vault to prove ownership of a verifiable credential (VC) from a trusted issuer without central services.

**Implementation**

* `proof@1` schema captured (see `spec/proof@1.md`):

  ```json
  {
    "id": "proof:mock-entra-a1b2c3d4e5f6",
    "provider": "mock-entra",
    "issuer": "https://entra.mock/human-net",
    "subject": "did:hn:z82tFh...",
    "format": "mock_jwt",
    "claims": {"scope": "entra/basic"},
    "issued_at": "2025-01-05T10:25:43Z",
    "expires_at": "2025-02-04T10:25:43Z",
    "digest": "8b9e1a01d4b0d7..."
  }
  ```
* Vault now records provider entries referencing a stable `proof_id`; sanitized
  proofs live under `identities/<alias>/proofs/` while raw credentials stay
  encrypted elsewhere.
* CLI UX supported by new subcommands/flags:

  ```bash
  hn id verify --provider mock-entra      # refresh + persist proof
  hn id verify --provider mock-didkit     # alternate verifier
  hn id verify --dry-run --force ...      # pipeline / CI safety
  hn id status --with-credentials         # proof ids + policy facts
  ```
* Policy hooks: `verification.to_policy_facts()` exposes
  `{provider, proof_id, issuer, valid_until}` for `offer@1`/`contract@1`
  gating.
* Tests: unit suites for ledger/providers, vault persistence tests, and
  `cargo test -p hn-cli` in CI.

---

### 2. Offer → Contract Chain

**Goal:** exchange capabilities over docs between verified peers.

**Artifacts**

* `offer@1`: proposed capability + policy + validity window.
* `contract@1`: accepted capability set, parties, HPKE keys, expiry.
* `event@1`: append-only transition record.

**FSM (M3 scope)**

```
PROPOSED → ACCEPTED → FULFILLED → (REVOKED | EXPIRED)
```

**HPKE**

* Suite: X25519 + HKDF + XChaCha20-Poly1305.
* Generate per-contract content key; wrap for recipient’s DID key.

**CLI (landed in repo)**

```bash
# Alice creates an offer and stores it under ~/.human-net/offers/<alias>/
hn contract offer create --audience did:hn:bob... --unit doc:finance-folder@1 \
  --capability read --policy-ref policy:doc.read --emit /tmp/offer.json

# Inspect / list offers for the active identity
hn contract offer list
hn contract offer show --id offer:alice:finance-folder:...

# Bob accepts the shared offer file and produces a reserved contract
HN_HOME=~/.human-net-bob hn contract accept --offer /tmp/offer.json --emit /tmp/contract.json

# Alice fulfils the contract and emits a shard@1 payload
hn contract fulfill --contract-id <contract-id> \
  --payload samples/docs/folder.json \
  --emit-shard /tmp/shard.json

# Cross-check the artefacts (digest + proofs)
hn contract verify --offer /tmp/offer.json --contract /tmp/contract.json
```

**Tests / fixtures**

* CLI unit regression: `cargo test -p hn-cli --test contract_chain` (verifies sample offer/contract consistency).
* Manual flow: follow `docs/m3/Alice_Bob_Contract_Chain.md` using the new commands; fixtures live under `samples/contracts/`.
* Fulfilment encrypts payloads via HPKE (X25519HkdfSha256 + ChaCha20Poly1305); shard import/decrypt path exposed via `hn shard fetch`.
* Event signatures, automated shard distribution, and revocation tooling remain TODO items heading into S4.

---

### 3. Shard Publish / Subscribe

**Goal:** replicate contract-bound payloads between friends (LAN-first).

**Shard Index (`shard@1`)**

```json
{
  "publisher_did": "did:key:…",
  "seq": 42,
  "entries": [{"type":"contract@1","id":"…","cid":"bafy…"}],
  "merkle_root": "sha256:…",
  "sig": "ed25519:…"
}
```

**Publish**

```bash
hn shard publish --changed
```

* Writes signed index and data bundles.

**Subscribe**

```bash
hn shard subscribe @friend/bob
```

* Verifies signature + Merkle root.
* Dedupes by `seq`, writes `receipt@1`.

**Smoke test:** two vaults, LAN exchange, decrypt & validate, then revoke and confirm future reads denied.

---

### 4. Reputation & Completion (`rep@1`)

* Minimal schema: `{contract, counterparty, rating, attester_sig, ts}`.
* CLI: `hn rep list`, `hn rep attest`.
* Advisory only in M3; used in M4 for discovery ranking.

---

### 5. Observability, Docs, DX

* Structured JSON logs (never log keys or plaintext).
* Update README and troubleshooting guide for verification failures.
* Document schemas (`proof@1`, `offer@1`, `contract@1`, `event@1`, `shard@1`, `rep@1`) under `spec/` with diagrams.
* Fixtures in `samples/` for offline demos.
* Add `hn smoke m3` end-to-end scenario.

---

## Incremental Delivery Plan

| Sprint | Theme                        | Key Deliverables                                                   | Demo Check                                            |
| ------ | ---------------------------- | ------------------------------------------------------------------ | ----------------------------------------------------- |
| **S1** | Verified identity foundation | `proof@1`, verifier adapters, CLI verify/status, vault persistence | Alice obtains credential → vault shows id.level = 2   |
| **S2** | Offer pipeline               | `offer@1`, FSM skeleton, HPKE integration                          | Alice creates offer, Bob inspects terms               |
| **S3** | Contract fulfilment & shards | Full FSM, shard publish/subscribe, storage integration             | Contract fulfilled, shard transferred/decrypted       |
| **S4** | Reputation & smoke           | `rep@1`, revocation path, docs/tests                               | `hn smoke m3` passes end-to-end with revocation + rep |

---

## Cross-Cutting Tasks

* Security review: key lifecycle, proof storage, revocation.
* Deterministic replay for all logs (`hn audit replay` extension).
* CI: unit + integration suites, fixture bundles.
* Diagrams (PlantUML/Mermaid) for offer/contract flow.

---

## Dependencies & Open Questions

* Provider emulation (mock EntraID vs OIDC generic).
* HPKE crate validation.
* Network sandbox for LAN demo.
* Contract ↔ policy alignment (policy gates on `offer.create`, `contract.accept`).
* Revocation channel: shard delta vs direct MCP.

---

## Definition of Done

* `hn smoke m3` passes in CI.
* Deterministic vault replay covers proofs, contracts, shards, reputation.
* Docs/specs include working JSON examples for each artifact.
* Manual two-actor walkthrough (Alice/Bob) validated.
* Open risks documented for M4.

---

## Summary of Identity-Level Change

### From static identity documents → dynamic proofs

* **Old model:** `id@2` (a static document for verified IDs)
* **New model:** `proof@1` artifacts + computed `id.level`

### Why the change?

| Problem with `id@2`                                                                 | Solution via `proof@1`                                                              |
| ----------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Tied identity to a single credential version; revocation or expiry was destructive. | Proofs are independent; each has its own lifecycle.                                 |
| Difficult to represent multiple credentials (passport + eID).                       | Multiple `proof@1` entries coexist; system computes effective id.level dynamically. |
| Forced PII or issuer metadata into identity record.                                 | Proofs are redacted, PII-free; originals live encrypted in the vault.               |
| Broke deterministic replay when proofs expired.                                     | Each proof is self-contained with its own hash; replay remains stable.              |

**Result:** Human.Net identities stay permanent and sovereign, while verifiable credentials evolve or expire independently — enabling L2/L3 compliance and deterministic replay.
