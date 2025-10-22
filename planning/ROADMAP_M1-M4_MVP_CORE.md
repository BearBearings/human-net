# Human.Net – Core MVP Roadmap (M1–M4)

Human.Net builds from self-sovereign identity to verifiable human–agent collaboration.  
Each milestone proves exactly one new trust boundary while keeping all components reusable.

---

## M1 – Identity & Vault (Self-Issued Beginnings)

**Goal:** Prove local sovereignty.

**Scope**
- L1 DID creation & key rotation.
- Encrypted local vault for personal data.
- LAN discovery (“I see peers” presence).
- Minimal `policy.json` controlling exposure.

**Exit Proof:**  
Two peers discover each other, exchange signed presence pings, and local policy gates apply.

---

## M2 – Docs & Policies (The Data Fabric)

**Goal:** Prove local data ownership and governance.

**Scope**
- `doc@1` primitives (`file@1`, `folder@1`, `note@1`).
- Vault namespaces + deterministic replay.
- Table-driven policy engine for read/write TTLs.
- Local views (`scope=local`) for filtering vault docs.

**Exit Proof:**  
A user imports a folder → vault creates `folder@1` → policy enforces access → replay produces same hash.

---

## M3 – Trust & Exchange (Verified Identity + Contracts + Publishing)

**Goal:** Prove inter-vault trust and secure data exchange.

**Scope**
- L2 verification via external API (EntraID, DIDKit, etc.).
- `offer@1` → `contract@1` with HPKE key wrapping.
- Shard publish/subscribe between friends (LAN + remote).
- `rep@1` entries for completion feedback.

**Exit Proof:**  
Two verified peers exchange a `folder@1` through contract@1; both vaults decrypt, verify, revoke.

---

## M4 – Discovery & Agency (Views + Assistants + Scale)

**Goal:** Prove global discovery and human/AI cooperation.

**Scope**
- `view@1` with HQL‑0 deterministic query + `intent` compilation.
- `materialization@1` receipts and proof verification.
- MCP runner prototype for global indices.
- A1 assistant compiling “intent → plan” under policy consent.

**Exit Proof:**  
User says “Find Anna’s Rome pictures.” Assistant compiles plan → executes across vault + friend shard → completes contract → verified receipt.

---

## Why This Works
1. **Layered trust:** each milestone adds one boundary (self → friend → world).
2. **No discard:** every artifact (vault, doc, contract, view) persists into production.
3. **Demo-ready:** after M4, two users + one MCP + one assistant show the full human–agent economy.

---

## Deferred Topics
| Topic | Why Defer | When |
|-------|------------|------|
| L3 state‑verified IDs | Needs public authority / API | Post‑M3 |
| Vector search | Adds index complexity | Post‑M4 |
| Payments / escrow | Requires economic layer | Post‑M4 |
| Federation | Needs proven MCP receipts | M5+ |
