
# Human.Net – Core MVP Roadmap (M1–M4)

Human.Net builds from self-sovereign identity to verifiable human–agent collaboration.
Each milestone proves exactly one new trust boundary while keeping all components reusable.

---

## M1 – Identity & Vault (Self-Issued Beginnings)

**Goal:** Prove local sovereignty.

**Scope**

* L1 DID creation & key rotation.
* Encrypted local vault for personal data.
* LAN discovery (“I see peers” presence).
* Minimal `policy.json` controlling exposure.

**Exit Proof:**
Two peers discover each other, exchange signed presence pings, and local policy gates apply.

---

## M2 – Docs & Policies (The Data Fabric)

**Goal:** Prove local data ownership and governance.

**Scope**

* `doc@1` primitives (`file@1`, `folder@1`, `note@1`).
* Vault namespaces + deterministic replay.
* Table-driven policy engine for read/write TTLs.
* Local views (`scope=local`) for filtering vault docs.

**Exit Proof:**
A user imports a folder → vault creates `folder@1` → policy enforces access → replay produces same hash.

---

## M3 – Trust & Exchange (Verified Identity + Contracts + Publishing)

**Goal:** Prove inter-vault trust and secure data exchange.

**Scope**

* L2 verification via external API (EntraID, DIDKit, etc.).
* `offer@1` → `contract@1` with HPKE key wrapping.
* Shard publish/subscribe between friends (LAN + remote).
* `rep@1` entries for completion feedback.

**Exit Proof:**
Two verified peers exchange a `folder@1` through `contract@1`; both vaults decrypt, verify, and revoke.

---

## M4 – Reach & Agency (WAN + MCP + Local Assistant)

**Goal:** Prove global discovery, WAN-scale reachability, and natural human–agent collaboration — without leaving self-sovereignty.

**Scope**

* **Built-in MCP server:** enables index caching, view materialization, and optional shard storage on any node (LAN → WAN).
* **Friend reach & discovery:** follow remote DIDs, fetch public indices, verify Merkle proofs, maintain TTL-based reach hints.
* **Local Assistant (A1):** Rust-native LLM (candle/llama-rs) that compiles natural language into structured `policy@1`, `offer@1`, and `contract@1`, using dry-run verification before commit.
* **Intent engine:** translates phrases like *“Offer my bike for 50€”* into actionable plans; all steps signed and replayable.
* **Synology / edge deployment:** MCP profile for home or small business nodes with HTTPS, storage TTL, and discovery control.
* **Vault sync:** encrypted event replication between paired devices (QR onboarding + E2EE).

**Exit Proof:**
Two users, each running a reachable MCP node, use the local assistant to draft and confirm an offer–contract exchange across WAN.
Indices and receipts verify remotely; both vaults replay identical state.
A1 produces a signed `plan@1` → validated `policy@1` → executed `offer@1`/`contract@1`.

---

## Why This Works

1. **Layered trust:** each milestone adds one boundary (self → friend → world).
2. **No discard:** every artifact (vault, doc, contract, view) persists into production.
3. **Demo-ready:** after M4, two users + one MCP + one assistant show the full human–agent economy.
4. **Human-centric:** AI acts under explicit consent and traceable policy, not behind opaque APIs.

---

## Exit Proof Table

| Milestone | Core Proof                            | Components Proven                          | Verification Mode |
| --------- | ------------------------------------- | ------------------------------------------ | ----------------- |
| **M1**    | Identity ping between two peers       | `id@1`, vault init, LAN discovery          | Local             |
| **M2**    | Deterministic doc import & replay     | `doc@1`, `policy@1`, `view@local`          | Local             |
| **M3**    | Verified folder exchange via contract | `id@2`, `offer@1`, `contract@1`, `shard@1` | LAN / remote      |
| **M4**    | WAN contract via assistant & MCP      | `mcp@1`, `view@1`, `assistant@1`, `plan@1` | WAN / public      |

---

## Deferred Topics

| Topic                       | Why Defer                         | When    |
| --------------------------- | --------------------------------- | ------- |
| L3 state-verified IDs       | Requires government/authority API | Post-M4 |
| Vector search               | Adds index complexity             | M5+     |
| Payments / escrow           | Needs economic layer              | M5+     |
| Federation & global caching | Requires verified MCP receipts    | M5+     |


