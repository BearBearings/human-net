# **Human.Net – Core MVP Roadmap (M1–M7)**

Human.Net evolves from **self-sovereign identity** to **verifiable human–agent collaboration** and now **human-centered value exchange**.
Each milestone proves one new trust boundary while keeping all artifacts reusable and auditable.

---

## **M1 – Identity & Vault (Self-Issued Beginnings)**

**Goal:** Prove local sovereignty.

**Scope**

* L1 DID creation & key rotation.
* Encrypted local vault for personal data.
* LAN discovery (“I see peers” presence).
* Minimal `policy.json` controlling exposure.

**Exit Proof:**
Two peers discover each other, exchange signed presence pings, and local policy gates apply.

---

## **M2 – Docs & Policies (The Data Fabric)**

**Goal:** Prove local data ownership and governance.

**Scope**

* `doc@1` primitives (`file@1`, `folder@1`, `note@1`).
* Vault namespaces + deterministic replay.
* Table-driven policy engine for read/write TTLs.
* Local views (`scope=local`) for filtering vault docs.

**Exit Proof:**
A user imports a folder → vault creates `folder@1` → policy enforces access → replay produces same hash.

---

## **M3 – Trust & Exchange (Verified Identity + Contracts + Publishing)**

**Goal:** Prove inter-vault trust and secure data exchange.

**Scope**

* L2 verification via external API (EntraID, DIDKit, etc.).
* `offer@1` → `contract@1` with HPKE key wrapping.
* Shard publish/subscribe between friends (LAN + remote).
* `rep@1` entries for completion feedback.

**Exit Proof:**
Two verified peers exchange a `folder@1` through `contract@1`; both vaults decrypt, verify, and revoke.

---

## **M4 – Reach & Agency (WAN + MCP + Local Assistant)**

**Goal:** Prove global discovery, WAN-scale reachability, and natural human–agent collaboration — without leaving self-sovereignty.

**Scope**

* **Built-in MCP server:** enables index caching, view materialization, and optional shard storage on any node (LAN → WAN).
* **Friend reach & discovery:** follow remote DIDs, fetch public indices, verify Merkle proofs, maintain TTL-based reach hints.
* **Local Assistant (A1):** Rust-native LLM (candle/llama-rs) that compiles natural language into structured `policy@1`, `offer@1`, and `contract@1`, using dry-run verification before commit.
* **Intent engine:** translates phrases like “Offer my bike for 50€” into actionable plans; all steps signed and replayable.
* **Synology / edge deployment:** MCP profile for home or small business nodes with HTTPS, storage TTL, and discovery control.
* **Vault sync:** encrypted event replication between paired devices (QR onboarding + E2EE).

**Exit Proof:**
Two users, each running a reachable MCP node, use the local assistant to draft and confirm an offer–contract exchange across WAN.
Indices and receipts verify remotely; both vaults replay identical state.
A1 produces a signed `plan@1` → validated `policy@1` → executed `offer@1`/`contract@1`.

---

## **M5 – Federation & Resilience (Networks of Trust)**

**Goal:** Establish durable multi-user networks by federating MCP nodes and enabling public discoverability of trust graphs.

**Scope**

* **Federated indices:** MCP nodes exchange verified Merkle proofs to maintain shared searchable caches.
* **Presence relays:** low-power peers (mobile, small devices) delegate reachability to trusted MCP hosts.
* **Resilience layer (backlog):** vault snapshotting/restore moved to backlog until post-M5 polish (picked up in M6).
* **DNS/DHT bridging:** DID → MCP endpoint mapping without central directories.
* **Reputation graphs:** signed interactions accumulate peer trust scores, aiding duplicate detection and identity validation.
* **Policy extensions:** configurable trust weighting for inbound offers and payments.
* **Edge hosting made simple:** “one-click” MCP startup profiles for NGOs, agencies, and small shops (local Synology, cloud VM, or mobile host).

**Exit Proof:**
Multiple users form a public-reachable federation; identities are cross-resolved via signed DHT hints;
a node loss does not break trust graph integrity; full vault restore from replicas is tracked in backlog (handled in M6).

---

## **M6 – Value & Exchange (Human-Centric Payments)**

**Goal:** Enable direct human-to-human and human-to-agent value transfer with cryptographic trust, explicit consent, and near-zero cost.

**Scope**

* **`payment@1` document type:** defines payer, payee, amount, currency, risk ownership (`risk=payer|shared`), and contract reference.
* **Local zero-fee transfers:** trusted peers can send small payments instantly with no platform intermediary.
* **Gateway MCPs:** optional bridge nodes for fiat or open-banking settlements; aggregate transactions to minimize external fees.
* **Policies for trust and risk:** payer can declare “friends” to waive protection; untrusted flows use escrow or small service fees.
* **Receipts and proofs:** `rep@2` receipts link payment to underlying contract or artifact.
* **Vault ledger:** append-only Merkle ledger in each vault, auditable but privacy-preserving.
* **Developer APIs:** allow apps (creators, NGOs, local services) to integrate tipping, donations, and micro-purchases.
* **Economic transparency:** every transaction is a signed fact, forming the foundation of a human-verified economy.
* **Operational hardening:** complete WAN federation drills and production-ready vault backup/restore flows.

**Exit Proof:**
Alice sends Bob €3 under `risk=payer`.
Both vaults record matching signed `payment@1` and `rep@2` documents; Bob’s balance updates deterministically.
The same mechanism scales to small businesses, local markets, or creators receiving micro-tips with negligible overhead.

---

## **M7 – Autonomous Agents & Federation (The Cognitive Layer)**

**Goal:** Extend the Human.Net trust and value fabric to autonomous agents that can reason, negotiate, and act under verifiable human policy.

**Scope**

* **Agent identity (`agent@1`):** agents gain DIDs and policy-bound roles; each agent signs under a supervising human or organization.
* **Federated reasoning:** MCP nodes host lightweight agent sandboxes; agents fetch public shards, compute proofs, and propose signed actions (`plan@2`).
* **Economic participation:** agents can initiate or fulfill `payment@1` and `contract@1` flows within human-approved risk thresholds.
* **Policy enforcement:** global `policy.agent.run` controls scope (what an agent can do, when, and for whom).
* **Audit & replay:** every agent action logs `trace@1` events, allowing deterministic replay and forensic verification.
* **Knowledge federation:** agents publish `insight@1` documents derived from data shards, with full provenance.
* **Coordination primitives:** agents coordinate via `proposal@1` and `vote@1` microdocs, forming distributed decision systems.
* **Consent-first AI:** no autonomous execution without signed human policy; every plan must be replayable and legible.

**Exit Proof:**
A1 (human-owned agent) scans a friend’s public offers, proposes a joint project (`plan@2`), negotiates via `contract@2`, and executes a small payment automatically under `policy.agent.run`.
Both vaults reproduce identical logs, and the human supervisors can replay and verify the entire sequence.

---

## **Why This Works**

1. **Layered trust:** self → friend → world → value → autonomy.
2. **Composable artifacts:** every object (doc, contract, payment, plan) is signed, replayable, and auditable.
3. **Progressive decentralization:** peers become servers, then networks, then self-governing ecosystems.
4. **Economic sustainability:** minimal fees, explicit risk ownership, and transparent proofs.
5. **Human primacy:** even autonomous agents act only within verifiable, consent-driven boundaries.

---

## **Exit Proof Table**

| Milestone | Core Proof                                 | Components Proven                             | Verification Mode     |
| --------- | ------------------------------------------ | --------------------------------------------- | --------------------- |
| **M1**    | Identity ping between two peers            | `id@1`, vault init, LAN discovery             | Local                 |
| **M2**    | Deterministic doc import & replay          | `doc@1`, `policy@1`, `view@local`             | Local                 |
| **M3**    | Verified folder exchange via contract      | `id@2`, `offer@1`, `contract@1`, `shard@1`    | LAN / Remote          |
| **M4**    | WAN contract via assistant & MCP           | `mcp@1`, `view@1`, `assistant@1`, `plan@1`    | WAN / Public          |
| **M5**    | Federated trust & discovery                | `presence@2`, `reputation@1`, DHT/DNS mapping | Federated WAN         |
| **M6**    | Human-to-human payment & receipt           | `payment@1`, `rep@2`, vault ledger            | Global / Economic     |
| **M7**    | Agentic cooperation & replayable reasoning | `agent@1`, `plan@2`, `trace@1`, `proposal@1`  | Federated + Cognitive |

---

## **Deferred Topics**

| Topic                          | Why Defer                                | When    |
| ------------------------------ | ---------------------------------------- | ------- |
| L3 state-verified IDs          | Requires authority or government linkage | Post-M6 |
| AI model sharing (`model@1`)   | Needs federated data and compute proofs  | M7+     |
| Automated dispute arbitration  | Depends on payment layer & policy graph  | M7      |
| Credit & lending primitives    | Build on proven payment layer            | M8      |
| Physical-world contracts (IoT) | Needs agentic orchestration              | M8+     |
| Vault backup & full restore    | Scoped to post-M5 polish/backlog         | M6      |

---

**Summary:**
By **M6**, Human.Net supports verifiable trust, exchange, and value among humans.
By **M7**, those same primitives enable *agents* to collaborate transparently within the same ethical, auditable framework — completing the loop from **identity** to **intelligence**, all under human control.
