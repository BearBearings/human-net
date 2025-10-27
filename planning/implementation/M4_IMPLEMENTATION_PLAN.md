
# M4 Implementation Plan — Reach & Agency

## Objective

Extend Human.Net from peer-to-peer trust into **global reach and human–agent collaboration**.
M4 introduces the **embedded MCP server**, **WAN discovery**, and the **A1 local assistant** that compiles natural intents into policy- and contract-compliant actions.

### Exit Proof

Two vaults, each running a reachable MCP node, exchange an `offer@1 → contract@1` sequence across WAN.
An A1 assistant compiles the user’s natural command (“Offer my bike for 50 €” or “Find Anna’s Rome pictures”) into a signed `plan@1`, executes it under policy consent, and both vaults replay identical state and verified receipts.

---

## Guiding Principles

* **Vaults as servers:** every user can host a minimal MCP endpoint without central dependency.
* **End-to-end determinism:** assistants, MCPs, and views must replay deterministically.
* **Consent-first AI:** assistants may *plan*, never *act*, without policy approval.
* **WAN optionality:** everything works offline; discovery only adds scale, not dependency.
* **Human legibility:** intents, plans, and outcomes must be auditable as signed microdocs.

---

## Workstreams

### 1. Embedded MCP Server

**Goal:** allow any vault to serve shards, views, and indices securely to trusted peers or public caches.

**Implementation**

* Binary: new sub-crate `hn-mcp` embedded in CLI (`cargo run -p hn-cli -- mcp serve`).
* Protocol: HTTPS (TLS + mutual auth via DIDs).
* Endpoints:

  * `GET /index` — return Merkle root + proof range.
  * `GET /shard/:id` — stream encrypted shard.
  * `POST /publish` — push shard delta (friends only).
* Config file `mcp.json`:

  ```json
  {"listen":"0.0.0.0:4433","mode":"friends","max_ttl":"7d","storage":"./cache"}
  ```
* Policy hooks: `policy.mcp.allow(mode, peer_did)` for reach gating.
* Tests: run two MCP instances locally, publish/subscribe over TCP loopback, compare digests.

---

### 2. WAN Discovery

**Goal:** make verified peers and their indices discoverable beyond LAN, without central directories.

**Implementation**

* Discovery schema `presence@2`: includes endpoint URLs, Merkle root, timestamp, and proof of control.
* CLI:

  ```bash
  hn discover add did:hn:anna https://anna.example.org
  hn discover refresh
  hn discover list
  ```
* Friends exchange signed `presence@2` docs periodically; MCP nodes cache them as “reach hints.”
* Optional integration with mDNS / DNS-SD for mixed LAN/WAN presence.
* Smoke: fetch friend index over WAN → verify Merkle proof → list remote offers.

---

### 3. A1 Local Assistant (Intent Compiler)

**Goal:** translate natural-language commands into signed Human.Net microdocs.

**Implementation**

* Engine: Rust LLM backend (`llama-rs` or `candle-transformers`).
* Schema:

  ```json
  {
    "id":"plan:offer-bike-50",
    "prompt":"Offer my bike for 50€",
    "steps":[
      {"intent":"create.offer","params":{"doc":"photo-bike@1","price":50}},
      {"intent":"publish.offer","params":{"audience":"friends"}}
    ],
    "signature":"ed25519:…"
  }
  ```
* CLI:

  ```bash
  hn ai plan "Offer my bike for 50€"
  hn ai run plan:offer-bike-50 --dry-run
  ```
* Policies: `policy.ai.run = ask` ensures explicit confirmation.
* Output: `plan@1` stored in `plans/<alias>/`, replayable and auditable.
* Tests: feed predefined prompts, validate generated JSON and hashes, compare replay digest.

---

### 4. Vault Sync (Multi-Device & Backup)

**Goal:** replicate encrypted state between multiple devices owned by the same user.

**Implementation**

* Pairing: QR-based handshake → X25519 ephemeral channel.
* Sync protocol: append-only event replication with `event@1` digests.
* CLI:

  ```bash
  hn sync pair --qr
  hn sync pull
  hn sync push
  ```
* Conflict resolution: deterministic by timestamp + signature.
* Optional Shamir (3-of-5) recovery for lost devices.
* Tests: two paired vaults → modify doc on one → verify mirrored hash on the other.

---

### 5. Views & Materialization Proofs

**Goal:** enable large-scale search and verifiable view composition across MCP indices.

**Implementation**

* Query engine: `view@1` executes subset HQL-0 (type, tags, AND/OR).
* Materialization receipts:

  ```json
  {
    "view":"friends-bike-offers",
    "source":["did:hn:anna","did:hn:bob"],
    "merkle_proof":"sha256:…",
    "signature":"ed25519:…"
  }
  ```
* CLI:

  ```bash
  hn view run friends-bike-offers --source mcp
  hn view verify friends-bike-offers
  ```
* Result views are cacheable and re-verifiable across vaults.
* Tests: cross-MCP query returning deterministic proof receipts.

---

### 6. Edge Deployment Profile (Synology / NAS)

**Goal:** allow simple real-world hosting on consumer devices.

* `hn mcp serve --profile synology` autoconfigures TLS, port forwarding, cache path.
* Health endpoint `/healthz` for uptime monitoring.
* Example use case: home user shares creative content or offers publicly through self-hosted MCP.
* Docs: “Running Human.Net on Synology NAS” under `docs/deploy/`.

---

### 7. Observability, Docs, DX

* Structured logs (`--log-json` mode).
* Extended smoke tests (`hn smoke m4`): assistant intent → MCP transfer → remote view proof.
* Specs: `plan@1`, `presence@2`, `view@1`, `materialization@1`.
* Mermaid diagrams for intent→plan→contract flow.
* Developer docs for embedding LLMs locally.

---

## Incremental Delivery Plan

| Sprint | Theme         | Key Deliverables                                           | Demo Check                                |
| ------ | ------------- | ---------------------------------------------------------- | ----------------------------------------- |
| **S1** | MCP base      | Local HTTP(S) MCP server, config, basic publish/subscribe  | Two vaults exchange shards via MCP        |
| **S2** | WAN discovery | presence@2 schema, friend refresh, Merkle proof validation | Alice fetches Bob’s remote index          |
| **S3** | A1 assistant  | Rust LLM backend, plan@1 schema, dry-run & consent flow    | “Offer my bike for 50€” → signed plan     |
| **S4** | Sync & views  | E2EE sync, HQL-0 query, materialization receipts           | Two devices sync; remote view verified    |
| **S5** | Smoke & DX    | `hn smoke m4`, docs, deployment guide                      | End-to-end WAN exchange + assistant proof |

---

## Sprint S1 Detail — MCP Base

Current state:

- `services/discovery` already ships the LAN discovery daemon (`hn-discovery`) that broadcasts and tracks peers over mDNS. WAN discovery remains future work for S2.
- `services/mcp` now carries the embedded MCP server scaffolding and the CLI exposes it via `hn mcp serve`.

Scope breakdown:

- Scaffold the embedded MCP server crate (`hn-mcp`) with async runtime, config loader, and TLS scaffolding.
- Implement minimum endpoints: `GET /healthz`, `GET /index`, `GET /shard/:id`, `POST /publish`; log structured events for digest comparisons.
- Add `mcp.json` parsing to the CLI, wiring `hn mcp serve` to start the embedded server with policy gating hooks.
- Reuse the existing LAN discovery peer table to seed initial reachability hints while WAN discovery is unavailable.
- Write local smoke: run two vaults on a MacBook Pro, publish shards over localhost HTTPS, verify Merkle roots match.
- Author Synology NAS (DS-series) test plan: cross-compile or deploy via Docker, confirm service start, certificate handling, and shard transfer back to a laptop client.
- Package a container image recipe (`tooling/docker/hn-mcp.Dockerfile`) and document DSM deployment (`docs/deploy/mcp-synology.md`).
- Add TLS + DID allowlist configuration to `mcp.json` plus a `hn mcp auth` helper that signs WAN publish requests.
- Automate end-to-end verification via `tooling/scripts/m4-s1-test.sh`; runs doc → offer → contract → fulfilment → MCP publish/subscribe loop.

Exit artifacts:

- Repeatable `cargo run -p hn-cli -- mcp serve --config mcp.json` demo with two local vaults syncing a shard.
- Synology deployment notes (`docs/deploy/mcp-synology.md`) plus container recipe for DS deployment.
- CLI tooling for request signing (`hn mcp auth`) exercised in local + Synology smoke.
- `m4-s1-test.sh` smoke script producing signed publish + remote subscribe proof.

---

## Sprint S2 Detail — WAN Discovery

Current state:

- Loopback MCP publish/subscribe works (S1); discovery beyond LAN is manual (`--mcp-url`).
- No schema or CLI support exists for advertising remote vault reachability.

Scope breakdown:

- Define and implement `presence@2` microdoc (DID, endpoints, Merkle root snapshot, expiry).
- Add CLI commands: `hn discover add|refresh|list`, and persistence under `$HN_HOME/discovery/`.
- Extend MCP server to serve latest presence and consume friend caches.
- Implement Merkle proof fetching/validation when pulling remote indices.
- Update smoke: publish Bob’s presence, have Alice refresh via WAN URL, then `hn shard subscribe --mcp-hint bob`.

Exit artifacts:

- `presence@2` spec + signed doc written under `spec/`.
- CLI produces cached hints and can show remote reach metadata.
- Automated smoke (`tooling/scripts/m4-s2-test.sh`) demonstrating Alice discovering Bob’s MCP via presence and fetching remote index over WAN.

---

## Sprint S3 Detail — A1 Assistant

Current state:

- `hn ai` command does not exist; plans are not modelled or signed.
- No mechanism turns a prompt into structured steps or stores plan artifacts.

Scope breakdown:

- Introduce `plan@1` schema with canonical JSON/signature support.
- Implement plan storage under `$HN_HOME/plans/<alias>/` plus CLI to generate, list, show, and dry-run plans.
- Provide a mock backend that converts prompts into deterministic plan steps (offer creation + publish) using explicit CLI parameters for doc and audience.
- Ensure generated plans are signed by the active identity and verifiable.

Exit artifacts:

- `spec/plan@1.md` with example and signing rules.
- New `hn ai` CLI with `plan`, `list`, `show`, `dry-run`, `run` commands.
- Smoke script (`tooling/scripts/m4-s3-test.sh`) proving prompt → plan generation → dry-run pipeline.

---

## Cross-Cutting Tasks

* Security review: MCP exposure, key rotation, consent gating.
* Replay determinism across MCP logs and AI plans.
* CI: run multi-node simulation (two vaults + one MCP).
* LLM model licensing and size validation (≤4 GB target).
* Developer tooling for Synology/NAS deployment.
* Assistant prompts default to dry-run execution until policy gates are enabled.

---

## Dependencies & Open Questions

* Model loading: candle vs llama-rs performance trade-offs.
* MCP TLS bootstrap: self-signed vs DID-based trust root.
* WAN traversal: fallback to relay if NAT blocked.
* Policy layering: how to combine `policy.ai.run` and `policy.mcp.publish`.
* Federation of indices: cache invalidation and expiry policy.

---

## Definition of Done

* `hn smoke m4` passes: assistant generates plan → WAN contract executes → view proof verified.
* Deterministic vault replay covers plans, MCP logs, and sync events.
* Docs/specs complete with examples for all new schemas.
* Two-actor + assistant demo reproducible on local + WAN setup.
* All open security items logged for M5 federation milestone.
