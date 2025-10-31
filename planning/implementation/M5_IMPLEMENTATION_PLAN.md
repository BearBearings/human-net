
# **M5 Implementation Plan — Federation & Resilience**

## **Objective**

Extend Human.Net from individual WAN peers into **federated networks of trust**.

> **Status note:** WAN real-world drill (multi-tenant validation) and full vault restore are deferred to Milestone 6. This plan documents the intended flows; execution resumes alongside the M6 operational hardening work.
M5 enables MCP nodes to interconnect, replicate indices, delegate reachability, and preserve resilience under node loss — without central servers.

**Exit Proof:**
Multiple vaults and MCP nodes federate across WAN.
When one node is offline, its presence and indices remain discoverable via trusted peers.
A vault can be fully restored from federated replicas, maintaining identical Merkle roots.

---

## **Guiding Principles**

* **No central directories:** federation emerges from mutual publication of signed `presence@2` documents.
* **Proof before trust:** all remote data or indices must carry Merkle + signature proof.
* **Optionality:** federation adds reach and resilience but never dependency.
* **Privacy-first caching:** nodes store encrypted shards only for authorized peers.
* **Deterministic recovery:** restored vaults must reproduce identical digests.
* **Progressive hosting:** same binary runs on NAS, NGO server, or cloud relay.

---

## **Sprints**

### **1. Federated Indices**

**Goal:** replicate searchable index fragments between trusted MCPs.

**Implementation**

* Define `index@2` — Merkle root + source + proof chain.
* Extend MCP with `/federate` endpoint for index exchange.
* Background task `mcp sync` periodically fetches proofs.
* Store remote indices under `$HN_HOME/cache/federation/<peer_did>/`.
* CLI:

  ```bash
  hn mcp federate add did:hn:bob
  hn mcp federate refresh
  hn mcp federate list
  ```
* Verify all incoming indices against signed `presence@2`.

**Test:** two MCPs exchange indices; Merkle roots verified.

---

### **2. Presence Relays**

**Goal:** make mobile or low-power peers reachable via trusted relays.

**Implementation**

* Add `relay@1` block to `presence@2`:

  ```json
  {"relay": {"did": "did:hn:relay123", "url": "https://relay.hn.net"}}
  ```
* MCPs support proxy publish for registered peers.
* CLI:

  ```bash
  hn mcp relay register --host did:hn:relay123 --url https://relay.hn.net
  hn mcp relay push --to did:hn:relay123
  ```
* TTL-based cleanup (`policy.relay.ttl`).
* Mutual DID verification before accepting traffic.

**Test:** mobile client reachable through relay; exchange completes with relay offline afterward.

---

### **3. Resilience & Backup**

**Goal:** deterministic vault recovery from federated replicas.

> **Status:** deferred to backlog (post-M5). Keep specification for reference; implementation resumes in later milestone.

**Implementation**

* `backup@1` doc = Merkle snapshot of vault state.
  * Includes manifest (`entries[]`) covering `identities/`, `personal/`, `contracts/`, `events/`, `shards/`, `receipts/`, `presence/`, `config/`, `sync/` (optional cache inclusion).
  * Payload sealed as HPKE-encrypted `tar+zstd` blob; default `scope=full`, `scope=delta` references a `base_backup`.
* CLI:

  ```bash
  hn vault backup create --push-url http://mcp.example.net:7733
  hn vault backup verify --path backup.json
  hn vault backup restore --path backup.json --into ~/.human-net --verify-only
  ```
  * `create` snapshots `$HN_HOME`, encrypts via HPKE, writes `backup@1`, and optionally pushes to MCP using authenticated `POST /backup`.
  * `verify` recomputes signatures, Merkle roots, and payload digests without touching live data.
  * `restore --verify-only` performs a dry run; without the flag it unpacks into a staging directory before swap-in.
* MCP transport:
  * `POST /backup` accepts signed `backup@1` payloads, storing `header.json` + `payload.bin` under `$MCP_HOME/backups/<owner>/<id>/` and indexing by canonical ID.
  * `GET /backup/:id` returns the header (append `?include=payload` to embed the ciphertext).
  * `GET /backup/:id/blob` streams the encrypted payload for restore tooling.
* Optional Shamir (3-of-5) key recovery.

**Tests:** snapshot → push → restore (verify-only) → digest identical.
* `cli/tests/backup.rs` exercises create/verify/restore round-trip with the local CLI + HPKE pipeline.
* `tooling/scripts/m5-smoke.sh` runs backup create with MCP push and restore verification inside the federated smoke suite.
* _(Deferred: re-enable full swap/restore automation once backlog work resumes.)_

---

### **4. Relational Trust Graphs**

**Goal:** express verifiable *closeness and trust*, not ratings or scores.

**Concept**

Reputation in Human.Net measures **verified relational proximity** —
“how well two peers have cooperated,” not “how popular they are.”
Each trust link is backed by signed events such as contracts, payments, or shard exchanges.

**Schemas**

`trust_link@1`

```json
{
  "from": "did:hn:alice",
  "to": "did:hn:bob",
  "based_on": [
    "contract:offer-bike-2025",
    "payment:rep-0049"
  ],
  "confidence": 0.93,
  "last_seen": "2025-10-25T08:01Z",
  "signature": "ed25519:..."
}
```

`reputation@1`

```json
{
  "observer": "did:hn:alice",
  "links": ["trust_link:alice-bob", "trust_link:alice-carol"],
  "aggregate": {"avg_confidence": 0.9, "size": 2},
  "signature": "ed25519:..."
}
```

**Usage**

* Each vault recomputes trust links locally:
  * `trust_link@1` includes `id`, `from`, `to`, `based_on[]`, `confidence`, optional `context`, `last_seen`, `ttl_seconds`, and a signature. Stored under `$HN_HOME/trust/links/<alias>/`.
  * `reputation@1` aggregates link IDs (`links[]`), summary stats (`avg_confidence`, `count`, optional min/max/stddev), optional `policy_ref`, and is written to `$HN_HOME/trust/reputation/<alias>/`.
* MCP exposes optional `/trust` endpoint for friend-of-friend discovery:
  * `GET /trust/:target` returns signed `reputation@1` if `policy.trust.exposure` allows.
  * `GET /trust/:target/links` (friends-only) streams selected `trust_link@1` headers without raw evidence.
* Policy engine learns new selectors (`reputation.avg_confidence`, `reputation.count`, `trust_link.confidence`) for inbound offer/payment gating. Exposure defaults to off unless explicitly enabled.
* CLI additions:
  * `hn trust link derive --to did:hn:bob --evidence contract:...,payment:...`
  * `hn trust reputation compute --target did:hn:bob --policy trust/default`
  * `hn trust publish --target did:hn:bob` (push aggregate to MCP).
* Server side: `services/mcp/src/trust` module providing `/trust` handlers, cache, and policy filters.

**Tests:** peers exchange trust links; recomputed aggregates deterministic (`cli/tests/trust_graph.rs` derives links, enforces policy gating, and checks aggregate stability).

---

### **5. DNS / DHT Bridging**

**Goal:** human-readable discovery of MCP endpoints without central registry.

**Implementation**

* Lightweight DHT storing `(did_hash → presence@2)` pairs.
  * Schema: `dht_hint@1` (`spec/dht_hint@1.md`) including `presence_cid`, `presence_url`, optional relay DID, signed by the advertised vault.
  * Key = `blake3(did)[:32]`; values propagated via libp2p Kademlia with record TTL aligned to `presence@2.expires_at`.
* Integrate libp2p-Kademlia lookup into discovery service.
  * New `hn-discovery` sub-module handling DHT bootstrap, publish, and resolve flows.
  * Configurable bootstrap peers via `$HN_HOME/config/dht.toml` (default to federation profile seeds).
* Optional DNS TXT:

  ```
  _hn.did.bob.human.net TXT "did:hn:bob=https://bob.hn.net/mcp"
  ```
* CLI:

  ```bash
  hn discover publish --dht
  hn discover resolve did:hn:bob
  hn discover cache list --dht
  ```
  * `publish --dht` injects latest `presence@2` into Kademlia + optional DNS TXT.
  * `resolve` verifies DHT hint chain and fetches presence; `--dns-only` and `--dht-only` toggles.
* Validate all records via DID signature chain.
  * Resolver recomputes `presence@2` canonical hash and ensures it matches `dht_hint@1.presence_cid`.

**Tests:** publish → resolve → fetch presence → validate signature (see `cli/tests/dht_cache_fallback.rs` and `cli/tests/relay.rs` for end-to-end coverage across DHT hints and relay retention).

---

### **6. Edge Hosting Profiles**

**Goal:** make federation hosting dead-simple for NGOs, creators, shops.

**Implementation**

* Command:

  ```bash
  hn mcp serve --profile federation
  ```

  Auto-configures:

  * HTTPS (Let’s Encrypt)
  * cache path
  * backup TTL = 7 days
  * relay / DHT advertisement
  * pre-populated allowlist policy templates (friends-only publish, trust exposure off by default)
  * seeds libp2p bootstrap peers + health endpoints enabled
* Docker profile `hn-mcp:federation`.
* Docs: “Running a Community MCP” (`docs/deploy/`).

**Implementation notes**

* Profile generator writes `mcp.federation.toml` + `discover.federation.toml` with sensible defaults (TLS via ACME, storage paths, log level, bootstrap list).
* `hn mcp serve --profile federation` loads profile, ensures dependencies (certbot hooks, systemd snippet) and starts MCP + discovery + DHT worker.
* Provide Ansible/bash snippet in docs for NAS/VM deployment.

**Test:** federation profile runs on NAS + VM; cross-node health check passes.
* Automated scenario: two nodes spin up with federation profile, publish presence to DHT, resolve each other, complete shard exchange.
* Add `hn smoke m5 dht` covering publish/resolve workflow.

---

## **Incremental Delivery Plan**

| Sprint | Theme                    | Key Deliverables                             | Demo Check                               |
| ------ | ------------------------ | -------------------------------------------- | ---------------------------------------- |
| **S1** | Federated Indices        | `index@2`, `/federate` endpoint, proof check | Two MCPs exchange verified indices       |
| **S2** | Presence Relays          | `presence@2` relay field + proxy publish     | Mobile peer reachable via relay          |
| **S3** | Resilience & Backup      | `backup@1` snapshot + restore                | Vault restored identically               |
| **S4** | Relational Trust         | `trust_link@1`, `reputation@1`, policy gates | Trust graph recomputed deterministically |
| **S5** | DHT & Federation Profile | DHT lookup, DNS bridge, auto-config profile  | DHT resolve + one-click federation demo  |
| **S6** | Smoke & Docs             | End-to-end smoke tests + full spec and docs  | `hn smoke m5` green + specs merged       |

---

## **Sprint S1 Detail — Federated Indices**

Current state:

* `hn mcp serve` (from M4) publishes local indices for direct consumers, but federation still depends on manual shard drops and `shard_index@1`.
* Remote cache directories under `~/.human-net/cache/` do not distinguish trusted peers, retention windows, or Merkle lineage.
* Presence proofs validate peer reachability, yet no canonical link ties a fetched index back to the signer of the latest `presence@2`.

Scope breakdown:

* Author `spec/index@2.md` capturing Merkle root, pagination cursors, source MCP URL, and the signer’s `presence@2` digest.
* Add a `/federate/index` endpoint to the MCP server that returns signed slices and honours pagination + If-None-Match headers.
* Introduce a `FederationSync` async worker that iterates configured peers, negotiates cursors, and retries with exponential backoff.
* Persist remote slices under `$HN_HOME/cache/federation/<peer_did>/index-<timestamp>.jsonl` with policy-driven pruning and compaction.
* Extend `hn mcp federate` CLI with `add`, `remove`, `list`, and `refresh` subcommands storing roster state in `~/.human-net/config/federation.toml`.
* Provide optional `--mirror` mode that downloads referenced artifacts into `$HN_HOME/cache/federation/<peer_did>/artifacts/`, verifying digests before storing.
* Validate every incoming slice: signature, Merkle recompute, presence digest match, and optional shard availability check before accepting.
* Emit structured telemetry (`federation.sync.success`, `federation.sync.failure`, `federation.prune`) consumed by upcoming smoke scripts.
* Surface peer health in `hn status` so failed validations downgrade a peer to `stale`, guiding operators before Sprint 2 relay work.

Exit artifacts:

* `spec/index@2.md` merged with canonical JSON examples and signing rules.
* `services/mcp/src/federation/` module housing endpoint handler, sync worker, and storage adapter with unit coverage around proof validation.
* CLI federation subcommands with integration coverage under `cli/tests/federation.rs`, booting multiple MCP nodes and verifying mirrored slices + cursor retention.

---

## **Cross-Cutting Tasks**

* Security review for relay abuse and backup integrity.
* Performance tuning for large federations.
* Structured `--log-json` telemetry for federation events.
* Regression automation (`hn smoke m5`).
* Specs: `presence@2.md`, `backup@1.md`, `trust_link@1.md`, `reputation@1.md`.

---

## **Dependencies & Open Questions**

* DHT library choice (custom vs libp2p).
* Storage caps for public relays.
* Visualization of trust graphs.
* Secret-sharing UX (QR or mnemonic).
* Shared governance for community MCP nodes.

---

## **Definition of Done**

* `hn smoke m5` passes: federation sync, relay reachability, backup restore, DHT resolve, trust graph recompute.
* Three or more MCP nodes verified by Merkle proofs.
* Vault backup/restore digest identical.
* Trust graphs stable and policy-bounded.
* Community MCP deploy and docs complete.

---

Would you like me to follow this with a **spec appendix** (the three short JSON skeletons for `presence@2`, `backup@1`, and `trust_link@1`) for direct code scaffolding?
