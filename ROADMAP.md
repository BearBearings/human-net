# Human.Net — MVP Roadmap

> Stack: Rust CLI + local services. Core concepts: **id**, **unit**, **view**, **snapshot**, **shard**, **contract**.

## M1 — Identity & Peer Network (LAN-first)
**Goal:** Establish the local trust & transport plane.

**Deliverables**
- `id` (L1) self-inception: create/use/show/verify/export/recover
- Discovery service (mDNS): `peer list/get`, health endpoint
- Policy skeleton: `policy get/patch` (consent gates)
- Service control: `service start|stop|status|logs` (discovery)

**CLI (must pass)**
```
hn id create <name>; hn id use <name>; hn id verify
hn service start discovery; hn peer list; hn peer get <alias|did>
hn policy get; hn policy patch --set max_spend_eur=50
```

**Acceptance**
- Two nodes on LAN discover each other (<2s)
- DID export + recover roundtrip succeeds
- All writes support `-o json`, `--dry-run`, `--yes` on writes

---

## M2 — Units & Views (Local DB; AI-friendly)
**Goal:** Make facts addressable (units) and perspectives composable (views).

**Deliverables**
- Units: `create/import/get/list/delete`, signatures, verification
- Indexer (SQLite+FTS), background refresh
- Views: `create (static|dynamic|ephemeral)`, `link`, `run`, `rows`, `snapshot`, `delete`
- GC policy & tool: TTL/LRU for ephemeral views; snapshot retention

**CLI (must pass)**
```
hn unit import --type offer -f offers.csv --map 'alias=slug,price=eur'
hn view create shop-db --mode dynamic --rule 'type=offer AND inventory.available>0' --source local
hn view run shop-db; hn view rows shop-db -o json
hn view exec --rule 'text:"green tee" AND price.amount:[0,2000]' --source local --ttl 3d
hn gc dry-run; hn gc run
```

**Acceptance**
- 10–50k units → query P95 <150 ms
- Cycle-safe view linking; `view snapshot` immutable & verifiable
- Ephemeral views auto-GC by TTL/LRU

---

## M3 — Publish & Contracts (Commerce rails)
**Goal:** Share and transact with signed micro-contracts.

**Deliverables**
- Publish: `view publish` → **shard** (CBOR) with mini-index + ETag
- Market search: fan-out over discovered peers’ shards
- State/events: `pricing@1`, `inventory@1` + reducers → index
- Contracts FSM (MCP): `propose → accept/reserve → fulfill` (+ proofs)
- Credential hooks (L2/L3) honored by MCP policy

**CLI (must pass)**
```
hn view publish shop-db --visibility public
hn service start all; hn peer list
hn contract propose sellerA green-tee --qty 1 --yes -o json
hn contract fulfill <ctr-id> --proof 'PSP:txn_123' --yes
```

**Acceptance**
- Shard discovery + market query <300 ms on LAN
- Versioned `RESERVE` prevents oversell; contract chain verifies end-to-end
- Price/stock deltas propagate to shard consumers (ETag)
