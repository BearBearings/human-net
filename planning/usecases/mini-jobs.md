
## `usecases/mini-jobs.md`

# 🔧 Mini Jobs — Local Task + Bid Marketplace on Human.Net

**Goal:** Request small jobs (fix a lamp, mount a shelf), attach photos, receive bids from neighbors or craftsmen, select, contract, and fulfill — all peer-to-peer.

---

## 1) Value

* **Frictions removed:** describe job by voice/photo; agent drafts the doc.
* **Trust knobs:** require L2/L3 for safety (e.g., `insured=true`, `trade_license`).
* **No middleman:** offers, bids, and contracts are signed microdocs.

---

## 2) Core artifacts

### `job@1` — the request

```json
{
  "type": "job@1",
  "@version": 1,
  "title": "Fix kitchen faucet leak",
  "description": "Slow drip at the base; mixer tap.",
  "photos": ["cid:…IMG_1023…","cid:…IMG_1024…"],
  "location_hint": "near Alexanderplatz",
  "tags": ["plumbing","urgent"],
  "budget": {"currency":"EUR","max":120},
  "deadline": "2025-11-05",
  "requirements": {"claims":["insured=true","trade_license=plumber"]},  // derived claims
  "issuer": "did:hn:carol",
  "sig": "ed25519:…"
}
```

### `offer@1` — the job posting (discoverable)

```json
{
  "type": "offer@1",
  "@version": 1,
  "capability": "fulfill-job",
  "unit": "doc:job@1#kitchen-faucet",
  "terms": {"mode":"fixed|bid","accepts_bids":true},
  "audience": ["nearby","trusted-pros"],
  "valid_until": "2025-11-04T18:00:00Z",
  "issuer": "did:hn:carol",
  "sig": "ed25519:…"
}
```

### `bid@1` — a provider’s proposal

```json
{
  "type": "bid@1",
  "@version": 1,
  "job": "doc:job@1#kitchen-faucet",
  "provider": "did:hn:dave",
  "quote": {"currency":"EUR","value":95},
  "schedule": {"window":"2025-11-03T17:00:00Z/2h"},
  "notes": "Includes gasket; if valve damaged, +20€.",
  "proof_refs": ["proof@1#trade_license","proof@1#insured"],
  "sig": "ed25519:…"
}
```

### `contract@1` — acceptance

```json
{
  "type": "contract@1",
  "@version": 1,
  "unit": "doc:job@1#kitchen-faucet",
  "capability": "fulfill-job",
  "state": "ACCEPTED",
  "parties": {"buyer":"did:hn:carol","provider":"did:hn:dave"},
  "price": {"currency":"EUR","value":95},
  "schedule": {"start":"2025-11-03T17:30:00Z","duration_min":90},
  "address_enc": "enc:…",                   // optional encrypted address
  "safety": {"claims_required":["insured=true","trade_license=plumber"]},
  "sig": "ed25519:…"
}
```

### `rep@1` — after completion

```json
{
  "type": "rep@1",
  "@version": 1,
  "contract": "doc:contract@1#…",
  "counterparty": "did:hn:dave",
  "rating": 5,
  "note": "Quick fix; fair price.",
  "attester": "did:hn:carol",
  "sig": "ed25519:…"
}
```

---

## 3) Flows

**A) Create job (voice + photos)**

* User: “Find a plumber to fix a leaky kitchen faucet, budget 120, before Nov 5.”
* Agent:

  1. extracts entities → drafts `job@1`
  2. asks to attach photos → auto CID
  3. proposes `offer@1` with `accepts_bids=true`

```bash
hn doc create job@1 --fields '{...}'
hn offer create --capability fulfill-job --unit doc:job@1#kitchen-faucet --terms accepts_bids=true
hn shard publish --changed
```

**B) Providers discover & bid**

```bash
hn shard subscribe hn+mdns://jobs.local
hn view create jobs --query 'type=offer@1 AND capability="fulfill-job"'
hn doc create bid@1 --fields '{...}' && hn shard publish --changed
```

**C) Buyer selects bid → contract**

```bash
hn view create bids --query 'type=bid@1 AND job="doc:job@1#kitchen-faucet"'
hn contract accept --offer <offer-id> --with-bid <bid-id>
hn shard publish --changed
```

**D) Fulfill, attest, optional escrow (later)**

```bash
hn contract fulfill --id <contract-id>
hn rep attest --contract <contract-id> --rating 5 --note "Great job"
hn shard publish --changed
```

---

## 4) Safety & trust

* **Requirements** field enforces derived claims (L3) like `insured=true`.
* Address and contact details go encrypted in the contract.
* Negative `rep@1` hides repeat offenders (local policy).

---

## 5) Why it proves HN’s value

* Photos + voice create rich, **min-click** job posts.
* **Bids** are verifiable; **acceptance** is a signed contract.
* Works in a neighborhood without any platform operator.
