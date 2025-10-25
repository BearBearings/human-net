
## `usecases/skill-exchange.md`

# 🧠 Skill Exchange — Time & Expertise Market on Human.Net

**Goal:** Let people trade skills (mentoring, tutoring, repair help) using **offers → contracts → shards** with time credits instead of money.
**Scope:** Works on M3 (docs, contracts, shards). Optional L2/L3 proofs to attest expertise or safety.

---

## 1) Value

* **Local-first trust:** offers and reputation are signed microdocs.
* **Cashless option:** time credits or barter (`exchange_for`).
* **Privacy by default:** no central platform; optional verified credentials (L3) for expertise.

---

## 2) Core artifacts (microdocs)

### `skill@1` — a skill profile (supply or demand)

```json
{
  "type": "skill@1",
  "@version": 1,
  "role": "offer|seek",                // I can teach X OR I'm looking for X
  "title": "Python mentoring",
  "description": "Beginner to intermediate. 60-min sessions.",
  "tags": ["python","mentoring","remote"],
  "rate": {"unit":"time-credits","value":1},  // per 60 minutes (example)
  "availability": ["Mon 18-20", "Thu 19-21"],
  "issuer": "did:hn:alice",
  "sig": "ed25519:…"
}
```

### `offer@1` (reused) — to transact a session

```json
{
  "type": "offer@1",
  "@version": 1,
  "capability": "schedule-session",
  "unit": "doc:skill@1#python-mentoring",
  "terms": {"duration_min":60,"rate":"1 time-credit"},
  "audience": ["@friends","nearby"],
  "valid_until": "2025-12-31T23:59:59Z",
  "issuer": "did:hn:alice",
  "sig": "ed25519:…"
}
```

### `contract@1` — booked session

```json
{
  "type": "contract@1",
  "@version": 1,
  "unit": "doc:skill@1#python-mentoring",
  "capability": "schedule-session",
  "state": "ACCEPTED",
  "parties": {"provider":"did:hn:alice","requester":"did:hn:bob"},
  "schedule": {"start":"2025-11-04T19:00:00Z","duration_min":60},
  "settlement": {"mode":"time-credits","amount":1},
  "sig": "ed25519:…"
}
```

### `rep@1` — post-session reputation

```json
{
  "type": "rep@1",
  "@version": 1,
  "contract": "doc:contract@1#…",
  "counterparty": "did:hn:alice",
  "rating": 5,
  "note": "Clear explanations and examples.",
  "attester": "did:hn:bob",
  "sig": "ed25519:…"
}
```

**Optional:** `proof@1` for expertise (e.g., “certified teacher”, “background check passed”), **derived claims only** (no PII).

---

## 3) Flows

**A) Publish skill**

```bash
hn doc create skill@1 --fields '{ "role":"offer","title":"Python mentoring", "rate":{"unit":"time-credits","value":1}}'
hn offer create --capability schedule-session --unit doc:skill@1#python-mentoring --terms duration_min=60,rate=1
hn shard publish --changed
```

**B) Discover & book**

```bash
hn shard subscribe hn+mdns://skills.local
hn view create nearby --query 'type=offer@1 AND capability="schedule-session"'
hn contract accept --offer <offer-id> --schedule '2025-11-04T19:00:00Z/60'
```

**C) Fulfill & review**

```bash
hn contract fulfill --id <contract-id>
hn rep attest --contract <contract-id> --rating 5 --note "Great!"
hn shard publish --changed
```

---

## 4) Safety & policy

* Require `id.level>=2` for minors or venue-hosted sessions.
* Allow `proof@1` derived claims (e.g., `background_check=true`).
* TTL cleanup of `rep@1` optional; keep anonymized aggregates.

---

## 5) Why it proves HN’s value

* Verifiable offers, bookings, and reputation — no platform.
* Cashless or paid later (M5); same contract logic.
* Fully offline-capable in small communities.

-