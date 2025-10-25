
## `usecases/_common-workflows.md`

# 🔁 Common Workflows & Ultra-Low-Friction Creation

These patterns recur across **Voting**, **Party Meet**, **Skill Exchange**, and **Mini Jobs**.
They show how to create and transact **with minimal user interaction** using **voice, agents, and photos**.

---

## 1) Core patterns

### P1. Describe → Draft → Approve

* **User:** speaks or types intent.
* **Agent:** extracts entities, proposes a doc.
* **User:** one-tap approve → publish.

**Examples**

* “Create a poll for Friday dinner.” → `vote.poll@1` + invites.
* “List my soldering service, 1 credit per hour.” → `skill@1` + `offer@1`.
* “I need a plumber, budget 120, before Nov 5.” → `job@1` + `offer@1`.

**Agent→HN command mapping (sketch)**

```
intent: create_poll → hn vote create … ; hn vote invite …
intent: publish_offer → hn offer create … ; hn shard publish --changed
intent: accept_contract → hn contract accept --offer …
```

---

### P2. Attach photos, not forms

* Snap or pick images → client computes CIDs → inserts into doc.
* Voice tags: “leaky tap”, “broken hinge” → stored as tags.

**UX**

* Camera inline → “Use these 2 photos?” → Done.

---

### P3. Proofs without PII

* Agent asks permission to reference **derived claims** (`age_over=18`, `insured=true`) from `proof@1`.
* Never reveals DOB or policy numbers.

**Policy**

```json
{"match":{"action":"projection.expose:claims"},"actions":{"allow":true}}
```

---

### P4. Contract in one tap

* Offers appear as cards → **Accept** = `contract@1` creation.
* Address/contact auto-encrypted field (optional).
* TTL and revocation built-in.

---

### P5. Publish/Subscribe auto-handoff

* After creating/accepting, the app **auto-publishes a shard** (`--changed`).
* Peers on LAN/club shard auto-subscribe and **verify receipts** in background.

---

## 2) Ultra-Short Schemas (recap)

* `profile@1`, `skill@1`, `job@1`, `offer@1`, `bid@1`, `contract@1`, `rep@1`, `vote.*@1`
* **Attachments:** `photos: ["cid:…"]`
* **Claims:** `requirements.claims: ["insured=true"]`

All **signed**, **deterministic**, and **policy-gated**.

---

## 3) Voice-first prompts (examples)

* “Create a mini job: fix a leaky kitchen faucet; budget 120 euros; deadline next Wednesday; attach last two photos.”
* “Offer 1-hour Python mentoring on Thursdays 7–9pm; rate 1 time-credit.”
* “Invite nearest guests to vote for the next song; candidates are {…}.”

The agent replies with a 1–2 line summary and a **single Confirm button**.

---

## 4) Safety rails (default)

* `id.level>=2` required for job providers if buyer requests it.
* Auto-apply TTLs (`PT24H` for party, `P3M` for jobs/contracts).
* Redaction: agent avoids exposing raw PII; shows a warning if a user tries.
* **Audit button:** “Show receipts” → displays shard index + Merkle proof.

---

## 5) Minimal UI sketch

* **Create Tab:** mic button + camera; agent summaries appear as cards with Confirm.
* **Discover Tab:** view cards (offers, polls, jobs) from subscribed shards.
* **Inbox Tab:** pending offers/contracts; one-tap Accept/Decline.
* **Profile Tab:** manage proofs & policy (“share derived claims only”), TTL defaults.

---

## 6) Developer hooks

* **Agent SDK**: callbacks to emit `hn` commands with dry-run previews.
* **Schema registry**: lightweight `runtime/schemas/*.json` for client validation.
* **Samples**: `samples/usecases/*` JSONs for instant demos.

---

## 7) Why this matters

* Keeps interactions **one or two taps**.
* Makes advanced cryptography **invisible** to users.
* Demonstrates **repeatable value** across different domains with the *same primitives*.

---

If you want, I can also generate small `samples/` JSON files for each use case so your team can run LAN demos immediately.
