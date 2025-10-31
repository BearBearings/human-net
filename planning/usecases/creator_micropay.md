
## `usecases/creator-micropay.md`

# 🎵 Creator Micropay — Fair, Direct Payments on Human.Net

**Why:** Let artists, writers, or coders get paid instantly — no middlemen, no 30 % cuts, no subscriptions.
Each stream, download, or license request becomes a **signed micro-contract** with a near-zero-fee settlement.

**Scope:** M3–M6 compatible; optional L2 verification for professional IDs or legal entities.

---

## 1) Creator Sovereignty First

* **You own your vault.** Your songs, photos, or texts live as signed docs (`doc@1`, `audio@1`, `video@1`) under your DID.
* **No platform lock-in:** others cache your work via MCP federation, but the origin stays verifiable.
* **Automatic credit:** all derivative works reference the original doc hash; provenance is cryptographic.
* **Instant income:** each viewer or listener triggers a micro-payment contract directly to your vault.

---

## 2) Artifacts (microdocs)

* `doc@1` — creative asset (audio, photo, post, etc.) with metadata, rights, and price.
* `offer@1` — proposed license (e.g., *listen once = €0.005*).
* `contract@1` — signed agreement between creator and consumer.
* `payment@1` — value transfer primitive (currency, amount, channel).
* `receipt@1` — signed proof of payment + content access.
* `rep@1` — satisfaction or authenticity feedback (optional).
* `trust_link@1` — relational proof: repeated fair dealings strengthen reputation.

> Each artifact is <5 kB, signed, and auditable — not a database row.

---

## 3) Flows

### A) Publish a work

```bash
hn doc import --type audio@1 --file track.wav --title "Freedom Loop" --price 0.005
hn shard publish --alias artist
```

### B) Offer usage terms

```bash
hn contract offer create \
  --doc track.wav \
  --capability listen \
  --price 0.005 \
  --policy-ref policy:music.listen
hn shard publish --changed
```

### C) Listener discovers & accepts

```bash
hn discover resolve did:hn:artist123
hn contract accept --offer <offer-id> --emit contract.json
hn shard publish --changed
```

### D) Automatic micro-payment

```bash
hn payment send --contract contract.json --amount 0.005 --currency EUR
hn shard publish --changed
```

### E) Receipt and reputation update

```bash
hn receipt create --contract contract.json --status success
hn trust update --peer did:hn:artist123 --based-on contract.json,payment.json
```

---

## 4) Privacy & Fairness Guarantees

* **No global ledger:** payments settle P2P or via light relay MCPs — no public transaction trace.
* **Mutual receipts:** both vaults hold identical `payment@1` and `receipt@1` docs.
* **Fraud-proof:** every transfer references the original contract + DID signatures.
* **Dynamic pricing:** artist can update `offer@1` TTLs; new contracts use new terms.
* **Anonymous support:** fans may pay via throwaway DIDs; artist still gets verified funds.

---

## 5) Reputation & Trust Graphs

* Each successful transaction adds a `trust_link@1` (proof of cooperation).
* Repeat buyers automatically raise confidence levels.
* Artists can publish anonymized aggregates (`reputation@1`) for discovery ranking.
* No stars, no likes — just verified history.

---

## 6) Wallet Integration

* **Local mode:** payment settles via device wallet (bank API, crypto bridge, or stored balance).
* **Relay mode:** if payer is offline, a trusted MCP relay holds the escrow for ≤ 24 h.
* **Currency bridge:** MCPs may host fiat/crypto adapters — still zero-fee within Human.Net.

Example adapter stub:

```bash
hn wallet connect --provider sepa-local
hn payment send --to did:hn:artist123 --amount 0.005 --currency EUR
```

---

## 7) Optional Extensions

* **Subscriptions:** repeated `payment@1` on schedule (e.g., weekly tip jar).
* **Crowdfund pools:** group `contract@1` objects into a shared `fund@1`.
* **AI royalties:** derivative AIs attach `usage@1` shards referencing training data.
* **Local markets:** cafés or venues run a federation MCP to showcase nearby artists.

---

## 8) Why This Proves HN’s Value

* **Zero friction:** true 1 ppm transaction cost — impossible on legacy rails.
* **Direct reward:** no intermediaries, no algorithmic throttling.
* **Proof of origin:** digital ownership finally has mathematical backing.
* **Resilient income:** even 100 micro-payments/day create real revenue for small creators.
* **Cultural sustainability:** local art stays local, yet globally verifiable.

---

## 9) Minimal CLI Smoke (demo)

```bash
# Artist
hn id create artist --yes
hn doc import --type audio@1 --file sample.wav --price 0.005
hn shard publish --alias artist
hn contract offer create --doc sample.wav --price 0.005 --emit offer.json
hn shard publish --changed

# Listener
hn id create listener --yes
hn contract accept --offer offer.json --emit contract.json
hn payment send --contract contract.json --amount 0.005
hn receipt create --contract contract.json --status success
hn trust update --peer did:hn:artist --based-on contract.json,payment.json
```

---

## 10) Example Policy

```json
{
  "policy:music.listen": {
    "requires": ["id.level>=1"],
    "grants": ["listen_once"],
    "expires": "PT1H",
    "price": 0.005
  }
}
```

---

## 11) Future Links (M6+)

* Integrate `payment@1` into LLM-generated plans (`plan@1` → `contract@1` → `payment@1`).
* Add multi-currency support and instant trust reconciliation.
* Enable federated analytics (aggregate plays/payments without leaking users).

---

### 🧩 Why it Matters

> Human.Net makes art a direct, living relationship again —
> **a conversation of trust and value between creator and listener.**

---

Would you like me to add a short JSON schema appendix for `payment@1` and `receipt@1` (like the ones in the other use cases) so it’s ready to integrate into the `/spec/` folder next?
