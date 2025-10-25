


## `usecases/party-meet.md`

# 🥳 Party Meet — Consentful Matching on Human.Net (Detachable Use Case)

**Why:** A fun, LAN-first social app: guests join a party network, vote on music, **opt-in matching**, and exchange intros/contracts—without a central server, data scraping, or creepy tracking.
**Scope:** M1–M3 compatible; optional L3 credentials for safety (age, venue checks).

---

## 1) Safety & Consent First

* **Opt-in profiles/prefs:** users decide *what to share* and *with whom*.
* **Pairwise DIDs:** fresh DID per intro to avoid linkability.
* **Age & safety gates:** optional **L3 derived claims** (e.g., `age_over=18`, `banlist=false`) via `proof@1`; never store raw PII in shards.
* **Short TTLs:** default auto-expire all party data (e.g., after 24h).

---

## 2) Artifacts (microdocs)

* `profile@1` — public or scoped bio (emoji, interests, pronouns, “what I’m here for”).
* `prefs@1` — private match preferences (search traits, deal-breakers).
* `meet.offer@1` — intent to connect (scope: nearby/friends; visibility and TTL).
* `meet.match@1` — computed compatibility **receipt** (local or via friend MCP), never exposes raw prefs.
* `contact.exchange@1` — a **contract@1** granting limited contact exchange (e.g., handle, DM token).
* `proof@1` — L2/L3 credentials (derived claims only: `age_over`, `student_at`, `guest_of_venue`).
* `grant@1` — **optional** PII disclosure receipt if any attribute is revealed.

> All are small, signed docs; nothing needs a server.

---

## 3) Flows

### A) Join PartyNet (LAN)

```bash
hn id create guest-43 --ep discovery=hn+mdns://party.local --yes
hn shard subscribe hn+mdns://party.local
```

### B) Publish lightweight profile

```bash
hn doc create profile@1 --fields '{ "emoji":"🪩", "interests":["house","art"], "looking":"chat" }'
hn shard publish --changed
```

### C) Private prefs (stay local; not sharded)

```bash
hn doc create prefs@1 --private --fields '{ "music":["house"], "age_over":18 }'
```

### D) Optional safety check (L3 derived claims)

```bash
hn id verify --provider didkit --store-proof    # yields proof@1
# policy requires: id.level>=2 and claims.age_over>=18 for matching
```

### E) Offer to meet (consentful)

```bash
hn doc new offer --targets doc:intro@1 --scope connect --ttl PT2H --audience nearby
hn shard publish --changed
```

### F) Matching (local-first or friend MCP)

* Local agent computes compatibility vectors from **public** signals (tags, mutual likes) + **private** prefs (never shared) → outputs `meet.match@1` receipt.
* If delegating to a friend MCP, send *only* hashed tags and opt-in traits; verify receipt on return.

### G) Introduce & exchange contact (contracted)

```bash
hn contract accept --offer <offer-id>           # forms contact.exchange@1
hn shard publish --changed                      # their device ingests it
```

### H) Auto-expire

```bash
hn policy enforce --ttl "PT24H"
hn gc plan && hn gc apply
```

---

## 4) Privacy Guarantees

* **No raw prefs** leave the device. Matching receipts carry only scores + proof they were computed from agreed signals.
* **Derived claims only** (e.g., `age_over=18`); actual DOB/address stay private.
* **Pairwise DIDs:** each intro uses a fresh DID; unlinkable across matches.
* **User-controlled TTLs:** default purge within 24h (or on exit).

---

## 5) Safety Controls

* Venue policy: require `id.level>=2` + `age_over>=18` to publish `meet.offer@1`.
* Block/report: simple `rep@1` negative attestations; local policy hides repeat offenders.
* “Do-not-disturb”: a policy flag suppresses inbound offers for a period.

---

## 6) LAN-first UX (zero setup)

* QR to join `hn+mdns://party.local`
* Emoji profile picker
* One-tap “Say hi” → emits `meet.offer@1`
* Icebreaker prompts as `doc:prompt@1` (e.g., “two truths & a lie”)
* Music vote uses the **Voting** use case (re-use `vote.*@1`)

---

## 7) Why this proves HN’s value

* **Consent by design:** every intro is a micro-contract.
* **Privacy by default:** no central DB; no mass scraping.
* **Trust knobs:** L3 claims when needed; otherwise L1 pseudonyms.
* **Portable & ephemeral:** perfect for meetups, festivals, conferences.

---

## 8) Optional Extensions

* **Afterparty circle:** convert `contact.exchange@1` into a group shard with shared photos (`post@1`).
* **Coaching agent:** suggests intros based on opt-in tags; never sees raw prefs.
* **Venue badge:** temporary `proof@1` claim “guest_of: venue@date” to filter offers.

---

## 9) Minimal CLI Smoke (demo)

```bash
# Host
hn id create host --ep discovery=hn+mdns://party.local --yes
hn shard publish --changed

# Two guests
hn id create guest-1 --ep discovery=hn+mdns://party.local --yes
hn id create guest-2 --ep discovery=hn+mdns://party.local --yes

# Profiles
hn doc create profile@1 --fields '{"emoji":"🦊","interests":["indie"],"looking":"chat"}'
hn shard publish --changed

# Offers
hn doc new offer --targets doc:intro@1 --scope connect --ttl PT2H --audience nearby

# Accept + exchange
hn contract accept --offer <offer-id>
hn shard publish --changed

# Cleanup
hn policy enforce --ttl PT24H && hn gc plan && hn gc apply
```


