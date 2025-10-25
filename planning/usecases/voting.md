## `usecases/digital-voting.md`

# 🗳️ Digital Voting on Human.Net (Detachable Use Case)

**Why:** A “Doodle-but-cryptographic” poll that proves participation, protects secrecy, and allows public recounts.
**Scope:** Works on M3 (docs + offers/contracts + shards). Advanced crypto (ZK/homomorphic) can layer on later.

---

## 1) Value

* **Transparency:** Anyone can see *who voted* (DIDs) and verify counts.
* **Privacy:** Nobody can see *what* any person voted (encrypted ballots).
* **Auditability:** Recount by deterministic replay of signed indices.
* **Offline-first:** LAN operation; WAN optional later.

---

## 2) Artifacts (microdocs)

* `vote.poll@1` — poll definition (title, choices, window, audience, retention).
* `vote.right@1` — one-time eligibility token per voter (issued by organizer).
* `vote.cast@1` — the encrypted ballot (includes voter DID; choice is encrypted).
* `tally@1` — computed totals (encrypted or plaintext, depending on mode).
* `result@1` — published results (plaintext totals + reference to tally).
* `receipt@1` — subscriber verification of shards (Merkle + signature).

> Optional later: `zk.attest@1` (proof sum=1), homomorphic tally for decrypting **only** totals.

---

## 3) Flow

1. **Create poll**

   ```bash
   hn vote create --poll poll:lunch --title "Lunch" \
     --mode single --candidates thai,italian,sushi \
     --open now --close +2h --encrypt on --publish-voter-list true
   ```
2. **Invite / Issue rights**

   ```bash
   hn vote invite --poll poll:lunch --to did:hn:bob
   hn shard publish --changed
   ```
3. **Cast ballots (encrypted)**

   ```bash
   hn vote cast --poll poll:lunch --choice thai
   hn shard publish --changed
   ```
4. **Collect & tally**

   ```bash
   hn shard subscribe @friends
   hn tally compute --poll poll:lunch --method sum-single
   hn tally verify  --poll poll:lunch
   ```
5. **Publish results**

   ```bash
   hn vote publish-results --poll poll:lunch
   hn shard publish --changed
   ```

---

## 4) Privacy & Policy

* **Who voted:** `vote.cast@1.voter_did` is public → list participants.
* **What they voted:** `vote.cast@1.ballot_enc` stays encrypted.
* **One person, one vote:** `vote.right@1` is single-use; duplicates rejected.
* **Retention:** `retention.ttl` (e.g., 3 months). GC removes ballots; results remain.

---

## 5) UX ideas

* QR join, emoji ballots, live bar chart from verified indices.
* “Observers mode” that verifies Merkle signatures in real time.

---

## 6) Stretch (later)

* ZK proof (`sum(choice)=1`) without revealing candidate.
* Homomorphic encryption: decrypt only totals.
* Mixnet to unlink submission timing from voter DID.

---

## 7) Why this proves HN’s value

* Turns consent + integrity into **math**, not platform policy.
* Works peer-to-peer; no server to breach or censor.
* Clear upgrade path from casual polls → civic-grade votes.

---