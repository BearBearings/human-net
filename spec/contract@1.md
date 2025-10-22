# contract@1 — Offer Acceptance & Execution FSM

`contract@1` materialises an accepted `offer@1` and tracks the execution of the
agreement between two peers. It is append-only: every state change is signed and
preserved for replay.

## States

| State | Description |
|-------|-------------|
| `PROPOSED` | Shell contract created alongside the offer (optional).
| `ACCEPTED` | Counterparty has accepted; resources are reserved, awaiting fulfilment.
| `FULFILLED` | Obligations completed; shard published / document transferred.
| `REVOKED` | Terminated before fulfilment (policy failure, manual abort).
| `EXPIRED` | Offer window elapsed without fulfilment.

## Events & Transitions

```text
PROPOSED --accept--> ACCEPTED
ACCEPTED --fulfill--> FULFILLED
ACCEPTED --revoke--> REVOKED
ACCEPTED --expire--> EXPIRED
PROPOSED --expire--> EXPIRED
```

Each transition emits an event document (`event@1`) containing the contract ID,
actor DID, proof reference, signature, and timestamp (implementation TBD).

## Contract Document Skeleton

```json
{
  "id": "contract:did-hn-3q6f6sfvbku5vqju3ntnhx1htuvbtwdwhwu2hrwn7la3:bob:doc-finance-folder-1:2025-10-22T15:53:35.819533Z",
  "offer_id": "offer:alice:doc-finance-folder-1:2025-10-22T15:53:35.806298Z",
  "terms_digest": "bc2b5aaa4c4189e820d47f706c6c65bf53958f3d07cc287951529b5554b5ebd6",
  "issuer": {
    "did": "did:hn:3q6f6sfvbku5vqju3ntnhx1htuvbtwdwhwu2hrwn7la3",
    "proof_id": "proof:mock-entra-ed9df68c8c65",
    "hpke_public_key": "L5sE42ExbiPH5SG61Qt6sfNKCPpCfIfHWdbK71njn1s="
  },
  "counterparty": {
    "did": "did:hn:hhdfjnbrtzq8ysreqlormubfmze96mawxj4ekhvhdt4h",
    "proof_id": "proof:mock-didkit-55f2f0230bed",
    "hpke_public_key": "ORYCATLEdseLcnaM9wQ+A5Et97PXrynDCEbSvWPd9xE="
  },
  "capability": "read",
  "doc": "doc:finance-folder@1",
  "state": "FULFILLED",
  "state_history": [
    {
      "state": "ACCEPTED",
      "event_id": "event:contract-sample:1:2025-10-22T15:53:35.819533Z",
      "sequence": 1,
      "timestamp": "2025-10-22T15:53:35.819533Z",
      "actor": "did:hn:hhdfjnbrtzq8ysreqlormubfmze96mawxj4ekhvhdt4h",
      "proof_id": "proof:mock-didkit-55f2f0230bed",
      "signature": "MEUCIQC3q9sWZsez6yTdY1qH7XH0EXAMPLEP6Tr4zVjS6hg==",
      "canonical_hash": "placeholder-reserved-hash",
      "reason": null
    },
    {
      "state": "FULFILLED",
      "event_id": "event:contract-sample:2:2025-10-22T15:53:35.830504Z",
      "sequence": 2,
      "timestamp": "2025-10-22T15:53:35.830504Z",
      "actor": "did:hn:3q6f6sfvbku5vqju3ntnhx1htuvbtwdwhwu2hrwn7la3",
      "proof_id": "proof:mock-entra-ed9df68c8c65",
      "signature": "MEQCIDztH4xGWGEXAMPLEmwmGhqyHn0UKWWHfLZL2jWNi3tAiA8xXl2YkAZ5Z==",
      "canonical_hash": "placeholder-fulfilled-hash",
      "reason": null
    }
  ],
  "encrypted_payload": {
    "hpke_suite": "X25519HkdfSha256+ChaCha20Poly1305",
    "enc": "sYFo+hFQTBAeGSpeQ+jjYDLlER6jPQ1lwVmiYuQnHSY=",
    "ciphertext": "9MwLlf2DU1R1hZicil2lTAifDFCBULIqHu099SHJURvoJWTQ/j/C9HuIrdz+2tqGp522CTltfngahqQQ77v11gh6uuvJT+1VOwgYE7hCrl1b6+aD0v1nXMxJ1i/VMiw5vG6l4xN5B1GVJQjnkpenLS+uAE68cadmNzi/VjWcShg/IObcFQCfIIF0P9O4EBeM1h6m5q0pue2UTYJm0ywAa5zkP5S945UaJ9O3dcxy5CgitZU4zFkE8wce2E5byx6BfXS6PqpiSIfBeHqbjBqUCLXjxD0FlOxN82fv3vKXy1KOd/Y9CSSuYDq59WFFFMZpo2JR7t1m1fgkcgX4thao1MPpyZGFpAQgzP45PFBNvJiP18BsiPHBMDmONNf4J91gUX8zfdmxflE0/am4Fnr1u8kjJCWgG+KCFvbPygec5tG5lFFdEHIbUD48WjuWLzVZdefliVW6edksNHCzFkjXsqp/FoYECY/lbk9ajplQDPmMfSSwmj+IYOZryOgrRkMTcgohpTZYq8dMOvMPRnjd752UKaeqtGFVelbs+9gJzxf4oyI=",
    "cid": "05407d9916ddee1c01303388458debaac86d917a8a9c1908f0053e3c380e7f8a"
  },
  "metadata": {
    "shard": {
      "payload_cid": "05407d9916ddee1c01303388458debaac86d917a8a9c1908f0053e3c380e7f8a",
      "algorithm": "ChaCha20Poly1305",
      "hpke_suite": "X25519HkdfSha256+ChaCha20Poly1305"
    },
    "retention_days": 30
  },
  "retention": {
    "archive_after": "2025-11-21T15:53:35.819533Z",
    "delete_after": null,
    "archived_at": null
  }
}
```

## Replay & Determinism

- `terms_digest` must match the originating offer before a contract is accepted.
- Every transition appends a signed `event@1` document. `state_history`
  captures the signature, canonical hash, and originating event id so replays
  can independently verify `ACCEPTED`/`FULFILLED`/`REVOKED`/`EXPIRED`
  transitions.
- Fulfilment publishes shards referencing the `contract_id`; the contract stores
  the HPKE suite, encapsulated key, ciphertext, and CID so receivers can verify
  payload provenance.
- Optional `retention` metadata drives `hn gc plan/apply --contracts`, emitting
  `archive@1` records once `archive_after` has elapsed.

## Relationship to Reputation (`rep@1`)

After `FULFILLED` or `REVOKED`, each party can append a `rep@1` entry keyed by
`contract_id`. Future offers/contracts pull reputation facts to decide whether
 to engage.
