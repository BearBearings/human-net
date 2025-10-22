# id@2 — Verified Identity Overlay

`id@2` extends the base `id@1` profile with **verified identity attestations** that
capture where a credential came from, when it was issued, and when it expires.
The goal is to make level-two (L2) trust decisions replayable without relying on
live network calls.

## Data Model

The profile gains a `verification` ledger that is serialized alongside the
existing `identity.json` record inside the vault:

```json
{
  "id": "did:hn:z82tFh...",
  "alias": "marketplace-node",
  "capabilities": ["unit:offer", "contract:fulfill"],
  "endpoints": {
    "discovery": "hn+mdns://marketplace.local"
  },
  "created_at": "2025-01-05T10:20:11Z",
  "updated_at": "2025-01-05T10:25:43Z",
  "verification": {
    "last_refreshed_at": "2025-01-05T10:25:43Z",
    "entries": [
      {
        "provider": "mock-entra",
        "issuer": "https://entra.mock/human-net",
        "proof_id": "proof:mock-entra-a1b2c3d4e5f6",
        "format": "mock_jwt",
        "verified_at": "2025-01-05T10:25:43Z",
        "expires_at": "2025-02-04T10:25:43Z"
      }
    ]
  }
}
```

### Ledger Semantics

- **`entries`** — ordered, provider-unique list of attestations.
- **`provider`** — logical verifier handle (e.g. `mock-entra`, `mock-didkit`).
- **`issuer`** — origin of the credential material.
- **`proof_id`** — pointer to the sanitized `proof@1` document written alongside
  the identity record.
- **`format`** — opaque label describing the serialization (JWT, LD proof,
  JSON fixture, etc.).
- **`verified_at`** — UTC timestamp when the credential was last fetched.
- **`expires_at`** — optional UTC expiry. `null` means "unbounded, treat as not
  cacheable".
- **`last_refreshed_at`** — convenience cursor so the vault can report the most
  recent verification event without scanning the entry list.

The ledger guarantees **provider uniqueness** by overwriting existing entries
with the same `provider`. Consumers should rely on `provider` rather than
`issuer` when performing lookups.

## Refresh Policy Helpers

`IdentityVerificationLedger::needs_refresh` offers a consistent refresh check
that other components can reuse. Its heuristics:

| Case | Result |
|------|--------|
| Entry missing | `true` |
| Entry present, `expires_at` <= `now + window` | `true` |
| Entry present, no `expires_at` | `false` |

Clients supply a `window` duration to express their freshness tolerance.

## Proof Artifacts (`proof@1`)

Every refresh that produces a new credential materializes a `proof@1` file in
`identities/<alias>/proofs/`. The ledger references these immutable artifacts via
`proof_id`; consumers load them when deeper inspection is required while keeping
PII and raw issuer payloads out of the profile. See [`proof@1`](proof@1.md) for
the canonical schema.

Each ledger emits derived **policy facts** via `to_policy_facts()`, exposing the
tuple `{provider, proof_id, issuer, valid_until}` so the policy engine and
contracts can reason over verification state without touching raw proof data.

## Provider Registry

Built-in providers are enumerated by `BuiltinVerifier`:

| Provider | Description | Default Expiry |
|----------|-------------|----------------|
| `mock-entra` | Simulates EntraID / OIDC issuer | 30 days |
| `mock-didkit` | Simulates DIDKit LD proof issuer | 90 days |

Each provider returns a fully signed `IdentityVerificationEntry`. A provider may
short-circuit and reuse an existing entry when the cache window is still fresh.
Passing `force=true` to the verification request bypasses that optimisation.

## CLI Touchpoints

- `hn id verify` invokes a provider, writes the resulting entry to disk (unless
  running with `--dry-run`), and reports whether the cache was refreshed.
- `hn id status` gives a human-readable view of the ledger, filtered by provider
  when requested.
- `hn id get --with-credentials` embeds the full ledger in JSON output so higher
  layers (policy engine, smoke tests) can make deterministic decisions.

## Deterministic Replay

Every verification event is captured by the ledger and persisted via
`IdentityVault::record_verification`. Replays simply deserialize the profile
and reconstruct the ledger, ensuring contract flows in M3 can prove which
credential path authorised the exchange.
