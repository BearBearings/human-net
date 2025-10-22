# policy@1 — Policy

The `policy@1` module governs how local operators declare consent boundaries,
persist authorization state, and surface notices to peers and human operators.

## Consent Gates

- Policy documents contain a `gates` object keyed by logical action:
  - `units.write` — import or mutate unit data.
  - `contracts.propose` — originate new contract offers.
  - `contracts.fulfill` — mark contract state transitions.
  - `spend.max_eur` — hard cap for automated payments (default `0`).
- Each gate includes:
  - `mode`: `allow`, `deny`, or `prompt`.
  - `conditions`: rule expression evaluated against identity + credential
    facts (see `runtime/rule-grammar.md`).
  - `audit`: toggle to emit events for the action.
- `hn policy get` returns the active document with evaluation timestamps.
- Mutations (`hn policy patch`) require `--yes` unless operating in dry-run
  mode; payloads are validated against the JSON schema in `runtime/schemas`.

## Keys & Storage

- Policies reside under the node vault at `policy/policy@1.json`.
- Vault metadata tracks:
  - `version`: semantic version, starts at `1`.
  - `last_applied`: ISO-8601 timestamp.
  - `applied_by`: DID of the operator performing the change.
- Changes are journaled in `policy/log.jsonl` with JCS canonicalization so
  they can be replayed or inspected for audits.
- Crypto binding: policy files are signed with the node L1 key to prevent
  tampering; signature is verified on load.

## Banner Requirements

- Whenever a gate switches to `prompt`, the CLI must display a banner
  describing the required consent before executing the action.
- Banners are derived from the policy document (`gates[].banner`), fall back to
  human-readable defaults, and include:
  - actionable summary (max 140 characters),
  - references to affected contracts or units,
  - operator instructions for manual approval.
- Banners propagate to service APIs via the MCP discovery endpoint so remote
  peers can understand consent requirements prior to issuing requests.
