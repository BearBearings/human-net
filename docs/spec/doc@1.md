# doc@1 — Signed Microdocument

`doc@1` is the container format for every locally signed microdocument. The CLI
(`hn doc …`) writes objects to `personal/docs/<type>/<id>.json` and stores:

- `id` – deterministic or random UUID
- `type` – subtype (e.g. `folder@1`, `file@1`, `note@1`)
- `content` – schema-specific payload
- `canonical_hash` – blake3 over RFC8785 canonical JSON
- `signature` – Ed25519 signature by the active identity
- `created_at` / `updated_at` – RFC3339 timestamps

Verification = recompute canonical JSON + signature check. `hn doc replay`
performs both steps and reports equality.
