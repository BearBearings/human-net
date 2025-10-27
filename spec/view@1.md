# view@1 — View Definition

`view@1` captures declarative filters over signed vault docs. Definitions live under
`~/.human-net/nodes/<alias>/views/<name>/view.json` and are materialised into
receipts that can be replayed or shared across devices.

## Definition Schema

```json
{
  "name": "finance-folders",
  "rule": "type=folder@1 AND tags:\"finance\"",
  "created_at": "2024-05-22T19:22:15.814Z",
  "updated_at": "2024-05-22T19:22:15.814Z"
}
```

| Field        | Type     | Description                                                      |
| ------------ | -------- | ---------------------------------------------------------------- |
| `name`       | string   | Handle used by `hn doc view` / `hn view`. Must be `[A-Za-z0-9_-]+`. |
| `rule`       | string   | HQL-0 filter (`type=<doc@version>` with optional `AND tags:"value"`). |
| `created_at` | RFC3339  | Timestamp when the definition was created.                        |
| `updated_at` | RFC3339  | Last modification timestamp.                                      |

### HQL-0 Grammar

```
rule        = type_clause ("AND" tag_clause)*
type_clause = "type=" <doc-type>
tag_clause  = "tags:" quoted_value | "tags=" quoted_value
quoted_value = '"' <ascii text> '"'
```

Rules are conjunctive. A doc matches when the `type` equals the supplied doc type
and it carries **all** referenced tags. Order of clauses is insignificant.

## Materialisation Outputs

Running `hn view run <name>` produces:

1. A **snapshot** (`snapshot@1`) recording the rows and canonical hash.
2. A signed **materialisation receipt** binding the snapshot to the signer.

Both artefacts live alongside the definition inside
`views/<name>/snapshots/` and `views/<name>/receipts/`.

Receipt verification (`hn view verify`) recomputes the snapshot hash, checks the
Ed25519 signature against the active identity, and reports whether the current
state still matches the materialised view.
