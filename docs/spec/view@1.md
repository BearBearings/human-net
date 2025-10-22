# view@1 — Local View Definition

Views live under `nodes/<alias>/views/<name>/view.json` and capture a minimal
HQL-0 rule:

```
type=folder@1 AND tags:"finance"
```

Supported predicates:
- `type=<doc-type>` (required)
- `tags:"value"` or `tags=value`

Snapshots are stored in `views/<name>/snapshots/` with canonical hashes so they
can be replayed / audited.
