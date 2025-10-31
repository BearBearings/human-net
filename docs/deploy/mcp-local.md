# Running Multiple MCP Nodes Locally

When you test federation on a single machine, each process must advertise a unique base URL and talk to the correct discovery daemon. Use the following environment variables before starting services:

```bash
export HN_PUBLIC_URL="http://127.0.0.1:8733"
export HN_DISCOVERY_URL="http://127.0.0.1:17710"
```

- `HN_PUBLIC_URL` controls the host/port embedded in presence documents and DHT hints.
- `HN_DISCOVERY_URL` makes CLI commands (e.g. `hn discover publish/resolve`) target a specific discovery daemon instead of the default `http://127.0.0.1:7710`.

For automated local federation testing, build once and invoke:

```bash
cargo build --bin hn --bin hn-discovery
cargo run --bin hn -- smoke m5
```

The smoke harness spins up one MCP and discovery daemon per user, publishes DHT hints, validates cached presence docs, and then shuts everything down. Set `HN_M5_KEEP=1` if you want it to leave per-user state behind for debugging.

For WAN-facing deployments, see [Running a Federation MCP](./federation-profile.md) which covers TLS hooks, discovery setup, and a docker-compose example.

### Trust exposure and relay sanity checks

If you want local CLI tests to serve reputation aggregates, flip the gate for your test identity:

```bash
hn policy gate set trust.exposure --mode allow --conditions target=* --yes
curl -s http://127.0.0.1:8733/trust/did:hn:bob | jq .
```

A minimal relay loop for local runs:

```bash
hn mcp relay register did:hn:alice --url http://127.0.0.1:8733
hn mcp relay push --to did:hn:alice
curl -s http://127.0.0.1:8733/relay/did:hn:alice/presence | jq .
```

Lower `HN_RELAY_TTL_SECS` before starting MCP to observe expiry quickly (the smoke harness uses `HN_RELAY_TTL_SECS=3`).

### Publishing DNS hints and resolving offline peers

When you publish a presence document with `--dht`, add `--dns-txt` to print the TXT record that operators can place in DNS:

```bash
hn discover publish \
  --merkle-root demo \
  --endpoint presence=https://node.local/.well-known/hn/presence \
  --dht --dns-txt
```

If the HTTP endpoint is temporarily offline, resolve with `--cache-fallback` to reuse the last cached document:

```bash
hn discover resolve --cache-fallback did:hn:example
```
