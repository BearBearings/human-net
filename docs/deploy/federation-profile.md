# Running a Federation MCP

The federation profile (`hn mcp serve --profile federation`) bootstraps a WAN-ready node using the same binary that powers local vaults. This guide covers the essential environment variables, discovery daemon, and a `docker-compose` quickstart for small operators.

## Environment variables

Before launching the MCP, set the base URL that peers should connect to and (optionally) point the CLI at the matching discovery daemon:

```bash
export HN_PUBLIC_URL="https://mcp.example.net:8733"
export HN_DISCOVERY_URL="http://127.0.0.1:17710"
```

- `HN_PUBLIC_URL` is embedded in presence documents, DHT hints, and DNS TXT records. When unset the profile falls back to the listen socket and logs a warning.
- `HN_DISCOVERY_URL` tells `hn discover` which daemon to use instead of the default `http://127.0.0.1:7710`.
- `HN_RELAY_TTL_SECS` limits how long relayed presences are cached (defaults to 900 seconds). The CLI flag `--relay-ttl <seconds>` provides the same override when invoking `hn mcp serve` directly.

For TLS, set `HN_TLS_CERT` and `HN_TLS_KEY` (paths relative to `$HN_HOME`) before invoking the profile; the server will automatically enable rustls with that material:

```bash
export HN_TLS_CERT="tls/fullchain.pem"
export HN_TLS_KEY="tls/privkey.pem"
```

## Launching discovery

The MCP does not start discovery on its own. Run the daemon alongside it (change ports as needed):

```bash
hn id use alice
hn-discovery --listen 0.0.0.0:17710 --service-type _human-net._tcp.local.
```

When operating multiple nodes on one machine, allocate unique ports and export the corresponding `HN_DISCOVERY_URL` before publishing hints.

The MCP now runs a background federation sync worker when the roster contains peers. Tune or disable it via:

- `HN_DISABLE_FEDERATION_WORKER=1` — opt out entirely (handy for tests or one-off manual refreshes).
- `HN_FEDERATION_SYNC_INTERVAL_SECS=120` — poll frequency (defaults to 300 seconds).
- `HN_FEDERATION_WORKER_MIRROR=1` — mirror every referenced artifact into the local cache on each cycle.

## Federation profile quickstart

The profile creates sensible defaults (public mode, seven-day TTL, `presence/latest.json`), and the federated smoke test documents how to inspect the resulting state:

```bash
hn mcp serve --profile federation --listen 0.0.0.0:8733
hn discover publish --merkle-root demo --dht --dns-txt
hn discover resolve --cache-fallback did:hn:alice
```

Run the full end-to-end scenario with:

```bash
cargo run --bin hn -- smoke m5
```

## Trust graph exposure

By default, reputation aggregates stay private. To serve them over `/trust/<did>`, enable the `trust.exposure` gate for the publishing identity:

```bash
hn policy gate set trust.exposure --mode allow --conditions target=* --yes
```

Leave `conditions` as a specific allowlist (e.g., `target=did:hn:friend`) if only certain peers should access the data. Operators should review exposure policies regularly and audit `trust/` directories before flipping the gate to `allow`.

Verify that the endpoint responds:

```bash
curl -s https://mcp.example.net:8733/trust/did:hn:friend | jq .
```

## Monitoring relay cache TTL

Relays automatically prune cached presence documents when their TTL expires. To check locally:

1. Register and push a relay for the mobile peer:

   ```bash
   hn mcp relay register did:hn:relay --url https://mcp.example.net:8733
   hn mcp relay push --to did:hn:relay
   ```

2. Fetch the cached presence:

   ```bash
   curl -s https://mcp.example.net:8733/relay/did:hn:mobile/presence | jq .
   ```

3. Wait longer than `HN_RELAY_TTL_SECS` (default 900 s). The same URL should now return `404`.

4. Push again to refresh the cache.

For test rigs, set `HN_RELAY_TTL_SECS=3` to observe expiry quickly.

## DHT/DNS resolution checklist

After publishing presence with `--dht --dns-txt`, confirm that discovery resolves via both DHT and DNS:

```bash
hn discover resolve did:hn:example            # full fetch
hn discover resolve --hint-only did:hn:example
hn discover resolve --cache-fallback did:hn:example
```

If using DNS, add the emitted TXT record (e.g., `_hn.did.example TXT "did:hn:example=https://mcp.example.net"`). When the HTTP endpoint is offline, `--cache-fallback` reuses the last signed document until a fresh presence is published.

## docker-compose snippet

```yaml
services:
  discovery:
    image: ghcr.io/human-net/hn-discovery:latest
    command: ["--listen", "0.0.0.0:17710", "--no-dht"]
    environment:
      HN_HOME: /data
    volumes:
      - ./data:/data
    network_mode: host

  mcp:
    image: ghcr.io/human-net/hn:latest
    command: ["mcp", "serve", "--profile", "federation", "--listen", "0.0.0.0:8733"]
    environment:
      HN_HOME: /data
      HN_PUBLIC_URL: https://mcp.example.net:8733
      HN_DISCOVERY_URL: http://127.0.0.1:17710
      HN_TLS_CERT: tls/fullchain.pem
      HN_TLS_KEY: tls/privkey.pem
    volumes:
      - ./data:/data
    network_mode: host
```

For systemd-based deployments, mirror the same environment variables and point services at per-node `$HN_HOME` directories.
