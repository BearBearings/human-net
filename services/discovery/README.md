# discovery

`hn-discovery` runs the LAN discovery plane for Human.Net nodes. It advertises
the active identity over mDNS, watches for other peers, stores recently seen
announcements, and surfaces the results through a lightweight HTTP API.

## Runtime behaviour

- **Identity bootstrap** – on start the daemon reads the active identity from
  the local vault (respecting `$HN_HOME` or `--home`) so that the broadcast
  advertises a real DID/alias.
- **mDNS announce/browse** – publishes `_human-net._tcp.local.` records with
  TXT metadata (`did`, `alias`, `http`, `capabilities`) and listens for other
  nodes; resolved peers are folded into the shared peer table with timestamps
  and address hints.
- **Peer table** – thread-safe store tracking peers by DID, pruning entries
  that go stale based on the configured TTL.
- **HTTP API** – exposes `GET /healthz` (uptime, peer count, self identity) and
  `GET /peers` (known peers, last-seen timestamps, advertised endpoints).

## Running locally

```bash
cargo run -p hn-discovery -- \
  --listen 0.0.0.0:7710 \
  --peer-ttl 180
```

The service logs to stdout via `tracing`. Use `RUST_LOG=debug` to inspect mDNS
events while iterating. Shut down with `Ctrl+C`; the daemon unregisters itself
and drains outstanding browse threads before exiting.
