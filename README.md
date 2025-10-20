# Human.Net
A human-centered data protocol for the AI age. Core concepts: **id**, **unit**, **view**, **snapshot**, **shard**, **contract**.

This repo contains the CLI, local services, and specifications for the MVP milestones.

## M1 quickstart

The CLI keeps all node state under `~/.human-net` by default. When you want to
run more than one node on the same machine (for example Alice and Bob during the
MVP smoke test) give each shell its own home:

```bash
export HN_HOME=$HOME/.human-net-alice   # in terminal A
export HN_HOME=$HOME/.human-net-bob     # in terminal B
```

### Manual workflow

1. Create and activate an identity in each shell:
   ```bash
   hn id create alice --capability unit:offer --endpoint discovery=hn+mdns://alice.local --yes
   hn id use alice
   ```
2. Start discovery (auto-selects a free port):
   ```bash
   hn service start discovery
   hn service status -o json   # running: true, listen/http show the port
   ```
3. Tail logs (options precede the service name):
   ```bash
   hn service logs --lines 50 discovery
   ```
4. On the second shell repeat for Bob. Once both services are running you can
   verify discovery:
   ```bash
   hn peer list -o json
   ```
5. Cleanup when you are done:
   ```bash
   hn service reset discovery --purge-logs
   ```

### Automated smoke test

The CLI bundles a convenience command that spins up temporary homes for Alice
and Bob, starts discovery for each, and asserts they discover one another:

```bash
hn smoke m1
```

This command is non-destructive (it uses ephemeral directories) and is the
recommended regression check before committing M1 changes.
