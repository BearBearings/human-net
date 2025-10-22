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

## M2 quickstart (Docs, Policies, Views)

1. Create/activate an identity (or reuse one from M1).
2. Seed policy, then sign/import docs:
   ```bash
   hn policy get > /dev/null
   # allow only folder@1 reads/writes
   cat <<'JSON' > ~/.human-net/nodes/alice/policy/policy@1.json
   {
     "version": 1,
     "gates": {
       "doc.write": { "mode": "allow", "conditions": "type=folder@1" },
       "doc.read":  { "mode": "allow", "conditions": "type=folder@1" }
     },
     "last_applied": "2025-01-01T00:00:00Z",
     "banners": {}
   }
   JSON

   hn doc import --type folder@1 --file samples/docs/folder.json --id finance-folder
   hn doc replay finance-folder
   ```
3. Evaluate policy denials / reads:
   ```bash
   hn doc import --type note@1 --file samples/docs/folder.json --id note-doc
   hn policy evaluate-doc --type note@1 --file samples/docs/folder.json
   ```
4. Create and run views (HQL-0 rules):
   ```bash
   hn doc view create finance --rule 'type=folder@1 AND tags:"finance"'
   hn doc view rows finance -o json
   hn doc view snapshot finance
   ```
5. Everything above is automated via:
   ```bash
   hn smoke m2
   ```
