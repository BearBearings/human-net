# Human.Net
A human-centered data protocol for the AI age. Core concepts: **id**, **doc**, **view**, **snapshot**, **shard**, **contract**.

This repo contains the CLI, local services, and specifications for the MVP milestones.

> **M3 (Trust & Exchange)** — Human.Net enables verifiable, encrypted peer-to-peer data exchange. L2-verified identities create offers and sign contracts that grant capabilities over docs. Payloads are published as signed shards with Merkle-verified indices, and recipients decrypt with HPKE. Everything is offline-verifiable and audit-replayable.

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
6. Tweak gate conditions without hand-editing JSON:
   ```bash
   hn policy gate set offer.create --conditions 'provider=mock-entra|mock-didkit'
   hn policy gate set contract.accept --mode prompt
   ```
5. Everything above is automated via:
   ```bash
   hn smoke m2
   ```

## M3 quickstart (Trust & Exchange)

L2 identities now exchange encrypted docs end-to-end:

1. Issue fresh proofs (offline simulators provided):
   ```bash
   hn id verify --provider mock-entra
   hn id verify --provider mock-didkit
   hn id get --with-credentials | jq '.identity.hpke'
   ```
2. Alice offers Bob access to a doc capability:
   ```bash
   hn contract offer create \
     --audience did:hn:bob... \
     --doc doc:finance-folder@1 \
     --capability read \
     --policy-ref policy:doc.read \
     --retention-days 30 \
     --emit /tmp/offer.json
   ```
3. Bob accepts and signs the contract:
   ```bash
   HN_HOME=~/.human-net-bob hn contract accept \
     --offer /tmp/offer.json \
     --emit /tmp/contract.json
   hn contract verify --offer /tmp/offer.json --contract /tmp/contract.json
   ```
4. Alice fulfils the contract, HPKE-encrypts the payload, and publishes a signed shard bundle:
   ```bash
   HN_HOME=~/.human-net-alice hn contract fulfill \
     --contract-id <contract-id> \
     --payload samples/docs/folder.json \
     --emit-shard /tmp/shard.json
   hn shard publish --target ~/drops/alice-to-bob
   ```
5. Bob subscribes, verifies the Merkle-signed index, and decrypts the shard:
   ```bash
   HN_HOME=~/.human-net-bob hn shard subscribe --source ~/drops/alice-to-bob
   HN_HOME=~/.human-net-bob hn shard verify --source ~/drops/alice-to-bob --alias bob
   HN_HOME=~/.human-net-bob hn shard fetch \
     --from ~/drops/alice-to-bob/shards/<shard-file>.json \
     --decrypt-out /tmp/decrypted.json --no-import
   ```
6. Manage contract lifecycles and audit trails:
   ```bash
   hn contract revoke --contract-id <contract-id> --reason "policy failure"
   hn contract expire sweep --dry-run
   hn audit replay --contracts
   hn gc plan --contracts
   hn gc apply --contracts
   ```

See `docs/m3/Alice_Bob_Contract_Chain.md` for the full walkthrough and
`samples/contracts/` for reproducible artefacts. A one-command regression is
available via:

```bash
hn smoke m3
```
