export HN_HOME=$(mktemp -d)
hn id create smoke-tester --capability doc --endpoint discovery=hn+mdns://smoke-tester.local --yes
hn policy get > /dev/null
cat <<'JSON' > "$HN_HOME/nodes/smoke-tester/policy/policy@1.json"
{
  "version": 1,
  "gates": {
    "doc.write": { "mode": "allow", "conditions": "type=folder@1", "audit": true },
    "doc.read":  { "mode": "allow", "conditions": "type=folder@1", "audit": true }
  },
  "last_applied": "2025-01-01T00:00:00Z",
  "banners": {}
}
JSON

hn doc import  --type folder@1 --file samples/docs/folder.json --id finance-folder
hn doc replay  finance-folder
hn doc list

hn doc import  --type note@1   --file samples/docs/folder.json --id note-doc
hn policy evaluate-doc --type note@1 --file samples/docs/folder.json

hn doc view create finance --rule 'type=folder@1 AND tags:"finance"'
hn doc view list
hn doc view rows finance -o json
hn doc view snapshot finance
hn doc view delete finance

hn doc delete finance-folder