# plan@1 — Assistant Plan Document

## Purpose

`plan@1` captures an A1 assistant’s structured interpretation of a natural-language instruction. Each plan is signed by the issuing identity, can be dry-run for validation, and (eventually) executed step-by-step under policy consent.

## Fields

| Field           | Type                | Required | Description                                                         |
|-----------------|---------------------|----------|---------------------------------------------------------------------|
| `id`            | `string`            | Yes      | Canonical identifier (`plan:<alias>:<slug>`)                        |
| `prompt`        | `string`            | Yes      | Original natural-language instruction                               |
| `created_at`    | `RFC3339 timestamp` | Yes      | Timestamp when the plan was generated                               |
| `steps`         | `array`             | Yes      | Ordered list of intents and parameters                              |
| `signature`     | `base64`            | Yes      | Ed25519 signature over canonical payload                            |
| `version`       | `integer`           | Yes      | Schema version (`1`)                                                |

### Step schema

```json
{
  "intent": "contract.offer.create",
  "params": {
    "doc": "ecb07255-da4b-4d2c-a01a-9a4a0bb5e538",
    "audience": "did:hn:bob",
    "capability": "read",
    "price": 0
  }
}
```

## Canonical form & signing

Canonical payload (before applying the signature):

```json
{
  "created_at": "2025-01-01T12:00:00Z",
  "id": "plan:alice:offer-finance-folder",
  "prompt": "Offer my finance folder to Bob",
  "steps": [
    {
      "intent": "contract.offer.create",
      "params": {
        "audience": "did:hn:bob",
        "capability": "read",
        "doc": "ecb07255-da4b-4d2c-a01a-9a4a0bb5e538"
      }
    }
  ],
  "version": 1
}
```

Signature: `Base64(Ed25519Sign(private_key, canonical_json))`.

Storage: `$HN_HOME/plans/<alias>/<plan-id>.json`.

