# Vault Recovery & Device Pairing

This guide mirrors the flow exercised by the M4 S4 smoke test. It covers:

1. Exporting a vault identity bundle.
2. Recovering the bundle on a fresh machine.
3. Pairing the restored vault with the original so state can sync securely.

## 1. Export the Identity

```bash
# On the original device
HN_HOME=~/.human-net/alice hn id export alice --file ./alice.bundle --password passphrase
```

- The bundle is encrypted with Argon2 + ChaCha20-Poly1305 using the supplied
  password.
- Keep the file offline until you recover on the target device.

## 2. Recover on a Second Device

```bash
# Transfer alice.bundle to the new machine first
HN_HOME=~/.human-net/alice hn id recover ./alice.bundle --password passphrase --alias alice
HN_HOME=~/.human-net/alice hn id use alice
```

Recovery restores the DID document, signing keys, and vault metadata. The
`--alias` flag lets you rename the identity locally if desired.

## 3. Pair the Devices for Sync

Pairing establishes a shared X25519 secret and local inbox/outbox directories
under `~/.human-net/<alias>/nodes/<alias>/sync/<pair-id>/`.

### Step A — Generate a QR Ticket on the Original Device

```bash
HN_HOME=~/.human-net/alice hn sync pair --qr --output json
# ➜ returns {"ticket":"HNPAIR1:...","expires_at": ... }
```

Present the token as a QR code or copy the string to the secondary device.

### Step B — Accept the Ticket on the Secondary Device

```bash
HN_HOME=~/.human-net/alice hn sync pair --qr --token HNPAIR1:... --output json
# ➜ returns {"response":"HNPAIR1-RESP:...","pair":{"id":...}}
```

The response token must be relayed back to the original device.

### Step C — Finalise Pairing on the Original Device

```bash
HN_HOME=~/.human-net/alice hn sync pair --qr --token HNPAIR1-RESP:... --output json
```

Both vaults now share an inbox/outbox pair plus a stored symmetric secret. You
can verify with:

```bash
HN_HOME=~/.human-net/alice hn sync status
HN_HOME=~/.human-net/alice hn sync list
```

## 4. Sync and Verify

Use the new DX commands to move state across devices:

```bash
# Primary machine
HN_HOME=~/.human-net/alice hn sync push

# Copy bundle => secondary inbox, then
HN_HOME=~/.human-net/alice hn sync pull
HN_HOME=~/.human-net/alice hn view verify finance
```

`hn sync status` reports the last push/pull timestamps, observed remote head, and
pending inbox/outbox counts so you can see at-a-glance whether the devices are
caught up.
