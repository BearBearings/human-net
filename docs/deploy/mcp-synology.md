# Running the MCP S1 Demo on Synology NAS

This guide shows how to bring the sprint S1 MCP server (`hn mcp serve`) onto a Synology DS-series NAS. Two approaches are documented:

1. **Docker / Container Manager (recommended)** – works on DSM 7+ for both x86_64 and ARM64 models.
2. **Native binary install** – for systems without Container Manager.

## 1. Docker Deployment

### Build a multi-arch image

Run the following on a development machine with Docker Buildx enabled:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f tooling/docker/hn-mcp.Dockerfile \
  -t human-net/hn-mcp:s1 \
  --push .
```

If you cannot push to a registry, swap `--push` for `--output type=tar,dest=hn-mcp.tar` and transfer the tarball to the NAS via `docker load`.

### Launch on Synology

1. Open **Container Manager** (or Docker) on DSM.
2. Pull the `human-net/hn-mcp:s1` image (or load the tarball).
3. Ensure your `$HN_HOME/mcp.json` (generated on first run) points at Synology paths and enables TLS + allowlist, for example:

   ```json
   {
     "listen": "0.0.0.0:7733",
     "mode": "friends",
     "max_ttl_seconds": 604800,
     "storage": "/volume1/human-net/mcp/storage",
     "tls": {
       "cert_path": "/volume1/human-net/tls/fullchain.pem",
       "key_path": "/volume1/human-net/tls/privkey.pem"
     },
     "allow": [
       {"did": "did:hn:alice", "public_key": "<base64-ed25519-pubkey>"}
     ]
   }
   ```

   Mount the TLS certificate/key pair (for example from DSM's reverse proxy or Let's Encrypt integration) into `/volume1/human-net/tls/` so the container can read it.
4. Create a container with:
   - **Command:** `hn mcp serve --listen 0.0.0.0:7733`
   - **Environment:** set `HN_HOME=/volume1/human-net` (or another shared folder).
   - **Volumes:** bind `/volume1/human-net:/var/lib/human-net` to persist config and cache.
   - **Ports:** map `7733/tcp` to the external WAN/LAN port you need.
5. Start the container and inspect the logs in Container Manager. The first run writes `mcp.json` inside the mounted volume.
6. Validate locally from a laptop on the same network:
   ```bash
   curl http://<nas-ip>:7733/healthz
   curl http://<nas-ip>:7733/index
   ```
   Both should return JSON payloads produced by the embedded server.

## 2. Native Binary Install (no Docker)

1. On a Linux/macOS build host compile statically linked binaries:
   ```bash
   cargo build --release --bin hn --bin mcp
   ```
   If the NAS is ARM-based, cross-compile with `--target aarch64-unknown-linux-gnu` (install the appropriate target via `rustup target add` first).
2. Copy the resulting binaries to the NAS, e.g. via `scp target/<target>/release/hn* nas:/usr/local/bin/`.
3. Copy the TLS certificate and key onto the NAS (e.g. `/volume1/human-net/tls/fullchain.pem` and `/volume1/human-net/tls/privkey.pem`).
4. SSH into the NAS and create the runtime directories:
   ```bash
   sudo mkdir -p /var/lib/human-net
   sudo chown $(whoami):users /var/lib/human-net
   ```
5. Edit `/var/lib/human-net/mcp.json` to point at the TLS files and configure the DID allowlist as in the Docker section above.
6. Start the service:
   ```bash
   HN_HOME=/var/lib/human-net nohup hn mcp serve --listen 0.0.0.0:7733 > /var/log/hn-mcp.log 2>&1 &
   ```
7. Validate with the same `curl` probes as the Docker workflow.

### Signing requests

In friends mode every `POST /publish` must carry signed headers. Use the local CLI to produce them from the JSON payload you plan to send:

```bash
hn mcp auth --body publish.json --alias alice > headers.json
```

This prints the `X-HN-DID`, `X-HN-Timestamp`, and `X-HN-Signature` values (plus the body digest) that must accompany the request. The timestamp is automatically generated; override it with `--timestamp` if needed. Combine the headers with a `curl` call:

```bash
curl https://<nas-host>:7733/publish \
  -H "Content-Type: application/json" \
  -H "X-HN-DID: did:hn:alice" \
  -H "X-HN-Timestamp: <value>" \
  -H "X-HN-Signature: <value>" \
  --data-binary @publish.json
```

Alternatively, run the end-to-end helper on the publishing node:

```bash
hn shard publish \
  --target ./outgoing \
  --mcp-url https://<nas-host>:7733 \
  --alias alice
```

The command writes the usual bundle to `--target` and streams the same payload to the MCP node with the correct headers.

## Next Steps

Once the service is up, pair it with a laptop vault for the S1 smoke:

```bash
hn mcp serve --config /path/to/mcp.json --listen 0.0.0.0:7733
# On the laptop (headers generated via `hn mcp auth`)
curl -X POST https://<nas-ip>:7733/publish \
  -H "Content-Type: application/json" \
  -H "X-HN-DID: ..." \
  -H "X-HN-Timestamp: ..." \
  -H "X-HN-Signature: ..." \
  --data-binary @publish.json
curl https://<nas-ip>:7733/index

# Subscribe to the Synology bundle
hn shard subscribe --mcp-url https://<nas-ip>:7733
```

Document the test results (healthz/index responses and publish acceptance) to close the sprint acceptance criteria.
