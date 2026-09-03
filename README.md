# Mneme Server

The small, self-hosted encrypted-backup target for **Mneme: Private Journal**.
Mneme encrypts diary manifests and original photos on the Android device before
uploading them. The server stores opaque ciphertext and does not have the
recovery key.

This server is optional. Mneme also supports user-selected encrypted folders
and readable ZIP exports without operating a shared Mneme cloud.

## Quick start with Docker Compose

```bash
curl -LO https://raw.githubusercontent.com/LainsMain/mneme-server/main/compose.yaml
curl -Lo stack.env https://raw.githubusercontent.com/LainsMain/mneme-server/main/stack.env.example
docker compose --env-file stack.env up -d
docker compose exec mneme-server /mneme token create --name "My phone"
```

The final command prints the app token once. In Mneme, open **Settings →
Advanced → Self-hosted backup**, enter the HTTPS URL and token, and test the
connection. The default host port is `8181`, avoiding the commonly occupied
port `8080`.

### Portainer

Create a Stack, paste [compose.yaml](compose.yaml), and load
[`stack.env.example`](stack.env.example) as `stack.env` or add the same
variables in Portainer. Deploy the stack, then open the `mneme-server`
container console and run:

```text
/mneme token create --name "My phone"
```

Use `/mneme token list` and `/mneme token revoke TOKEN_ID` to manage devices.

## Cloudflare Tunnel

Cloudflare Tunnel is not bundled or required. An existing `cloudflared` stack
can route a public hostname to the server. Either:

- join the tunnel container to the external `mneme-backup` Docker network and
  route to `http://mneme-server:8080`; or
- set `MNEME_BIND_ADDRESS=0.0.0.0`, protect port 8181 with the host firewall,
  and route the tunnel to `http://HOST_LAN_IP:8181`.

Do not expose the API directly to the public internet over plain HTTP. The
Mneme app accepts HTTPS, except for emulator loopback in debug builds.

## Data, backup, and restore

The named `mneme-server-data` volume contains:

- a SQLite catalog of device tokens and ciphertext references;
- encrypted manifests; and
- encrypted content-addressed photo objects.

Back up this Docker volume as part of normal host administration. Restoring
the volume restores tokens and uploaded ciphertext. Restoring diary content to
a phone additionally requires the recovery code shown by the Mneme app; the
server cannot recreate it.

Mneme retains manifest history and can request conservative garbage collection
from its Advanced settings. Ciphertext is never interpreted by the server.

## Updating without losing data

```bash
docker compose --env-file stack.env pull mneme-server
docker compose --env-file stack.env up -d mneme-server
docker compose --env-file stack.env ps
```

Image updates leave the named data volume intact. Pin `MNEME_IMAGE` to a
version such as `lainsmain/mneme-server:0.3.5` when you prefer controlled
upgrades. Images are published for AMD64 and ARM64.

## API and development

The stable Android compatibility contract is API version 1. Semantic server
versions are independent from Android app releases. See
[`api/openapi.yaml`](api/openapi.yaml).

```bash
go test ./...
go run ./cmd/mneme serve
```

Environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `MNEME_DATA_DIR` | `/data` | Database and ciphertext directory |
| `MNEME_LISTEN` | `:8080` | HTTP listen address inside the container |

## Security

Tokens are random bearer credentials; only Argon2id-derived hashes are stored.
Treat a plaintext token like a password and revoke it if exposed. Report
security issues privately as described in [SECURITY.md](SECURITY.md).

Mneme Server is available under the [MIT License](LICENSE).
