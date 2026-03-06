# Shade

Shade is a CVM framework for putting containerized applications behind a TEE-aware
edge stack. It validates a `shade.yml` configuration, merges it with your existing
`docker-compose.yml`, and generates a complete `docker-compose.shade.yml` with:

- TLS termination and certificate management
- TDX attestation endpoints
- EKM channel binding support
- Secure reverse proxying through nginx
- Optional bearer-token auth for selected routes

## What Shade Generates

Given your application compose file plus `shade.yml`, Shade produces a full compose
stack that includes:

- your application services
- `nginx-cert-manager`
- `attestation-service`
- `auth-service` when enabled

Only nginx exposes host ports. User service `ports` are stripped from the generated
compose so traffic always enters through the framework edge.

## Repository Structure

```text
src/shade/                 Python package for the CLI, schema, and generator
services/cert-manager/     nginx, TLS, Let's Encrypt, and EKM plumbing
services/attestation-service/
                           FastAPI service for TDX quotes
services/auth-service/     bearer-token auth backend
tests/                     unit tests for the root Python package
docker-compose.yml         repository integration stack with a mock app
docker-compose.dev.override.yml
test_cvm.py                end-to-end integration test runner
```

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/)
- Docker with Compose support
- A dstack socket at `/var/run/dstack.sock` for production attestation and TEE-derived key flows

For local development and most unit tests, Docker is only needed for integration
commands and TDX hardware is not required.

## Installation

```bash
uv sync --dev
uv run shade --help
```

## Quick Start

1. Create a starter config:

```bash
uv run shade init
```

2. Add or update your application compose file. Example:

```yaml
services:
  my-app:
    image: ghcr.io/example/my-app:latest
    expose:
      - "8000"

  admin:
    image: ghcr.io/example/admin:latest
    expose:
      - "3000"
```

3. Configure Shade in `shade.yml`:

```yaml
app:
  name: my-app

services:
  admin:
    networks: [proxy]

cvm:
  domain: app.example.com
  tls:
    mode: letsencrypt
    letsencrypt_staging: false
  cors:
    origins:
      - '^https://app\.example\.com$'
  routes:
    - path: /
      port: 8000
    - path: /admin
      service: admin
      port: 3000
      auth_required: true
    - path: /ws
      port: 8000
      websocket: true

plugins:
  auth:
    enabled: true
```

4. If auth is enabled, provide a token in `.env`:

```dotenv
AUTH_SERVICE_TOKEN=replace-with-a-secret-at-least-32-characters-long
```

5. Validate and build:

```bash
uv run shade validate
uv run shade build
```

6. Start the generated stack:

```bash
docker compose -f docker-compose.shade.yml up -d
```

## CLI

```bash
uv run shade init [-d OUTPUT_DIR]
uv run shade validate [-c shade.yml] [-f docker-compose.yml]
uv run shade build [-c shade.yml] [-f docker-compose.yml] [-o docker-compose.shade.yml]
```

`shade build` validates first, then writes a generated compose file with summary
counts for services, networks, and routes.

## Configuration Reference

### Core Fields

- `app.name`: main service name from `docker-compose.yml`
- `services.<name>.networks`: extra networks for user services
- `cvm.domain`: public hostname served by nginx
- `cvm.routes[]`: explicit proxy routes
- `cvm.cors.origins`: allowed origin regexes
- `cvm.tls.mode`: `letsencrypt` or `self-signed`
- `cvm.tls.letsencrypt_staging`: use Let's Encrypt staging
- `cvm.tls.letsencrypt_account_version`: deterministic account key namespace
- `plugins.auth.enabled`: enable auth service and `/_auth` integration

### Route Fields

Each route supports:

- `path`
- `port`
- `service` (optional, defaults to `app.name`)
- `auth_required` (optional)
- `cors` (optional, defaults to `true`)
- `websocket` (optional, defaults to `false`)

### Important Rules

- Routes must start with `/`.
- Route paths must be unique.
- User routes cannot use `/health`, `/tdx_quote`, `/_auth`, or `/debug/ekm`.
- Services cannot join Shade internal networks `attestation` or `auth`.
- If a route targets a non-app service, that service must be attached to the `proxy` network in `shade.yml`.
- The main app service is auto-attached to `proxy` during generation even if it is not listed under `services`.
- `auth_required: true` requires `plugins.auth.enabled: true`.

## Generated Compose Behavior

The generator:

- copies your user services into the output
- removes user service host port mappings
- injects framework services and networks
- preserves top-level user `networks`, `volumes`, `configs`, and `secrets`
- renders nginx route and upstream fragments from `cvm.routes`
- escapes nginx/template `$` variables so Docker Compose does not interpolate them prematurely

Framework images are pinned in `src/shade/versions.py`.

## Local Development

The checked-in root compose files are for repository development and integration
testing. They run a mock application behind the framework services.

Useful commands:

```bash
# Root package tests
uv run pytest tests/ -v
make unit-tests

# Integration workflow
make dev-up
make test-all
make dev-full
make dev-down
```

`make dev-full` starts the local stack, waits for readiness, runs the end-to-end
suite in `test_cvm.py`, and then tears the stack down.

## Services

- `services/cert-manager/`: nginx config rendering, certificate lifecycle, and EKM extraction
- `services/attestation-service/`: TDX quote service; see `services/attestation-service/README.md`
- `services/auth-service/`: lightweight bearer-token auth backend for nginx auth subrequests

## Notes

- `letsencrypt` is the default TLS mode. `self-signed` skips Let's Encrypt and uses a TEE-derived self-signed certificate path instead.
- The auth service requires `AUTH_SERVICE_TOKEN`; if it is missing or too short, auth requests fail.
- The generated stack mounts `/var/run/dstack.sock` into framework services for attestation and deterministic key derivation.
