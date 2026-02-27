# Shade

Shade is a CVM (Confidential Virtual Machine) framework that wraps any containerized application with TEE infrastructure: TLS termination, TDX attestation, EKM channel binding, and secure reverse proxying.

## Installation

```bash
pip install shade
# or with uv
uv pip install shade
```

## Quick Start

```bash
# Initialize a new project
shade init

# Build the Shade docker-compose
shade build -c shade.yml -f docker-compose.yml -o docker-compose.shade.yml

# Validate configuration
shade validate
```

## Policy Generation

Shade generates Atlas-compatible policy files that work directly with [Atlas](https://github.com/concrete-security/atlas) aTLS verification. These policies allow clients to verify CVM deployments using `createAtlsFetch({ policy })`.

### CLI Usage

**Production mode** — fetches measurements from the CVM, verifies compose:

```bash
shade policy generate \
  --domain vllm.concrete-security.com \
  --compose docker-compose.shade.yml \
  -o policy.json
```

**Dev mode** — skips runtime verification (no CVM needed):

```bash
shade policy generate --disable-runtime-verification -o policy.json
```

### CLI Options

| Option | Description |
|--------|-------------|
| `--domain` | CVM domain to fetch measurements from (required for production) |
| `--compose`, `-f` | Docker-compose file to verify against the CVM (recommended for production) |
| `--allowed-tcb-status` | Comma-separated TCB statuses (default: `UpToDate`) |
| `--disable-runtime-verification` | Skip runtime checks (dev mode) |
| `--output`, `-o` | Output file or `-` for stdout (default: `-`) |

### Python API

```python
from shade import generate_atlas_policy

# Production policy — verifies compose matches what the CVM reports
policy = generate_atlas_policy(
    domain="vllm.concrete-security.com",
    docker_compose_file=open("docker-compose.shade.yml").read(),
)

# Dev policy (no CVM needed)
dev_policy = generate_atlas_policy(disable_runtime_verification=True)
```

The returned dict is ready for `json.dumps()` and direct use with Atlas:

```javascript
import { createAtlsFetch } from "atlas-node";

const policy = JSON.parse(fs.readFileSync("policy.json", "utf-8"));
const fetch = createAtlsFetch({ target: "my-cvm.example.com", policy });
const response = await fetch("/v1/models");
// response.attestation.trusted === true
```

### How It Works

In production mode, `generate_atlas_policy(domain=...)` queries the CVM's `/tdx_quote` endpoint to fetch:

1. **Bootchain measurements** — MRTD and RTMR0-2 from `tcb_info`
2. **App compose** — full `app_compose` from `tcb_info.app_compose` (includes docker_compose_file, allowed_envs, and all dstack defaults pre-merged)
3. **OS image hash** — from `quote.vm_config`

If `--compose` is provided, the local docker-compose content is compared against `app_compose.docker_compose_file` from the CVM. A mismatch raises an error — the CVM may be running different code than expected.

When `disable_runtime_verification` is set, only the TCB status check is performed — useful for development and testing.

> **Security warning:** The `/tdx_quote` call does **not** verify the TDX quote against Intel DCAP collateral. All returned measurements (bootchain, os_image_hash) could be fabricated by the CVM operator or anyone who can MITM the connection. **The only field you can independently verify is the docker-compose file** — always pass `--compose` for production policies. For full verification of an untrusted CVM, use Atlas aTLS (`createAtlsFetch`) which performs DCAP quote verification over an attested channel.

### Valid TCB Statuses

- `UpToDate` — platform is fully patched (recommended for production)
- `SWHardeningNeeded` — software mitigations available
- `ConfigurationNeeded` — configuration changes needed
- `OutOfDate` — platform needs updates
- `TDRelaunchAdvised` — TD relaunch recommended
- `Revoked` — platform revoked

## Development

```bash
# Install dev dependencies
uv sync --group dev

# Run unit tests
uv run pytest tests/ -v

# Run integration tests (requires atlas-node + network access)
uv run pytest tests/ -m integration -v

# Lint and format
uv run ruff check
uv run ruff format --check
```

## License

See [LICENSE](LICENSE) for details.
