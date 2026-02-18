# CLAUDE.md

## Project Overview

Shade is a CVM (Confidential Virtual Machine) framework that wraps any containerized application with TEE infrastructure: TLS termination, TDX attestation, EKM channel binding, and secure reverse proxying.

It provides:
- A Python CLI (`shade build/validate/init`) that generates Docker Compose from `shade.yml` + user `docker-compose.yml`
- Pre-built services: cert-manager (nginx + Let's Encrypt + EKM), attestation-service (TDX quotes), auth-service (token auth plugin)

## Repository Structure

```
shade/
├── src/shade/           # Python package: CLI, config, generator, API
│   ├── cli.py           # Click CLI: shade build/validate/init
│   ├── config.py        # Pydantic models for shade.yml
│   ├── generator.py     # Docker Compose generator
│   ├── compose.py       # User compose loading/validation
│   ├── api.py           # Public API (build, validate, init)
│   └── versions.py      # Service image version registry
├── services/            # Service source code
│   ├── cert-manager/    # Nginx + Let's Encrypt + EKM + aTLS
│   ├── attestation-service/  # TDX attestation (FastAPI + dstack_sdk)
│   └── auth-service/    # Token-based auth (plugin)
├── tests/               # Unit tests (pytest)
├── docker-compose.yml   # Integration testing with mock app
├── docker-compose.dev.override.yml
├── test_cvm.py          # Integration test script
├── Makefile
└── pyproject.toml
```

## Build & Development Commands

```bash
# Unit tests
uv run pytest tests/ -v

# Integration tests (starts docker-compose stack with mock app)
make dev-full        # Full workflow: up, wait, test, down
make dev-up          # Start services
make dev-down        # Stop services
make test-all        # Run all integration tests

# Single test
uv run pytest tests/test_generator.py -v
```

## Code Style

- Python 3.11+, managed with `uv`
- Ruff for linting/formatting (line-length=100, 4-space indent, double quotes)
- Google docstring convention
- Conventional Commits: `feat(shade): ...`, `fix(generator): ...`

## Key Concepts

- **shade.yml**: User config declaring app name, domain, routes, plugins
- **Routes**: Explicit nginx location blocks — no implicit catch-all
- **Networks**: `proxy` (nginx <-> app), `attestation` (internal), `auth` (plugin)
- **Plugins**: auth-service is opt-in via `plugins.auth.enabled`
- **`_escape_for_compose()`**: Escapes `$` -> `$$` for nginx variables in generated compose

## Testing Notes

- Unit tests: `tests/` directory, no Docker required
- Integration tests: require Docker, use `make dev-full`
- Dev dependencies in `[dependency-groups] dev` of `pyproject.toml`
