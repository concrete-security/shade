"""Pre-flight deployment readiness checks.

Each check function returns a list of CheckResult(passed, message).
"""

import re
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path

import yaml

from shade.config import ShadeConfig
from shade.versions import get_images

_ENV_VAR_PATTERN = re.compile(r"(?<!\$)\$\{([A-Z_][A-Z0-9_]*)\}")
_ENV_VAR_WITH_DEFAULT_PATTERN = re.compile(r"(?<!\$)\$\{([A-Z_][A-Z0-9_]*):-[^}]*\}")


@dataclass
class CheckResult:
    """Result of a single deployment readiness check."""

    passed: bool
    message: str


def check_images_resolvable(config: ShadeConfig) -> list[CheckResult]:
    """Check that framework images can be resolved via docker manifest inspect."""
    results = []
    images = get_images(config.framework.version)
    for service, image in images.items():
        try:
            result = subprocess.run(
                ["docker", "manifest", "inspect", image],
                capture_output=True,
                timeout=30,
            )
            if result.returncode == 0:
                results.append(CheckResult(True, f"Framework image OK: {service}"))
            else:
                stderr = result.stderr.decode(errors="replace").lower()
                if "unauthorized" in stderr or "denied" in stderr:
                    results.append(
                        CheckResult(
                            False,
                            f"Framework image {service}: cannot verify (auth required, run 'docker login ghcr.io')",
                        )
                    )
                else:
                    results.append(
                        CheckResult(False, f"Framework image not found: {image}")
                    )
        except Exception as exc:
            results.append(CheckResult(False, f"Cannot check framework image: {image} ({exc})"))
    return results


def check_domain_resolves(config: ShadeConfig) -> list[CheckResult]:
    """Check that the configured domain is valid and resolves in DNS."""
    domain = config.cvm.domain
    try:
        socket.getaddrinfo(domain, None)
        return [CheckResult(True, f"Domain '{domain}' resolves")]
    except socket.gaierror:
        return [
            CheckResult(
                False,
                f"Domain '{domain}' does not resolve in DNS (ensure it points to your CVM)",
            )
        ]


def check_tls_production(config: ShadeConfig) -> list[CheckResult]:
    """Check that TLS is not using Let's Encrypt staging in production."""
    if config.cvm.tls.letsencrypt_staging:
        return [
            CheckResult(
                False,
                "TLS using Let's Encrypt staging (set letsencrypt_staging: false for production)",
            )
        ]
    return [CheckResult(True, "TLS configured for production")]


def _load_yaml_file(path: Path) -> dict | None:
    """Load a YAML file, returning None if it doesn't exist or is invalid."""
    if not path.exists():
        return None
    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return None


def check_generated_compose_no_dev_mode(output_path: Path) -> list[CheckResult]:
    """Check that the generated compose does not have DEV_MODE=true."""
    data = _load_yaml_file(output_path)
    if data is None:
        return [
            CheckResult(False, f"Generated compose not found at {output_path}: run 'shade build' first")
        ]
    services = data.get("services", {})
    for name, svc in services.items():
        env = svc.get("environment", {})
        if isinstance(env, dict) and env.get("DEV_MODE") == "true":
            return [CheckResult(False, f"Generated compose has DEV_MODE=true on service '{name}'")]
        if isinstance(env, list):
            for item in env:
                if item == "DEV_MODE=true":
                    return [
                        CheckResult(
                            False, f"Generated compose has DEV_MODE=true on service '{name}'"
                        )
                    ]
    return [CheckResult(True, "No DEV_MODE in generated compose")]


def check_no_build_contexts(output_path: Path) -> list[CheckResult]:
    """Check that the generated compose has no local build contexts."""
    data = _load_yaml_file(output_path)
    if data is None:
        return []
    results = []
    services = data.get("services", {})
    has_build = False
    for name, svc in services.items():
        build = svc.get("build")
        if build is None:
            continue
        has_build = True
        if isinstance(build, str):
            results.append(
                CheckResult(False, f"Service '{name}' uses local build context: {build}")
            )
        elif isinstance(build, dict) and "context" in build:
            results.append(
                CheckResult(False, f"Service '{name}' uses local build context: {build['context']}")
            )
    if not has_build:
        results.append(CheckResult(True, "All services use pre-built images"))
    return results


def check_dstack_socket_mounted(output_path: Path) -> list[CheckResult]:
    """Check that generated compose mounts /var/run/dstack.sock in prod."""
    data = _load_yaml_file(output_path)
    if data is None:
        return []
    services = data.get("services", {})
    for svc in services.values():
        volumes = svc.get("volumes", [])
        for vol in volumes:
            if isinstance(vol, str) and "dstack.sock" in vol:
                return [CheckResult(True, "dstack.sock mounted")]
            if isinstance(vol, dict) and "dstack.sock" in str(vol.get("source", "")):
                return [CheckResult(True, "dstack.sock mounted")]
    return [
        CheckResult(
            False, "Generated compose does not mount /var/run/dstack.sock (required for production)"
        )
    ]


def check_allowed_envs(output_path: Path) -> list[CheckResult]:
    """List environment variables from generated compose for Phala allowed_envs."""
    data = _load_yaml_file(output_path)
    if data is None:
        return []
    env_vars: set[str] = set()
    services = data.get("services", {})
    for svc in services.values():
        env = svc.get("environment", {})
        if isinstance(env, dict):
            env_vars.update(env.keys())
        elif isinstance(env, list):
            for item in env:
                if "=" in item:
                    env_vars.add(item.split("=", 1)[0])
    if env_vars:
        sorted_vars = sorted(env_vars)
        return [
            CheckResult(
                True,
                f"Phala allowed_envs: {', '.join(sorted_vars)}",
            )
        ]
    return []


def check_no_host_ports(user_compose: dict) -> list[CheckResult]:
    """Warn about host port mappings in user services (shade strips them)."""
    results = []
    services = user_compose.get("services", {})
    has_ports = False
    for name, svc in services.items():
        ports = svc.get("ports", [])
        if ports:
            has_ports = True
            results.append(
                CheckResult(False, f"Service '{name}' has host port mappings (will be stripped)")
            )
    if not has_ports:
        results.append(CheckResult(True, "No host port mappings in user services"))
    return results


def check_images_pinned(user_compose: dict) -> list[CheckResult]:
    """Check that user service images are pinned by digest."""
    results = []
    services = user_compose.get("services", {})
    all_ok = True
    for name, svc in services.items():
        image = svc.get("image", "")
        if not image:
            if svc.get("build"):
                all_ok = False
                results.append(
                    CheckResult(False, f"Service '{name}' uses build context, no image (not deployable remotely)")
                )
            continue
        if "@sha256:" not in image:
            all_ok = False
            results.append(CheckResult(False, f"Service '{name}' image not pinned by digest: {image}"))
    if all_ok and services:
        results.append(CheckResult(True, "All service images pinned by digest"))
    return results


def check_env_vars_defined(
    env_path: Path,
    compose_path: Path,
    output_path: Path | None = None,
) -> list[CheckResult]:
    """Check that all ${VAR} references in compose files are defined in .env."""
    env_keys: set[str] = set()
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                env_keys.add(line.split("=", 1)[0].strip())

    referenced_vars: set[str] = set()
    defaulted_vars: set[str] = set()

    paths = [compose_path]
    if output_path:
        paths.append(output_path)
    for path in paths:
        if not path.exists():
            continue
        content = path.read_text()
        defaulted_vars.update(_ENV_VAR_WITH_DEFAULT_PATTERN.findall(content))
        referenced_vars.update(_ENV_VAR_PATTERN.findall(content))

    missing = referenced_vars - defaulted_vars - env_keys
    if missing:
        results = []
        for var in sorted(missing):
            results.append(CheckResult(False, f"${{{var}}} referenced in compose but not defined in .env"))
        return results
    return [CheckResult(True, "All env vars defined")]


def run_all_checks(
    config: ShadeConfig | None = None,
    user_compose: dict | None = None,
    output_path: Path | None = None,
    env_path: Path | None = None,
    compose_path: Path | None = None,
) -> list[CheckResult]:
    """Run all pre-flight checks and return accumulated results."""
    results: list[CheckResult] = []

    if config:
        results.extend(check_images_resolvable(config))
        results.extend(check_domain_resolves(config))
        results.extend(check_tls_production(config))

    if output_path:
        results.extend(check_generated_compose_no_dev_mode(output_path))
        results.extend(check_no_build_contexts(output_path))
        results.extend(check_dstack_socket_mounted(output_path))
        results.extend(check_allowed_envs(output_path))

    if user_compose:
        results.extend(check_no_host_ports(user_compose))
        results.extend(check_images_pinned(user_compose))

    if env_path and compose_path:
        results.extend(
            check_env_vars_defined(env_path, compose_path, output_path)
        )

    return results
