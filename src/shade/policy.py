"""Policy retrieval helpers for Shade.

Fetches Atlas-compatible policy JSON documents from source repositories.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib import error, parse, request

DEFAULT_POLICY_BASE_URL = "https://raw.githubusercontent.com"
DEFAULT_POLICY_PATH_TEMPLATE = "cvm/policies/{cvm}/atlas-policy.json"

_REPO_PART = re.compile(r"^[A-Za-z0-9._-]+$")
_CVM_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


class PolicyFetchError(RuntimeError):
    """Raised when policy retrieval or validation fails."""


@dataclass(frozen=True)
class AtlasPolicyFetchResult:
    """Resolved metadata + policy content returned by fetch_atlas_policy()."""

    repo: str
    cvm: str
    ref: str
    policy_path: str
    url: str
    policy: dict[str, Any]


def _validate_repo(repo: str) -> None:
    if not isinstance(repo, str):
        raise ValueError("repo must be a string in 'owner/repo' format")
    parts = repo.split("/")
    if len(parts) != 2 or not all(parts):
        raise ValueError("repo must be in 'owner/repo' format")
    if not _REPO_PART.fullmatch(parts[0]) or not _REPO_PART.fullmatch(parts[1]):
        raise ValueError("repo contains invalid characters")


def _validate_cvm(cvm: str) -> None:
    if not isinstance(cvm, str) or not cvm.strip():
        raise ValueError("cvm must be a non-empty string")
    if not _CVM_NAME.fullmatch(cvm):
        raise ValueError("cvm contains invalid characters")


def _resolve_policy_path(path_template: str, cvm: str) -> str:
    if not isinstance(path_template, str) or not path_template.strip():
        raise ValueError("path_template must be a non-empty string")

    try:
        path = path_template.format(cvm=cvm)
    except KeyError as exc:
        raise ValueError("path_template can only use the '{cvm}' placeholder") from exc

    path = path.strip().lstrip("/")
    if not path:
        raise ValueError("resolved policy path cannot be empty")

    segments = path.split("/")
    if any(segment in {".", ".."} or segment == "" for segment in segments):
        raise ValueError("resolved policy path must not contain empty, '.' or '..' segments")

    return path


def build_policy_url(
    repo: str,
    cvm: str,
    ref: str = "main",
    *,
    path_template: str = DEFAULT_POLICY_PATH_TEMPLATE,
    base_url: str = DEFAULT_POLICY_BASE_URL,
) -> tuple[str, str]:
    """Build the raw URL for a policy in a target repo/cvm/ref."""
    _validate_repo(repo)
    _validate_cvm(cvm)

    if not isinstance(ref, str) or not ref.strip():
        raise ValueError("ref must be a non-empty string")
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError("base_url must be a non-empty string")

    policy_path = _resolve_policy_path(path_template, cvm)

    owner, name = repo.split("/", 1)
    owner_enc = parse.quote(owner, safe="")
    name_enc = parse.quote(name, safe="")
    ref_enc = parse.quote(ref.strip(), safe="")
    path_enc = "/".join(parse.quote(segment, safe="") for segment in policy_path.split("/"))

    url = f"{base_url.rstrip('/')}/{owner_enc}/{name_enc}/{ref_enc}/{path_enc}"
    return policy_path, url


def validate_atlas_policy_shape(policy: dict[str, Any]) -> list[str]:
    """Run lightweight Atlas policy shape checks."""
    errors: list[str] = []

    if policy.get("type") != "dstack_tdx":
        errors.append("policy.type must be 'dstack_tdx'")

    allowed = policy.get("allowed_tcb_status")
    if allowed is not None:
        if not isinstance(allowed, list) or not all(isinstance(item, str) for item in allowed):
            errors.append("policy.allowed_tcb_status must be a list of strings")

    bootchain = policy.get("expected_bootchain")
    if bootchain is not None:
        if not isinstance(bootchain, dict):
            errors.append("policy.expected_bootchain must be an object")
        else:
            for key in ("mrtd", "rtmr0", "rtmr1", "rtmr2"):
                value = bootchain.get(key)
                if value is not None and not isinstance(value, str):
                    errors.append(f"policy.expected_bootchain.{key} must be a string")

    app_compose = policy.get("app_compose")
    if app_compose is not None:
        if not isinstance(app_compose, dict):
            errors.append("policy.app_compose must be an object")
        elif not isinstance(app_compose.get("docker_compose_file"), str):
            errors.append("policy.app_compose.docker_compose_file must be a string")

    os_image_hash = policy.get("os_image_hash")
    if os_image_hash is not None and not isinstance(os_image_hash, str):
        errors.append("policy.os_image_hash must be a string")

    return errors


def _fetch_json_object(url: str, timeout: float) -> dict[str, Any]:
    req = request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "shade-policy-fetcher",
        },
        method="GET",
    )

    try:
        with request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read().decode("utf-8")
    except error.HTTPError as exc:
        raise PolicyFetchError(f"Failed to fetch policy (HTTP {exc.code}) from {url}") from exc
    except error.URLError as exc:
        raise PolicyFetchError(f"Failed to fetch policy from {url}: {exc.reason}") from exc
    except TimeoutError as exc:  # pragma: no cover - defensive
        raise PolicyFetchError(f"Timed out fetching policy from {url}") from exc

    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise PolicyFetchError(f"Policy document at {url} is not valid JSON") from exc

    if not isinstance(parsed, dict):
        raise PolicyFetchError(f"Policy document at {url} must be a JSON object")

    return parsed


def fetch_atlas_policy(
    repo: str,
    cvm: str,
    ref: str = "main",
    *,
    path_template: str = DEFAULT_POLICY_PATH_TEMPLATE,
    base_url: str = DEFAULT_POLICY_BASE_URL,
    timeout: float = 20.0,
    validate_shape: bool = True,
) -> AtlasPolicyFetchResult:
    """Fetch an Atlas policy for a specific repo + CVM target."""
    if timeout <= 0:
        raise ValueError("timeout must be > 0")

    policy_path, url = build_policy_url(
        repo=repo,
        cvm=cvm,
        ref=ref,
        path_template=path_template,
        base_url=base_url,
    )
    policy = _fetch_json_object(url=url, timeout=timeout)

    if validate_shape:
        errors = validate_atlas_policy_shape(policy)
        if errors:
            raise PolicyFetchError("Invalid Atlas policy shape: " + " | ".join(errors))

    return AtlasPolicyFetchResult(
        repo=repo,
        cvm=cvm,
        ref=ref,
        policy_path=policy_path,
        url=url,
        policy=policy,
    )
