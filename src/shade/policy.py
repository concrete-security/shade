"""Policy generation helpers for Shade.

Generates Atlas-compatible policy documents from live CVM deployments.
"""

from __future__ import annotations

import json
import os
import ssl
from typing import Any
from urllib import error, request

VALID_TCB_STATUSES = [
    "UpToDate",
    "OutOfDate",
    "ConfigurationNeeded",
    "TDRelaunchAdvised",
    "SWHardeningNeeded",
    "Revoked",
]


class PolicyFetchError(RuntimeError):
    """Raised when policy retrieval or validation fails."""


def _is_valid_lowercase_hex(s: str) -> bool:
    """Check if a string is a valid non-empty lowercase hex string."""
    return bool(s) and all(c in "0123456789abcdef" for c in s)


# ---------------------------------------------------------------------------
# CVM measurement fetching
# ---------------------------------------------------------------------------


def fetch_cvm_measurements(domain: str, *, timeout: float = 30.0) -> dict[str, Any]:
    """Fetch TDX measurements and app_compose from a live CVM.

    Posts to https://{domain}/tdx_quote with a random nonce to retrieve
    bootchain measurements, OS image hash, and the full app_compose.

    .. warning:: SECURITY — UNVERIFIED MEASUREMENTS

        This function fetches data over plain HTTPS **without aTLS**.
        SSL verification is disabled (CVMs may self-sign), and the TDX
        quote is **not verified** against Intel DCAP collateral.

        All returned values (bootchain measurements, os_image_hash,
        app_compose) could be fabricated — by the CVM operator or by
        anyone who can MITM the connection.  The only field callers
        can independently verify is ``docker_compose_file`` inside
        ``app_compose`` (by comparing with the locally-built compose).

        For full verification, use Atlas aTLS (``createAtlsFetch``).

    Args:
        domain: CVM domain (e.g., "vllm.concrete-security.com").
        timeout: HTTP timeout in seconds.

    Returns:
        Dict with keys: mrtd, rtmr0, rtmr1, rtmr2, os_image_hash, app_compose.

    Raises:
        PolicyFetchError: If CVM is unreachable, response invalid, or data missing.
    """
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("domain must be a non-empty string")
    if timeout <= 0:
        raise ValueError("timeout must be > 0")

    nonce_hex = os.urandom(32).hex()

    url = f"https://{domain.strip()}/tdx_quote"
    payload = json.dumps({"nonce_hex": nonce_hex}).encode("utf-8")

    req = request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "shade-policy-generator",
        },
        method="POST",
    )

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    try:
        with request.urlopen(req, timeout=timeout, context=ssl_context) as resp:
            response_text = resp.read().decode("utf-8")
    except error.HTTPError as exc:
        raise PolicyFetchError(
            f"Failed to fetch measurements from {domain} (HTTP {exc.code})"
        ) from exc
    except error.URLError as exc:
        raise PolicyFetchError(f"Failed to connect to {domain}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise PolicyFetchError(f"Timed out connecting to {domain}") from exc

    try:
        response = json.loads(response_text)
    except json.JSONDecodeError as exc:
        raise PolicyFetchError(f"CVM at {domain} returned invalid JSON") from exc

    if not isinstance(response, dict) or not response.get("success"):
        err = response.get("error", "unknown error") if isinstance(response, dict) else ""
        raise PolicyFetchError(f"CVM at {domain} returned error: {err}")

    # Extract tcb_info
    tcb_info = response.get("tcb_info")
    if not isinstance(tcb_info, dict):
        raise PolicyFetchError(f"CVM at {domain} missing tcb_info")

    # Extract bootchain measurements
    measurements: dict[str, str] = {}
    invalid = []
    for name in ("mrtd", "rtmr0", "rtmr1", "rtmr2"):
        value = tcb_info.get(name)
        if not isinstance(value, str) or not _is_valid_lowercase_hex(value):
            invalid.append(name)
        else:
            measurements[name] = value

    if invalid:
        raise PolicyFetchError(f"CVM at {domain} has invalid measurements: {', '.join(invalid)}")

    # Extract app_compose (JSON string → dict)
    app_compose_str = tcb_info.get("app_compose")
    if not isinstance(app_compose_str, str):
        raise PolicyFetchError(f"CVM at {domain} missing tcb_info.app_compose")

    try:
        app_compose = json.loads(app_compose_str)
    except json.JSONDecodeError as exc:
        raise PolicyFetchError(f"CVM at {domain} has invalid app_compose JSON") from exc

    if not isinstance(app_compose, dict):
        raise PolicyFetchError(f"CVM at {domain} app_compose is not an object")

    # Extract os_image_hash from quote.vm_config
    quote = response.get("quote")
    if not isinstance(quote, dict):
        raise PolicyFetchError(f"CVM at {domain} missing quote")

    vm_config_str = quote.get("vm_config")
    if not isinstance(vm_config_str, str):
        raise PolicyFetchError(f"CVM at {domain} missing quote.vm_config")

    try:
        vm_config = json.loads(vm_config_str)
    except json.JSONDecodeError as exc:
        raise PolicyFetchError(f"CVM at {domain} has invalid vm_config JSON") from exc

    os_image_hash = vm_config.get("os_image_hash")
    if not isinstance(os_image_hash, str) or not _is_valid_lowercase_hex(os_image_hash):
        raise PolicyFetchError(f"CVM at {domain} has invalid os_image_hash")

    return {
        "mrtd": measurements["mrtd"],
        "rtmr0": measurements["rtmr0"],
        "rtmr1": measurements["rtmr1"],
        "rtmr2": measurements["rtmr2"],
        "os_image_hash": os_image_hash,
        "app_compose": app_compose,
    }


# ---------------------------------------------------------------------------
# Policy generation
# ---------------------------------------------------------------------------


def generate_atlas_policy(
    domain: str | None = None,
    *,
    docker_compose_file: str | None = None,
    allowed_tcb_status: list[str] | None = None,
    disable_runtime_verification: bool = False,
) -> dict[str, Any]:
    """Generate an Atlas-compatible policy for a CVM deployment.

    Production mode (domain provided): fetches measurements and app_compose
    from the CVM's /tdx_quote endpoint.

    Dev mode (disable_runtime_verification=True): skips runtime verification,
    no domain or measurements needed.

    .. warning:: SECURITY — UNVERIFIED MEASUREMENTS

        In production mode, measurements are fetched via
        ``fetch_cvm_measurements`` over plain HTTPS — the TDX quote is
        **not** verified against Intel DCAP collateral.  This means
        **all returned values** (bootchain, os_image_hash, app_compose)
        could be fabricated by the CVM operator or anyone who can MITM
        the connection.

        The **only** field you can independently verify is
        ``docker_compose_file`` inside ``app_compose``: pass your local
        compose file via the ``docker_compose_file`` parameter and this
        function will compare it against what the CVM reports.  Everything
        else (mrtd, rtmr0-2, os_image_hash) is trusted without evidence.

        For full verification of an untrusted CVM, use Atlas aTLS
        (``createAtlsFetch``) which performs DCAP quote verification
        over an attested channel.

    Args:
        domain: CVM domain to fetch measurements from (required for production).
        docker_compose_file: Local docker-compose content to verify against
            the CVM's reported app_compose.docker_compose_file. Recommended
            for production — raises ValueError on mismatch.
        allowed_tcb_status: Allowed TCB status values. Defaults to ["UpToDate"].
        disable_runtime_verification: Skip runtime checks (dev mode).

    Returns:
        Atlas policy dict ready for JSON serialization.
    """
    if allowed_tcb_status is None:
        allowed_tcb_status = ["UpToDate"]

    for status in allowed_tcb_status:
        if status not in VALID_TCB_STATUSES:
            raise ValueError(
                f"invalid TCB status '{status}', valid values are: {VALID_TCB_STATUSES}"
            )

    policy: dict[str, Any] = {
        "type": "dstack_tdx",
        "allowed_tcb_status": allowed_tcb_status,
    }

    if disable_runtime_verification:
        policy["disable_runtime_verification"] = True
    else:
        if domain is None:
            raise ValueError(
                "domain is required when disable_runtime_verification=False. "
                "Use disable_runtime_verification=True for dev mode."
            )
        measurements = fetch_cvm_measurements(domain)

        if docker_compose_file is not None:
            cvm_compose = measurements["app_compose"].get("docker_compose_file")
            if cvm_compose != docker_compose_file:
                raise ValueError(
                    "docker-compose mismatch: the CVM reports a different "
                    "docker_compose_file than the one provided locally. "
                    "The CVM may be running different code than expected."
                )

        policy["expected_bootchain"] = {
            "mrtd": measurements["mrtd"],
            "rtmr0": measurements["rtmr0"],
            "rtmr1": measurements["rtmr1"],
            "rtmr2": measurements["rtmr2"],
        }
        policy["os_image_hash"] = measurements["os_image_hash"]
        policy["app_compose"] = measurements["app_compose"]

    return policy
