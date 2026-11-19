"""Shade framework version registry.

Maps framework versions to container image references.
"""

# ruff: noqa: E501
VERSIONS: dict[str, dict[str, str]] = {
    "0.1.0": {
        "cert-manager": "ghcr.io/concrete-security/shade-cert-manager@sha256:b65cd668293a6dda554a57bd962bdde93b3f7a64aa69b73646e05038b9f01e7f",
        "attestation-service": "ghcr.io/concrete-security/shade-attestation-service@sha256:f60286a3523732fab018fe766fad3efe07fef29c9504aaadf739ec6fc073aa60",
        "auth-service": "ghcr.io/concrete-security/shade-auth-service:sha-950ddc3",
    },
}

LATEST_VERSION = "0.1.0"


def get_images(version: str | None = None) -> dict[str, str]:
    """Get container images for a given framework version.

    Args:
        version: Framework version string. None means latest stable.

    Returns:
        Dict mapping service name to image reference.

    Raises:
        ValueError: If the version is not found.
    """
    v = version or LATEST_VERSION
    if v not in VERSIONS:
        available = ", ".join(sorted(VERSIONS.keys()))
        raise ValueError(f"Unknown framework version '{v}'. Available: {available}")
    return VERSIONS[v]
