"""Shade framework version registry.

Maps framework versions to container image references.
"""

# ruff: noqa: E501
VERSIONS: dict[str, dict[str, str]] = {
    "0.1.0": {
        "cert-manager": "ghcr.io/concrete-security/shade-cert-manager:sha-4786351",
        "attestation-service": "ghcr.io/concrete-security/shade-attestation-service:sha-339842a",
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
