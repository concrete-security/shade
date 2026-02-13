"""Shade framework version registry.

Maps framework versions to container image references.
"""

# ruff: noqa: E501
VERSIONS: dict[str, dict[str, str]] = {
    "0.1.0": {
        "cert-manager": "ghcr.io/concrete-security/shade-cert-manager@sha256:1af9c4381774484be345eb6bbc6216c8020367e78b06b15c875a7fe5eb63a872",
        "attestation-service": "ghcr.io/concrete-security/shade-attestation-service@sha256:51e52f431cbae53a50b258733283199fcde983a53531f65067da8ac07b5fb7ad",
        "auth-service": "ghcr.io/concrete-security/shade-auth-service@sha256:f819c57d1648a4b4340fc296ef9872e43b70c7190d67a93820cf4f7b657d5310",
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
