"""Shade framework version registry.

Maps framework versions to container image references.
"""

# ruff: noqa: E501
VERSIONS: dict[str, dict[str, str]] = {
    "0.1.0": {
        "cert-manager": "ghcr.io/concrete-security/shade-cert-manager@sha256:3ddc9bba61c86dc54884f41fb6b7a192f3ec60b0ff8ef860882006ddac7f22f8",
        "attestation-service": "ghcr.io/concrete-security/shade-attestation-service@sha256:62e4692069e021f1612542e9aefd4e33f390b84a4fab0230ef01aca3e354365b",
        "auth-service": "ghcr.io/concrete-security/shade-auth-service@sha256:2582b97055c60a24ab368822d12e1ac29ca74ca99fc9384c7807840ccd96c5e6",
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
