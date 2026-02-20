"""Shade CVM Framework - TEE infrastructure for containerized apps."""

from shade.api import build, get_atlas_policy, init, validate

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "build",
    "validate",
    "init",
    "get_atlas_policy",
]
