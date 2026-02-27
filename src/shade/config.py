"""Shade configuration models.

Defines the shade.yml schema using Pydantic v2 models.
"""

from pathlib import Path
from typing import Self

import yaml
from pydantic import BaseModel, field_validator, model_validator

# Framework-reserved paths that user routes cannot use
RESERVED_PATHS = {"/health", "/tdx_quote", "/_auth", "/debug/ekm"}

# Framework-internal networks that user services cannot join
INTERNAL_NETWORKS = {"attestation", "auth"}


class AppRef(BaseModel):
    """Reference to the user's main app service."""

    name: str  # service name in docker-compose.yml


class ServiceRef(BaseModel):
    """A user service with explicit network connections."""

    networks: list[str] = []  # Shade network names to join (e.g., ["proxy"])


class RouteConfig(BaseModel):
    """Nginx location block. Every proxied path must be explicitly declared."""

    path: str  # e.g. "/", "/metrics", "/admin"
    service: str | None = None  # target service (default: app.name)
    port: int  # target service port
    auth_required: bool = False  # requires auth plugin enabled
    cors: bool = True  # inherit CORS settings
    websocket: bool = False  # opt-in WebSocket upgrade proxying

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("Route path must start with '/'")
        return v


class AuthPlugin(BaseModel):
    """Auth plugin. Adds auth-service + /_auth endpoint + 'auth' network."""

    enabled: bool = False


class PluginsConfig(BaseModel):
    """Plugin configuration."""

    auth: AuthPlugin = AuthPlugin()


class CorsConfig(BaseModel):
    """CORS configuration."""

    origins: list[str] = []


class TlsConfig(BaseModel):
    """TLS configuration."""

    letsencrypt_staging: bool = False
    letsencrypt_account_version: str = "v1"


class CvmConfig(BaseModel):
    """CVM (Confidential VM) configuration."""

    domain: str
    cors: CorsConfig = CorsConfig()
    tls: TlsConfig = TlsConfig()
    routes: list[RouteConfig] = []

    @model_validator(mode="after")
    def validate_routes(self) -> Self:
        paths = [r.path for r in self.routes]
        seen: set[str] = set()
        for p in paths:
            if p in seen:
                raise ValueError(f"Duplicate route path: {p}")
            seen.add(p)

        for route in self.routes:
            if route.path in RESERVED_PATHS:
                raise ValueError(
                    f"Route path '{route.path}' conflicts with framework-reserved path"
                )

        return self


class FrameworkConfig(BaseModel):
    """Framework version configuration."""

    version: str | None = None  # None = latest stable


class ShadeConfig(BaseModel):
    """Root shade.yml configuration."""

    framework: FrameworkConfig = FrameworkConfig()
    app: AppRef
    services: dict[str, ServiceRef] = {}  # user service network config
    cvm: CvmConfig
    plugins: PluginsConfig = PluginsConfig()

    @field_validator("services")
    @classmethod
    def validate_services(cls, v: dict[str, ServiceRef]) -> dict[str, ServiceRef]:
        for svc_name, svc_ref in v.items():
            for net in svc_ref.networks:
                if net in INTERNAL_NETWORKS:
                    raise ValueError(
                        f"Service '{svc_name}' cannot join framework-internal network '{net}'"
                    )
        return v

    @model_validator(mode="after")
    def validate_cross_field(self) -> Self:
        for route in self.cvm.routes:
            if route.auth_required and not self.plugins.auth.enabled:
                raise ValueError(
                    f"Route '{route.path}' has auth_required=true but auth plugin is not enabled"
                )

        for route in self.cvm.routes:
            target = route.service or self.app.name
            if target in self.services:
                if "proxy" not in self.services[target].networks:
                    raise ValueError(
                        f"Route '{route.path}' targets service '{target}' "
                        "which is not on 'proxy' network"
                    )

        if self.app.name in self.services:
            if "proxy" not in self.services[self.app.name].networks:
                raise ValueError(f"Main app service '{self.app.name}' must be on 'proxy' network")

        return self


def load_shade_config(path: str | Path) -> ShadeConfig:
    """Load and parse a shade.yml file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path) as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ValueError("Invalid shade.yml: expected a YAML mapping")

    return ShadeConfig(**raw)
