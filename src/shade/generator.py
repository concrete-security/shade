"""Shade compose generator.

Takes a ShadeConfig + user compose data and produces a merged docker-compose
with all framework services wired in.
"""

import copy
import json

from shade.config import ShadeConfig
from shade.versions import get_images


def _upstream_name(service: str, port: int) -> str:
    """Generate a unique nginx upstream name for a service+port pair."""
    safe_name = service.replace("-", "_").replace(".", "_")
    return f"{safe_name}_{port}"


def _render_upstreams(config: ShadeConfig) -> str:
    """Render nginx upstream blocks from route config."""
    seen: set[str] = set()
    blocks: list[str] = []

    for route in config.cvm.routes:
        target = route.service or config.app.name
        name = _upstream_name(target, route.port)
        if name not in seen:
            seen.add(name)
            blocks.append(f"upstream {name} {{\n    server {target}:{route.port};\n}}")

    return "\n\n".join(blocks)


def _render_locations(config: ShadeConfig) -> str:
    """Render nginx location blocks from route config."""
    blocks: list[str] = []

    for route in config.cvm.routes:
        target = route.service or config.app.name
        upstream = _upstream_name(target, route.port)

        lines: list[str] = []

        # Determine location match type
        if route.path == "/":
            lines.append("    location / {")
        else:
            lines.append(f"    location {route.path} {{")

        # Auth subrequest
        if route.auth_required:
            lines.append("        auth_request /_auth;")

        # CORS headers placeholder (rendered at container startup by render_nginx_conf.py)
        if route.cors:
            lines.append("${CORS_HEADERS}")

        # Proxy configuration
        lines.append(f"        proxy_pass http://{upstream};")

        # WebSocket support (opt-in per route)
        if route.websocket:
            lines.append("        proxy_http_version 1.1;")
            lines.append("        proxy_set_header Upgrade $http_upgrade;")
            lines.append("        proxy_set_header Connection $connection_upgrade;")
            lines.append("        proxy_read_timeout 3600s;")
            lines.append("        proxy_send_timeout 3600s;")

        lines.append("        proxy_set_header Host $host;")
        lines.append("        proxy_set_header X-Real-IP $remote_addr;")
        lines.append("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
        lines.append("        proxy_set_header X-Forwarded-Proto $scheme;")
        lines.append("    }")

        blocks.append("\n".join(lines))

    return "\n\n".join(blocks)


def _escape_for_compose(value: str) -> str:
    """Escape $ signs in env var values for Docker Compose.

    Docker Compose interprets $VAR and ${VAR} in env values. We need to
    escape $ -> $$ so nginx variables ($host, $remote_addr) and template
    variables (${CORS_HEADERS}) pass through literally to the container.
    """
    return value.replace("$", "$$")


def _render_cors_origins(origins: list[str]) -> str:
    """Render CORS origins as a JSON array string for the env var."""
    if not origins:
        return "[]"
    return json.dumps(origins)


def generate(config: ShadeConfig, user_compose: dict) -> dict:
    """Generate the complete Shade docker-compose from config + user compose.

    Args:
        config: Validated ShadeConfig.
        user_compose: Parsed user docker-compose.yml data.

    Returns:
        Complete docker-compose dict ready for YAML serialization.
    """
    images = get_images(config.framework.version)
    result: dict = {"services": {}, "networks": {}, "volumes": {}}

    # ---- Copy user services ----
    user_services = user_compose.get("services", {})
    for svc_name, svc_def in user_services.items():
        svc = copy.deepcopy(svc_def)

        # Strip external ports from user services (only nginx has external ports)
        svc.pop("ports", None)

        # Apply network assignments from shade.yml
        svc_networks = set()
        if svc_name in config.services:
            svc_networks.update(config.services[svc_name].networks)
        # Auto-add main app to proxy network
        if svc_name == config.app.name:
            svc_networks.add("proxy")

        if svc_networks:
            existing_networks = svc.get("networks", [])
            if isinstance(existing_networks, list):
                merged = list(set(existing_networks) | svc_networks)
            elif isinstance(existing_networks, dict):
                merged = existing_networks.copy()
                for net in svc_networks:
                    if net not in merged:
                        merged[net] = None
            else:
                merged = list(svc_networks)
            svc["networks"] = merged

        result["services"][svc_name] = svc

    # ---- Render nginx fragments ----
    # Note: These fragments contain nginx variables ($host, $remote_addr, etc.)
    # and render_nginx_conf.py template variables (${CORS_HEADERS}).
    # Docker Compose will interpolate $VAR, so we escape $ -> $$ for all
    # nginx/template variables that should be passed through literally.
    extra_upstreams = _render_upstreams(config)
    extra_locations = _render_locations(config)

    # ---- nginx-cert-manager service ----
    nginx_networks = ["proxy", "attestation"]
    if config.plugins.auth.enabled:
        nginx_networks.append("auth")

    # Escape CORS origins regex patterns (contain $ anchors)
    cors_origins_escaped = _escape_for_compose(_render_cors_origins(config.cvm.cors.origins))

    nginx_env = [
        f"DOMAIN={config.cvm.domain}",
        f"CORS_ORIGINS={cors_origins_escaped}",
        f"AUTH_ENABLED={'true' if config.plugins.auth.enabled else 'false'}",
        "DEV_MODE=false",
        f"SKIP_LETSENCRYPT={'true' if config.cvm.tls.mode == 'self-signed' else 'false'}",
        f"LETSENCRYPT_STAGING={'true' if config.cvm.tls.letsencrypt_staging else 'false'}",
        f"LETSENCRYPT_ACCOUNT_VERSION={config.cvm.tls.letsencrypt_account_version}",
        "FORCE_RM_CERT_FILES=false",
        "LOG_LEVEL=INFO",
    ]

    # Escape nginx/template variables in fragments (contain $host, ${CORS_HEADERS}, etc.)
    if extra_upstreams:
        nginx_env.append(f"EXTRA_UPSTREAMS={_escape_for_compose(extra_upstreams)}")
    if extra_locations:
        nginx_env.append(f"EXTRA_LOCATIONS={_escape_for_compose(extra_locations)}")

    result["services"]["nginx-cert-manager"] = {
        "image": images["cert-manager"],
        "container_name": "nginx-cert-manager",
        "ports": ["80:80", "443:443"],
        "environment": nginx_env,
        "volumes": [
            "tls-certs-keys:/etc/nginx/ssl/",
            "/var/run/dstack.sock:/var/run/dstack.sock",
        ],
        "networks": nginx_networks,
        "restart": "unless-stopped",
    }

    # ---- attestation-service ----
    result["services"]["attestation-service"] = {
        "image": images["attestation-service"],
        "container_name": "attestation-service",
        "environment": [
            "HOST=0.0.0.0",
            "PORT=8080",
            "WORKERS=1",
        ],
        "volumes": ["/var/run/dstack.sock:/var/run/dstack.sock"],
        "expose": ["8080"],
        "networks": ["attestation"],
        "restart": "unless-stopped",
        "deploy": {"mode": "replicated", "replicas": 1},
    }

    # ---- auth-service (plugin) ----
    if config.plugins.auth.enabled:
        result["services"]["auth-service"] = {
            "image": images["auth-service"],
            "container_name": "auth-service",
            "environment": [
                "HOST=0.0.0.0",
                "PORT=8081",
                "AUTH_SERVICE_TOKEN=${AUTH_SERVICE_TOKEN}",
                "LOG_LEVEL=INFO",
            ],
            "expose": ["8081"],
            "networks": ["auth"],
            "restart": "unless-stopped",
        }

    # ---- Networks ----
    result["networks"]["proxy"] = {"driver": "bridge"}
    result["networks"]["attestation"] = {"driver": "bridge"}
    if config.plugins.auth.enabled:
        result["networks"]["auth"] = {"driver": "bridge"}

    # Preserve user-defined networks
    user_networks = user_compose.get("networks", {})
    for net_name, net_def in user_networks.items():
        if net_name not in result["networks"]:
            result["networks"][net_name] = net_def

    # ---- Volumes ----
    result["volumes"]["tls-certs-keys"] = None

    # Preserve user-defined volumes
    user_volumes = user_compose.get("volumes", {})
    for vol_name, vol_def in user_volumes.items():
        if vol_name not in result["volumes"]:
            result["volumes"][vol_name] = vol_def

    # ---- Configs ----
    user_configs = user_compose.get("configs", {})
    if user_configs:
        result["configs"] = {}
        for cfg_name, cfg_def in user_configs.items():
            result["configs"][cfg_name] = cfg_def

    # ---- Secrets ----
    user_secrets = user_compose.get("secrets", {})
    if user_secrets:
        result["secrets"] = {}
        for sec_name, sec_def in user_secrets.items():
            result["secrets"][sec_name] = sec_def

    return result
