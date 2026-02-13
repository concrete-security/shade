"""Docker Compose loading and validation utilities."""

from pathlib import Path

import yaml

from shade.config import ShadeConfig


def load_user_compose(path: str | Path) -> dict:
    """Load and parse a user's docker-compose.yml file.

    Args:
        path: Path to the docker-compose.yml file.

    Returns:
        Parsed YAML as a dict.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If the file is not valid YAML or missing 'services'.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Compose file not found: {path}")

    with open(path) as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Invalid compose file: expected a YAML mapping, got {type(data)}")

    if "services" not in data:
        raise ValueError("Compose file must have a 'services' key")

    return data


def validate_app_service(compose_data: dict, app_name: str) -> list[str]:
    """Validate that the main app service exists in the compose file.

    Returns:
        List of error messages (empty = valid).
    """
    errors: list[str] = []
    services = compose_data.get("services", {})
    if app_name not in services:
        errors.append(
            f"Main app service '{app_name}' not found in docker-compose.yml. "
            f"Available services: {', '.join(sorted(services.keys()))}"
        )
    return errors


def validate_route_services(compose_data: dict, config: ShadeConfig) -> list[str]:
    """Validate that all route target services exist in compose and have proxy network.

    Returns:
        List of error messages (empty = valid).
    """
    errors: list[str] = []
    services = compose_data.get("services", {})

    for route in config.cvm.routes:
        target = route.service or config.app.name
        if target not in services:
            errors.append(
                f"Route '{route.path}' targets service '{target}' which is not defined in "
                "docker-compose.yml"
            )

    return errors
