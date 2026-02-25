"""Tests for shade.versions module."""

import re
from pathlib import Path

import pytest
import yaml

from shade.versions import LATEST_VERSION, VERSIONS, get_images


class TestGetImages:
    """Test version image resolution."""

    def test_latest_version(self):
        images = get_images()
        assert "cert-manager" in images
        assert "attestation-service" in images
        assert "auth-service" in images

    def test_explicit_version(self):
        images = get_images(LATEST_VERSION)
        assert "cert-manager" in images

    def test_unknown_version(self):
        with pytest.raises(ValueError, match="Unknown framework version"):
            get_images("9.9.9")

    def test_all_images_are_pinned(self):
        """All images must use a pinned tag (e.g. :sha-<hex>) or digest (@sha256:<hex>)."""
        pinned_pattern = re.compile(r"^[^@:]+(?::[^\s@]+|@sha256:[0-9a-f]{64})$")
        for version, images in VERSIONS.items():
            for service, image_ref in images.items():
                assert pinned_pattern.match(image_ref), (
                    f"Version {version} service '{service}' must be pinned: {image_ref}"
                )


class TestImageDrift:
    """Verify image refs in docker-compose.yml match versions.py."""

    COMPOSE_PATH = Path(__file__).resolve().parent.parent / "docker-compose.yml"

    SERVICE_NAME_MAP = {
        "cert-manager": ["cert-manager", "nginx-cert-manager"],
        "attestation-service": ["attestation-service"],
        "auth-service": ["auth-service"],
    }

    def test_compose_images_match_versions(self):
        compose = yaml.safe_load(self.COMPOSE_PATH.read_text(encoding="utf-8"))
        services = compose.get("services", {})

        latest_images = get_images()
        matched = 0

        for version_key, image_ref in latest_images.items():
            candidate_names = self.SERVICE_NAME_MAP.get(version_key, [version_key])

            for name in candidate_names:
                if name not in services:
                    continue
                compose_image = services[name].get("image", "")
                assert compose_image == image_ref, (
                    f"Image drift: compose service '{name}' has {compose_image} "
                    f"but versions.py has {image_ref} for '{version_key}'"
                )
                matched += 1

        assert matched > 0, "No pinned services found in docker-compose.yml to compare"
