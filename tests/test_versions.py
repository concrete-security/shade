"""Tests for shade.versions module."""

import re

import pytest

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

    def test_all_images_are_digest_pinned(self):
        digest_pattern = re.compile(r"^[^@]+@sha256:[0-9a-f]{64}$")
        for version, images in VERSIONS.items():
            for service, image_ref in images.items():
                assert digest_pattern.match(image_ref), (
                    f"Version {version} service '{service}' must be digest-pinned: {image_ref}"
                )
