"""Tests for shade.versions module."""

import pytest

from shade.versions import LATEST_VERSION, get_images


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
