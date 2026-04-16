"""Tests for shade.policy module."""

from __future__ import annotations

import json
from urllib import error

import pytest

from shade.policy import (
    PolicyFetchError,
    _is_valid_lowercase_hex,
    fetch_cvm_measurements,
    generate_atlas_policy,
)


class _FakeResponse:
    def __init__(self, payload: str):
        self._payload = payload.encode("utf-8")

    def read(self) -> bytes:
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


# ---------------------------------------------------------------------------
# _is_valid_lowercase_hex
# ---------------------------------------------------------------------------


def test_is_valid_lowercase_hex_valid():
    assert _is_valid_lowercase_hex("0123456789abcdef") is True


def test_is_valid_lowercase_hex_uppercase():
    assert _is_valid_lowercase_hex("ABCDEF") is False


def test_is_valid_lowercase_hex_empty():
    assert _is_valid_lowercase_hex("") is False


def test_is_valid_lowercase_hex_non_hex():
    assert _is_valid_lowercase_hex("xyz") is False


# ---------------------------------------------------------------------------
# fetch_cvm_measurements
# ---------------------------------------------------------------------------


def test_fetch_cvm_measurements_success(monkeypatch):
    """Test successful fetch of CVM measurements."""
    fake_cvm_response = {
        "success": True,
        "tcb_info": {
            "mrtd": "aa" * 48,
            "rtmr0": "bb" * 48,
            "rtmr1": "cc" * 48,
            "rtmr2": "dd" * 48,
            "app_compose": json.dumps(
                {"docker_compose_file": "services: {}", "runner": "docker-compose"}
            ),
        },
        "quote": {
            "vm_config": json.dumps({"os_image_hash": "ee" * 32, "cpu_count": 24}),
        },
    }

    def fake_urlopen(req, timeout, context):
        assert req.full_url == "https://test.example.com/tdx_quote"
        assert req.method == "POST"
        assert timeout == 30.0
        # Verify nonce was sent
        data = json.loads(req.data.decode("utf-8"))
        assert "nonce_hex" in data
        return _FakeResponse(json.dumps(fake_cvm_response))

    monkeypatch.setattr("shade.policy.request.urlopen", fake_urlopen)

    result = fetch_cvm_measurements("test.example.com")
    assert result["mrtd"] == "aa" * 48
    assert result["rtmr0"] == "bb" * 48
    assert result["rtmr1"] == "cc" * 48
    assert result["rtmr2"] == "dd" * 48
    assert result["os_image_hash"] == "ee" * 32
    assert result["app_compose"]["docker_compose_file"] == "services: {}"
    assert result["app_compose"]["runner"] == "docker-compose"


def test_fetch_cvm_measurements_invalid_domain():
    """Test that empty domain raises ValueError."""
    with pytest.raises(ValueError, match="domain must be"):
        fetch_cvm_measurements("")


def test_fetch_cvm_measurements_connection_error(monkeypatch):
    """Test URLError raises PolicyFetchError."""

    def fake_urlopen(req, timeout, context):
        raise error.URLError("connection refused")

    monkeypatch.setattr("shade.policy.request.urlopen", fake_urlopen)

    with pytest.raises(PolicyFetchError, match="connection refused"):
        fetch_cvm_measurements("test.example.com")


def test_fetch_cvm_measurements_http_error(monkeypatch):
    """Test HTTPError raises PolicyFetchError."""

    def fake_urlopen(req, timeout, context):
        raise error.HTTPError(req.full_url, 503, "Service Unavailable", hdrs=None, fp=None)

    monkeypatch.setattr("shade.policy.request.urlopen", fake_urlopen)

    with pytest.raises(PolicyFetchError, match="HTTP 503"):
        fetch_cvm_measurements("test.example.com")


def test_fetch_cvm_measurements_invalid_json(monkeypatch):
    """Test that bad JSON raises PolicyFetchError."""

    def fake_urlopen(req, timeout, context):
        return _FakeResponse("not json {{{")

    monkeypatch.setattr("shade.policy.request.urlopen", fake_urlopen)

    with pytest.raises(PolicyFetchError, match="invalid JSON"):
        fetch_cvm_measurements("test.example.com")


def test_fetch_cvm_measurements_missing_tcb_info(monkeypatch):
    """Test missing tcb_info raises PolicyFetchError."""

    def fake_urlopen(req, timeout, context):
        return _FakeResponse(json.dumps({"success": True}))

    monkeypatch.setattr("shade.policy.request.urlopen", fake_urlopen)

    with pytest.raises(PolicyFetchError, match="missing tcb_info"):
        fetch_cvm_measurements("test.example.com")


def test_fetch_cvm_measurements_invalid_measurements(monkeypatch):
    """Test invalid measurements raise PolicyFetchError."""
    fake_cvm_response = {
        "success": True,
        "tcb_info": {
            "mrtd": "NOT_HEX",  # Invalid
            "rtmr0": "bb" * 48,
            "rtmr1": "cc" * 48,
            "rtmr2": "dd" * 48,
            "app_compose": json.dumps({"docker_compose_file": "services: {}"}),
        },
        "quote": {
            "vm_config": json.dumps({"os_image_hash": "ee" * 32}),
        },
    }

    def fake_urlopen(req, timeout, context):
        return _FakeResponse(json.dumps(fake_cvm_response))

    monkeypatch.setattr("shade.policy.request.urlopen", fake_urlopen)

    with pytest.raises(PolicyFetchError, match="invalid measurements"):
        fetch_cvm_measurements("test.example.com")


def test_fetch_cvm_measurements_invalid_app_compose(monkeypatch):
    """Test invalid app_compose raises PolicyFetchError."""
    fake_cvm_response = {
        "success": True,
        "tcb_info": {
            "mrtd": "aa" * 48,
            "rtmr0": "bb" * 48,
            "rtmr1": "cc" * 48,
            "rtmr2": "dd" * 48,
            "app_compose": "not json {{{",  # Invalid JSON
        },
        "quote": {
            "vm_config": json.dumps({"os_image_hash": "ee" * 32}),
        },
    }

    def fake_urlopen(req, timeout, context):
        return _FakeResponse(json.dumps(fake_cvm_response))

    monkeypatch.setattr("shade.policy.request.urlopen", fake_urlopen)

    with pytest.raises(PolicyFetchError, match="invalid app_compose JSON"):
        fetch_cvm_measurements("test.example.com")


def test_fetch_cvm_measurements_timeout_validation():
    """Test that timeout validation works."""
    with pytest.raises(ValueError, match="timeout must be > 0"):
        fetch_cvm_measurements("test.example.com", timeout=0)


def test_fetch_cvm_measurements_missing_os_image_hash(monkeypatch):
    """Test missing os_image_hash raises PolicyFetchError."""
    fake_cvm_response = {
        "success": True,
        "tcb_info": {
            "mrtd": "aa" * 48,
            "rtmr0": "bb" * 48,
            "rtmr1": "cc" * 48,
            "rtmr2": "dd" * 48,
            "app_compose": json.dumps({"docker_compose_file": "services: {}"}),
        },
        "quote": {
            "vm_config": json.dumps({"cpu_count": 24}),  # Missing os_image_hash
        },
    }

    def fake_urlopen(req, timeout, context):
        return _FakeResponse(json.dumps(fake_cvm_response))

    monkeypatch.setattr("shade.policy.request.urlopen", fake_urlopen)

    with pytest.raises(PolicyFetchError, match="invalid os_image_hash"):
        fetch_cvm_measurements("test.example.com")


def test_fetch_cvm_measurements_success_not_true(monkeypatch):
    """Test that success=False raises PolicyFetchError."""

    def fake_urlopen(req, timeout, context):
        return _FakeResponse(json.dumps({"success": False, "error": "test error"}))

    monkeypatch.setattr("shade.policy.request.urlopen", fake_urlopen)

    with pytest.raises(PolicyFetchError, match="test error"):
        fetch_cvm_measurements("test.example.com")


# ---------------------------------------------------------------------------
# generate_atlas_policy
# ---------------------------------------------------------------------------


def test_generate_atlas_policy_production(monkeypatch):
    """Test production mode with domain - fetches measurements."""
    fake_measurements = {
        "mrtd": "aa" * 48,
        "rtmr0": "bb" * 48,
        "rtmr1": "cc" * 48,
        "rtmr2": "dd" * 48,
        "os_image_hash": "ee" * 32,
        "app_compose": {"docker_compose_file": "services: {}", "runner": "docker-compose"},
    }

    def fake_fetch_cvm_measurements(domain, *, timeout=30.0):
        assert domain == "test.example.com"
        return fake_measurements

    monkeypatch.setattr("shade.policy.fetch_cvm_measurements", fake_fetch_cvm_measurements)

    policy = generate_atlas_policy("test.example.com")

    assert policy["type"] == "dstack_tdx"
    assert policy["allowed_tcb_status"] == ["UpToDate"]
    assert policy["expected_bootchain"]["mrtd"] == "aa" * 48
    assert policy["expected_bootchain"]["rtmr0"] == "bb" * 48
    assert policy["expected_bootchain"]["rtmr1"] == "cc" * 48
    assert policy["expected_bootchain"]["rtmr2"] == "dd" * 48
    assert policy["os_image_hash"] == "ee" * 32
    assert policy["app_compose"]["docker_compose_file"] == "services: {}"
    assert policy["app_compose"]["runner"] == "docker-compose"


def test_generate_atlas_policy_custom_tcb(monkeypatch):
    """Test custom TCB status list."""
    fake_measurements = {
        "mrtd": "aa" * 48,
        "rtmr0": "bb" * 48,
        "rtmr1": "cc" * 48,
        "rtmr2": "dd" * 48,
        "os_image_hash": "ee" * 32,
        "app_compose": {"docker_compose_file": "services: {}"},
    }

    monkeypatch.setattr(
        "shade.policy.fetch_cvm_measurements", lambda domain, *, timeout=30.0: fake_measurements
    )

    policy = generate_atlas_policy(
        "test.example.com", allowed_tcb_status=["UpToDate", "SWHardeningNeeded"]
    )
    assert policy["allowed_tcb_status"] == ["UpToDate", "SWHardeningNeeded"]


def test_generate_atlas_policy_dev_mode():
    """Test dev mode - no domain or measurements needed."""
    policy = generate_atlas_policy(disable_runtime_verification=True)

    assert policy["type"] == "dstack_tdx"
    assert policy["disable_runtime_verification"] is True
    assert "expected_bootchain" not in policy
    assert "os_image_hash" not in policy
    assert "app_compose" not in policy


def test_generate_atlas_policy_missing_domain():
    """Test that missing domain without dev mode raises ValueError."""
    with pytest.raises(ValueError, match="domain is required"):
        generate_atlas_policy()


def test_generate_atlas_policy_invalid_tcb_status():
    """Test invalid TCB status raises ValueError."""
    with pytest.raises(ValueError, match="invalid TCB status"):
        generate_atlas_policy("test.example.com", allowed_tcb_status=["UpToDate", "InvalidStatus"])


def test_generate_atlas_policy_compose_match(monkeypatch):
    """Compose verification passes when local matches CVM."""
    fake_measurements = {
        "mrtd": "aa" * 48,
        "rtmr0": "bb" * 48,
        "rtmr1": "cc" * 48,
        "rtmr2": "dd" * 48,
        "os_image_hash": "ee" * 32,
        "app_compose": {"docker_compose_file": "services:\n  app:\n    image: python:3.11\n"},
    }

    monkeypatch.setattr(
        "shade.policy.fetch_cvm_measurements", lambda domain, *, timeout=30.0: fake_measurements
    )

    policy = generate_atlas_policy(
        "test.example.com",
        docker_compose_file="services:\n  app:\n    image: python:3.11\n",
    )
    assert policy["type"] == "dstack_tdx"
    compose = policy["app_compose"]["docker_compose_file"]
    assert compose == "services:\n  app:\n    image: python:3.11\n"


def test_generate_atlas_policy_compose_mismatch(monkeypatch):
    """Compose verification fails when local differs from CVM."""
    fake_measurements = {
        "mrtd": "aa" * 48,
        "rtmr0": "bb" * 48,
        "rtmr1": "cc" * 48,
        "rtmr2": "dd" * 48,
        "os_image_hash": "ee" * 32,
        "app_compose": {"docker_compose_file": "services:\n  app:\n    image: evil:latest\n"},
    }

    monkeypatch.setattr(
        "shade.policy.fetch_cvm_measurements", lambda domain, *, timeout=30.0: fake_measurements
    )

    with pytest.raises(ValueError, match="docker-compose mismatch"):
        generate_atlas_policy(
            "test.example.com",
            docker_compose_file="services:\n  app:\n    image: python:3.11\n",
        )
