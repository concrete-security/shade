"""Tests for shade.policy module."""

from __future__ import annotations

import json
from urllib import error

import pytest

from shade.policy import (
    DEFAULT_POLICY_BASE_URL,
    VALID_TCB_STATUSES,
    AtlasPolicyFetchResult,
    PolicyFetchError,
    _is_valid_lowercase_hex,
    build_policy_url,
    fetch_atlas_policy,
    fetch_cvm_measurements,
    generate_atlas_policy,
    validate_atlas_policy_shape,
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
# build_policy_url
# ---------------------------------------------------------------------------


def test_build_policy_url_defaults():
    policy_path, url = build_policy_url(repo="acme/demo", cvm="dev")
    assert policy_path == "cvm/policies/dev/atlas-policy.json"
    assert url == f"{DEFAULT_POLICY_BASE_URL}/acme/demo/main/cvm/policies/dev/atlas-policy.json"


def test_build_policy_url_encodes_ref():
    _, url = build_policy_url(repo="acme/demo", cvm="prod", ref="feature/hardening")
    assert "/feature%2Fhardening/" in url


def test_build_policy_url_rejects_invalid_repo():
    with pytest.raises(ValueError, match="owner/repo"):
        build_policy_url(repo="bad-repo", cvm="dev")


def test_build_policy_url_rejects_non_string_repo():
    with pytest.raises(ValueError, match="owner/repo"):
        build_policy_url(repo=123, cvm="dev")


def test_build_policy_url_rejects_repo_invalid_chars():
    with pytest.raises(ValueError, match="invalid characters"):
        build_policy_url(repo="ac me/de mo", cvm="dev")


def test_build_policy_url_rejects_empty_cvm():
    with pytest.raises(ValueError, match="non-empty string"):
        build_policy_url(repo="acme/demo", cvm="")


def test_build_policy_url_rejects_cvm_invalid_chars():
    with pytest.raises(ValueError, match="invalid characters"):
        build_policy_url(repo="acme/demo", cvm="bad name!")


def test_build_policy_url_rejects_empty_path_template():
    with pytest.raises(ValueError, match="non-empty string"):
        build_policy_url(repo="acme/demo", cvm="dev", path_template="")


def test_build_policy_url_rejects_bad_placeholder():
    with pytest.raises(ValueError, match="placeholder"):
        build_policy_url(repo="acme/demo", cvm="dev", path_template="{bad}/policy.json")


def test_build_policy_url_rejects_empty_resolved_path():
    with pytest.raises(ValueError, match="cannot be empty"):
        build_policy_url(repo="acme/demo", cvm="dev", path_template="/", ref="main")


def test_build_policy_url_rejects_dotdot_segment():
    with pytest.raises(ValueError, match="must not contain"):
        build_policy_url(repo="acme/demo", cvm="dev", path_template="../{cvm}/policy.json")


def test_build_policy_url_rejects_empty_ref():
    with pytest.raises(ValueError, match="ref must be"):
        build_policy_url(repo="acme/demo", cvm="dev", ref="")


def test_build_policy_url_rejects_empty_base_url():
    with pytest.raises(ValueError, match="base_url must be"):
        build_policy_url(repo="acme/demo", cvm="dev", base_url="")


# ---------------------------------------------------------------------------
# validate_atlas_policy_shape
# ---------------------------------------------------------------------------


def test_validate_atlas_policy_shape():
    errors = validate_atlas_policy_shape(
        {
            "type": "dstack_tdx",
            "allowed_tcb_status": ["UpToDate"],
            "app_compose": {"docker_compose_file": "services: {}"},
        }
    )
    assert errors == []


def test_validate_shape_invalid_tcb_status():
    errors = validate_atlas_policy_shape({"type": "dstack_tdx", "allowed_tcb_status": 42})
    assert any("allowed_tcb_status" in e for e in errors)


def test_validate_shape_invalid_tcb_status_value():
    errors = validate_atlas_policy_shape(
        {"type": "dstack_tdx", "allowed_tcb_status": ["InvalidStatus"]}
    )
    assert any("invalid value 'InvalidStatus'" in e for e in errors)


def test_validate_shape_all_valid_tcb_statuses():
    errors = validate_atlas_policy_shape(
        {"type": "dstack_tdx", "allowed_tcb_status": VALID_TCB_STATUSES}
    )
    assert errors == []


def test_validate_shape_invalid_bootchain_not_dict():
    errors = validate_atlas_policy_shape({"type": "dstack_tdx", "expected_bootchain": "bad"})
    assert any("expected_bootchain must be an object" in e for e in errors)


def test_validate_shape_invalid_bootchain_field():
    errors = validate_atlas_policy_shape(
        {"type": "dstack_tdx", "expected_bootchain": {"mrtd": 123}}
    )
    assert any("mrtd must be a string" in e for e in errors)


def test_validate_shape_bootchain_not_lowercase_hex():
    errors = validate_atlas_policy_shape(
        {"type": "dstack_tdx", "expected_bootchain": {"mrtd": "ABCDEF"}}
    )
    assert any("lowercase hex" in e for e in errors)


def test_validate_shape_invalid_app_compose_not_dict():
    errors = validate_atlas_policy_shape({"type": "dstack_tdx", "app_compose": "bad"})
    assert any("app_compose must be an object" in e for e in errors)


def test_validate_shape_app_compose_missing_file():
    errors = validate_atlas_policy_shape({"type": "dstack_tdx", "app_compose": {}})
    assert any("docker_compose_file must be a string" in e for e in errors)


def test_validate_shape_invalid_os_image_hash():
    errors = validate_atlas_policy_shape({"type": "dstack_tdx", "os_image_hash": 999})
    assert any("os_image_hash must be a string" in e for e in errors)


def test_validate_shape_os_image_hash_not_lowercase_hex():
    errors = validate_atlas_policy_shape({"type": "dstack_tdx", "os_image_hash": "ZZZZ"})
    assert any("lowercase hex" in e for e in errors)


def test_validate_shape_cache_collateral_not_bool():
    errors = validate_atlas_policy_shape({"type": "dstack_tdx", "cache_collateral": "yes"})
    assert any("cache_collateral must be a boolean" in e for e in errors)


def test_validate_shape_disable_runtime_verification_not_bool():
    errors = validate_atlas_policy_shape({"type": "dstack_tdx", "disable_runtime_verification": 1})
    assert any("disable_runtime_verification must be a boolean" in e for e in errors)


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


def test_generate_atlas_policy_passes_shape_validation(monkeypatch):
    """Test generated policy passes shape validation."""
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

    policy = generate_atlas_policy("test.example.com")
    errors = validate_atlas_policy_shape(policy)
    assert errors == []


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


# ---------------------------------------------------------------------------
# fetch_atlas_policy
# ---------------------------------------------------------------------------


def test_fetch_atlas_policy_success(monkeypatch):
    policy_doc = {
        "type": "dstack_tdx",
        "allowed_tcb_status": ["UpToDate"],
        "app_compose": {"docker_compose_file": "services: {}"},
    }

    def fake_urlopen(req, timeout):
        assert req.full_url.endswith("/cvm/policies/dev/atlas-policy.json")
        assert timeout == 12.5
        return _FakeResponse(json.dumps(policy_doc))

    monkeypatch.setattr("shade.policy.request.urlopen", fake_urlopen)
    result = fetch_atlas_policy(repo="acme/demo", cvm="dev", timeout=12.5)
    assert isinstance(result, AtlasPolicyFetchResult)
    assert result.repo == "acme/demo"
    assert result.cvm == "dev"
    assert result.policy == policy_doc


def test_fetch_atlas_policy_http_error(monkeypatch):
    def fake_urlopen(req, timeout):
        raise error.HTTPError(req.full_url, 404, "Not Found", hdrs=None, fp=None)

    monkeypatch.setattr("shade.policy.request.urlopen", fake_urlopen)

    with pytest.raises(PolicyFetchError, match="HTTP 404"):
        fetch_atlas_policy(repo="acme/demo", cvm="dev")


def test_fetch_atlas_policy_shape_error(monkeypatch):
    def fake_urlopen(req, timeout):
        return _FakeResponse(json.dumps({"type": "wrong"}))

    monkeypatch.setattr("shade.policy.request.urlopen", fake_urlopen)

    with pytest.raises(PolicyFetchError, match="Invalid Atlas policy shape"):
        fetch_atlas_policy(repo="acme/demo", cvm="dev")


def test_fetch_atlas_policy_allows_skip_shape_validation(monkeypatch):
    def fake_urlopen(req, timeout):
        return _FakeResponse(json.dumps({"type": "wrong"}))

    monkeypatch.setattr("shade.policy.request.urlopen", fake_urlopen)

    result = fetch_atlas_policy(repo="acme/demo", cvm="dev", validate_shape=False)
    assert result.policy["type"] == "wrong"


def test_fetch_atlas_policy_url_error(monkeypatch):
    def fake_urlopen(req, timeout):
        raise error.URLError("connection refused")

    monkeypatch.setattr("shade.policy.request.urlopen", fake_urlopen)

    with pytest.raises(PolicyFetchError, match="connection refused"):
        fetch_atlas_policy(repo="acme/demo", cvm="dev")


def test_fetch_atlas_policy_invalid_json(monkeypatch):
    def fake_urlopen(req, timeout):
        return _FakeResponse("not json {{{")

    monkeypatch.setattr("shade.policy.request.urlopen", fake_urlopen)

    with pytest.raises(PolicyFetchError, match="not valid JSON"):
        fetch_atlas_policy(repo="acme/demo", cvm="dev")


def test_fetch_atlas_policy_non_dict_json(monkeypatch):
    def fake_urlopen(req, timeout):
        return _FakeResponse(json.dumps([1, 2, 3]))

    monkeypatch.setattr("shade.policy.request.urlopen", fake_urlopen)

    with pytest.raises(PolicyFetchError, match="must be a JSON object"):
        fetch_atlas_policy(repo="acme/demo", cvm="dev")


def test_fetch_atlas_policy_rejects_zero_timeout():
    with pytest.raises(ValueError, match="timeout must be > 0"):
        fetch_atlas_policy(repo="acme/demo", cvm="dev", timeout=0)
