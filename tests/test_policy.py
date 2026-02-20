"""Tests for shade.policy module."""

from __future__ import annotations

import json
from urllib import error

import pytest

from shade.policy import (
    DEFAULT_POLICY_BASE_URL,
    AtlasPolicyFetchResult,
    PolicyFetchError,
    build_policy_url,
    fetch_atlas_policy,
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


def test_build_policy_url_defaults():
    policy_path, url = build_policy_url(repo="acme/demo", cvm="dev")
    assert policy_path == "cvm/policies/dev/atlas-policy.json"
    assert (
        url
        == f"{DEFAULT_POLICY_BASE_URL}/acme/demo/main/cvm/policies/dev/atlas-policy.json"
    )


def test_build_policy_url_encodes_ref():
    _, url = build_policy_url(repo="acme/demo", cvm="prod", ref="feature/hardening")
    assert "/feature%2Fhardening/" in url


def test_build_policy_url_rejects_invalid_repo():
    with pytest.raises(ValueError, match="owner/repo"):
        build_policy_url(repo="bad-repo", cvm="dev")


def test_validate_atlas_policy_shape():
    errors = validate_atlas_policy_shape(
        {
            "type": "dstack_tdx",
            "allowed_tcb_status": ["UpToDate"],
            "app_compose": {"docker_compose_file": "services: {}"},
        }
    )
    assert errors == []


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


# --- _validate_repo edge cases ---


def test_build_policy_url_rejects_non_string_repo():
    with pytest.raises(ValueError, match="owner/repo"):
        build_policy_url(repo=123, cvm="dev")


def test_build_policy_url_rejects_repo_invalid_chars():
    with pytest.raises(ValueError, match="invalid characters"):
        build_policy_url(repo="ac me/de mo", cvm="dev")


# --- _validate_cvm edge cases ---


def test_build_policy_url_rejects_empty_cvm():
    with pytest.raises(ValueError, match="non-empty string"):
        build_policy_url(repo="acme/demo", cvm="")


def test_build_policy_url_rejects_cvm_invalid_chars():
    with pytest.raises(ValueError, match="invalid characters"):
        build_policy_url(repo="acme/demo", cvm="bad name!")


# --- _resolve_policy_path edge cases ---


def test_build_policy_url_rejects_empty_path_template():
    with pytest.raises(ValueError, match="non-empty string"):
        build_policy_url(repo="acme/demo", cvm="dev", path_template="")


def test_build_policy_url_rejects_bad_placeholder():
    with pytest.raises(ValueError, match="placeholder"):
        build_policy_url(repo="acme/demo", cvm="dev", path_template="{bad}/policy.json")


def test_build_policy_url_rejects_empty_resolved_path():
    # cvm is "dev" but template produces only "/" which strips to empty
    with pytest.raises(ValueError, match="cannot be empty"):
        build_policy_url(repo="acme/demo", cvm="dev", path_template="/", ref="main")


def test_build_policy_url_rejects_dotdot_segment():
    with pytest.raises(ValueError, match="must not contain"):
        build_policy_url(repo="acme/demo", cvm="dev", path_template="../{cvm}/policy.json")


# --- build_policy_url ref/base_url edge cases ---


def test_build_policy_url_rejects_empty_ref():
    with pytest.raises(ValueError, match="ref must be"):
        build_policy_url(repo="acme/demo", cvm="dev", ref="")


def test_build_policy_url_rejects_empty_base_url():
    with pytest.raises(ValueError, match="base_url must be"):
        build_policy_url(repo="acme/demo", cvm="dev", base_url="")


# --- validate_atlas_policy_shape error branches ---


def test_validate_shape_invalid_tcb_status():
    errors = validate_atlas_policy_shape({"type": "dstack_tdx", "allowed_tcb_status": 42})
    assert any("allowed_tcb_status" in e for e in errors)


def test_validate_shape_invalid_bootchain_not_dict():
    errors = validate_atlas_policy_shape({"type": "dstack_tdx", "expected_bootchain": "bad"})
    assert any("expected_bootchain must be an object" in e for e in errors)


def test_validate_shape_invalid_bootchain_field():
    errors = validate_atlas_policy_shape(
        {"type": "dstack_tdx", "expected_bootchain": {"mrtd": 123}}
    )
    assert any("mrtd must be a string" in e for e in errors)


def test_validate_shape_invalid_app_compose_not_dict():
    errors = validate_atlas_policy_shape({"type": "dstack_tdx", "app_compose": "bad"})
    assert any("app_compose must be an object" in e for e in errors)


def test_validate_shape_app_compose_missing_file():
    errors = validate_atlas_policy_shape({"type": "dstack_tdx", "app_compose": {}})
    assert any("docker_compose_file must be a string" in e for e in errors)


def test_validate_shape_invalid_os_image_hash():
    errors = validate_atlas_policy_shape({"type": "dstack_tdx", "os_image_hash": 999})
    assert any("os_image_hash must be a string" in e for e in errors)


# --- _fetch_json_object error paths ---


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


# --- fetch_atlas_policy timeout validation ---


def test_fetch_atlas_policy_rejects_zero_timeout():
    with pytest.raises(ValueError, match="timeout must be > 0"):
        fetch_atlas_policy(repo="acme/demo", cvm="dev", timeout=0)
