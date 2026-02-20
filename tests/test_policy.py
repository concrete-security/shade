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
