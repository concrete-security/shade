"""Tests for shade.verify module."""

import socket
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from shade.config import ShadeConfig
from shade.verify import (
    CheckResult,
    check_allowed_envs,
    check_domain_resolves,
    check_dstack_socket_mounted,
    check_env_vars_defined,
    check_generated_compose_no_dev_mode,
    check_images_pinned,
    check_images_resolvable,
    check_no_build_contexts,
    check_no_host_ports,
    check_tls_production,
    run_all_checks,
)


def _make_config(**overrides) -> ShadeConfig:
    """Create a minimal ShadeConfig for testing."""
    data = {
        "app": {"name": "my-app"},
        "cvm": {"domain": "example.com"},
    }
    data.update(overrides)
    return ShadeConfig(**data)


def _write_yaml(path: Path, data: dict):
    with open(path, "w") as f:
        yaml.dump(data, f)


def _all_passed(results: list[CheckResult]) -> bool:
    return all(r.passed for r in results)


def _failed(results: list[CheckResult]) -> list[CheckResult]:
    return [r for r in results if not r.passed]


class TestCheckImagesResolvable:
    """Test framework image resolution check."""

    def test_images_resolvable(self):
        config = _make_config()
        with patch("shade.verify.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            results = check_images_resolvable(config)
            assert _all_passed(results)

    def test_image_not_resolvable(self):
        config = _make_config()
        with patch("shade.verify.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            mock_run.return_value.stderr = b"manifest unknown"
            results = check_images_resolvable(config)
            failed = _failed(results)
            assert len(failed) > 0
            assert all("not found" in r.message for r in failed)

    def test_image_private_warns(self):
        config = _make_config()
        with patch("shade.verify.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            mock_run.return_value.stderr = b"denied"
            results = check_images_resolvable(config)
            failed = _failed(results)
            assert len(failed) > 0
            assert all("auth required" in r.message for r in failed)

    def test_image_docker_not_found(self):
        config = _make_config()
        with patch("shade.verify.subprocess.run", side_effect=FileNotFoundError):
            results = check_images_resolvable(config)
            failed = _failed(results)
            assert len(failed) > 0
            assert all("Cannot check" in r.message for r in failed)

    def test_image_timeout(self):
        config = _make_config()
        with patch("shade.verify.subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 30)):
            results = check_images_resolvable(config)
            failed = _failed(results)
            assert len(failed) > 0


class TestCheckDomainResolves:
    """Test domain DNS resolution check."""

    def test_domain_resolves(self):
        config = _make_config(cvm={"domain": "example.com"})
        with patch("shade.verify.socket.getaddrinfo", return_value=[("AF_INET", None, None, None, ("93.184.216.34", 0))]):
            results = check_domain_resolves(config)
            assert _all_passed(results)

    def test_domain_does_not_resolve(self):
        config = _make_config(cvm={"domain": "nonexistent.example"})
        with patch("shade.verify.socket.getaddrinfo", side_effect=socket.gaierror("Name not resolved")):
            results = check_domain_resolves(config)
            failed = _failed(results)
            assert len(failed) == 1
            assert "does not resolve" in failed[0].message


class TestCheckTlsProduction:
    """Test TLS production check."""

    def test_production_tls(self):
        config = _make_config()
        results = check_tls_production(config)
        assert _all_passed(results)

    def test_staging_tls(self):
        config = _make_config(cvm={"domain": "example.com", "tls": {"letsencrypt_staging": True}})
        results = check_tls_production(config)
        failed = _failed(results)
        assert len(failed) == 1
        assert "staging" in failed[0].message


class TestCheckGeneratedComposeNoDevMode:
    """Test DEV_MODE detection in generated compose."""

    def test_no_dev_mode(self, tmp_path):
        compose = tmp_path / "docker-compose.shade.yml"
        _write_yaml(compose, {
            "services": {"nginx": {"environment": {"DEV_MODE": "false"}}},
        })
        results = check_generated_compose_no_dev_mode(compose)
        assert _all_passed(results)

    def test_dev_mode_dict(self, tmp_path):
        compose = tmp_path / "docker-compose.shade.yml"
        _write_yaml(compose, {
            "services": {"nginx": {"environment": {"DEV_MODE": "true"}}},
        })
        results = check_generated_compose_no_dev_mode(compose)
        failed = _failed(results)
        assert len(failed) == 1
        assert "DEV_MODE" in failed[0].message

    def test_dev_mode_list(self, tmp_path):
        compose = tmp_path / "docker-compose.shade.yml"
        _write_yaml(compose, {
            "services": {"nginx": {"environment": ["DEV_MODE=true"]}},
        })
        results = check_generated_compose_no_dev_mode(compose)
        assert len(_failed(results)) == 1

    def test_missing_file(self, tmp_path):
        results = check_generated_compose_no_dev_mode(tmp_path / "nonexistent.yml")
        failed = _failed(results)
        assert len(failed) == 1
        assert "not found" in failed[0].message

    def test_invalid_yaml(self, tmp_path):
        compose = tmp_path / "docker-compose.shade.yml"
        compose.write_text(": invalid: yaml: {{")
        results = check_generated_compose_no_dev_mode(compose)
        failed = _failed(results)
        assert len(failed) == 1
        assert "not found" in failed[0].message


class TestCheckNoBuildContexts:
    """Test build context detection."""

    def test_no_build_contexts(self, tmp_path):
        compose = tmp_path / "compose.yml"
        _write_yaml(compose, {"services": {"app": {"image": "python:3.11"}}})
        results = check_no_build_contexts(compose)
        assert _all_passed(results)

    def test_build_context_string(self, tmp_path):
        compose = tmp_path / "compose.yml"
        _write_yaml(compose, {"services": {"app": {"build": "./app"}}})
        results = check_no_build_contexts(compose)
        failed = _failed(results)
        assert len(failed) == 1
        assert "build context" in failed[0].message

    def test_build_context_dict(self, tmp_path):
        compose = tmp_path / "compose.yml"
        _write_yaml(compose, {"services": {"app": {"build": {"context": "/abs/path"}}}})
        results = check_no_build_contexts(compose)
        assert len(_failed(results)) == 1


class TestCheckDstackSocketMounted:
    """Test dstack.sock mounting check."""

    def test_socket_mounted(self, tmp_path):
        compose = tmp_path / "compose.yml"
        _write_yaml(compose, {
            "services": {
                "attestation": {
                    "volumes": ["/var/run/dstack.sock:/var/run/dstack.sock"],
                },
            },
        })
        results = check_dstack_socket_mounted(compose)
        assert _all_passed(results)

    def test_socket_mounted_dict_style(self, tmp_path):
        compose = tmp_path / "compose.yml"
        _write_yaml(compose, {
            "services": {
                "attestation": {
                    "volumes": [{"source": "/var/run/dstack.sock", "target": "/var/run/dstack.sock"}],
                },
            },
        })
        results = check_dstack_socket_mounted(compose)
        assert _all_passed(results)

    def test_socket_not_mounted(self, tmp_path):
        compose = tmp_path / "compose.yml"
        _write_yaml(compose, {"services": {"app": {"image": "python:3.11"}}})
        results = check_dstack_socket_mounted(compose)
        failed = _failed(results)
        assert len(failed) == 1
        assert "dstack.sock" in failed[0].message


class TestCheckAllowedEnvs:
    """Test allowed_envs listing."""

    def test_lists_env_vars(self, tmp_path):
        compose = tmp_path / "compose.yml"
        _write_yaml(compose, {
            "services": {
                "app": {"environment": {"API_KEY": "secret", "PORT": "8000"}},
            },
        })
        results = check_allowed_envs(compose)
        assert len(results) == 1
        assert "API_KEY" in results[0].message
        assert "PORT" in results[0].message

    def test_no_env_vars(self, tmp_path):
        compose = tmp_path / "compose.yml"
        _write_yaml(compose, {"services": {"app": {"image": "python:3.11"}}})
        assert check_allowed_envs(compose) == []

    def test_list_format_env(self, tmp_path):
        compose = tmp_path / "compose.yml"
        _write_yaml(compose, {
            "services": {"app": {"environment": ["KEY=val"]}},
        })
        results = check_allowed_envs(compose)
        assert len(results) == 1
        assert "KEY" in results[0].message


class TestCheckNoHostPorts:
    """Test host port detection."""

    def test_no_ports(self):
        compose = {"services": {"app": {"image": "python:3.11"}}}
        results = check_no_host_ports(compose)
        assert _all_passed(results)

    def test_has_ports(self):
        compose = {"services": {"app": {"image": "python:3.11", "ports": ["8080:8080"]}}}
        results = check_no_host_ports(compose)
        failed = _failed(results)
        assert len(failed) == 1
        assert "stripped" in failed[0].message


class TestCheckImagesPinned:
    """Test image digest pinning check."""

    def test_pinned_image(self):
        compose = {
            "services": {
                "app": {"image": "python@sha256:abc123def456"},
            },
        }
        results = check_images_pinned(compose)
        assert _all_passed(results)

    def test_unpinned_image(self):
        compose = {"services": {"app": {"image": "python:3.11"}}}
        results = check_images_pinned(compose)
        failed = _failed(results)
        assert len(failed) == 1
        assert "not pinned" in failed[0].message

    def test_no_image_with_build(self):
        compose = {"services": {"app": {"build": "."}}}
        results = check_images_pinned(compose)
        failed = _failed(results)
        assert len(failed) == 1
        assert "build context" in failed[0].message


class TestCheckEnvVarsDefined:
    """Test environment variable completeness check."""

    def test_all_vars_defined(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text("API_KEY=secret\nPORT=8000\n")
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("image: app\nenvironment:\n  API_KEY: ${API_KEY}\n  PORT: ${PORT}\n")
        output = tmp_path / "nonexistent.yml"
        results = check_env_vars_defined(env, compose, output)
        assert _all_passed(results)

    def test_missing_var(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text("API_KEY=secret\n")
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("environment:\n  API_KEY: ${API_KEY}\n  TOKEN: ${PUSH_TOKEN}\n")
        output = tmp_path / "nonexistent.yml"
        results = check_env_vars_defined(env, compose, output)
        failed = _failed(results)
        assert len(failed) == 1
        assert "PUSH_TOKEN" in failed[0].message

    def test_var_with_default_ignored(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text("")
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("environment:\n  PORT: ${PORT:-8000}\n")
        output = tmp_path / "nonexistent.yml"
        results = check_env_vars_defined(env, compose, output)
        assert _all_passed(results)

    def test_no_env_file(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("environment:\n  TOKEN: ${TOKEN}\n")
        env = tmp_path / ".env"
        output = tmp_path / "nonexistent.yml"
        results = check_env_vars_defined(env, compose, output)
        failed = _failed(results)
        assert len(failed) == 1
        assert "TOKEN" in failed[0].message

    def test_vars_in_generated_compose(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text("")
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("")
        output = tmp_path / "output.yml"
        output.write_text("environment:\n  SECRET: ${SECRET_KEY}\n")
        results = check_env_vars_defined(env, compose, output)
        failed = _failed(results)
        assert len(failed) == 1
        assert "SECRET_KEY" in failed[0].message

    def test_escaped_docker_compose_vars_ignored(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text("")
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("")
        output = tmp_path / "output.yml"
        output.write_text("environment:\n  - \"EXTRA=$${CORS_HEADERS} $$host\"\n")
        results = check_env_vars_defined(env, compose, output)
        assert _all_passed(results)


class TestRunAllChecks:
    """Test the aggregated check runner."""

    def test_returns_results_list(self):
        results = run_all_checks()
        assert isinstance(results, list)

    def test_skips_config_checks_without_config(self):
        results = run_all_checks(config=None)
        assert isinstance(results, list)
