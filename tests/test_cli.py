"""Tests for shade.cli module."""

import json

import yaml
from click.testing import CliRunner

from shade.cli import cli
from shade.policy import AtlasPolicyFetchResult


def _setup_project(tmp_path, shade_config: dict, compose: dict):
    """Create shade.yml and docker-compose.yml in a temp directory."""
    shade_yml = tmp_path / "shade.yml"
    with open(shade_yml, "w") as f:
        yaml.dump(shade_config, f)

    compose_yml = tmp_path / "docker-compose.yml"
    with open(compose_yml, "w") as f:
        yaml.dump(compose, f)

    return tmp_path


class TestBuildCommand:
    """Test the 'shade build' CLI command."""

    def test_build_success(self, tmp_path):
        _setup_project(
            tmp_path,
            shade_config={"app": {"name": "my-app"}, "cvm": {"domain": "example.com"}},
            compose={"services": {"my-app": {"image": "python:3.11"}}},
        )
        runner = CliRunner()
        output_path = str(tmp_path / "docker-compose.shade.yml")
        result = runner.invoke(
            cli,
            [
                "build",
                "-c",
                str(tmp_path / "shade.yml"),
                "-f",
                str(tmp_path / "docker-compose.yml"),
                "-o",
                output_path,
            ],
        )
        assert result.exit_code == 0
        assert "Generated" in result.output

    def test_build_validation_error(self, tmp_path):
        _setup_project(
            tmp_path,
            shade_config={"app": {"name": "my-app"}, "cvm": {"domain": "example.com"}},
            compose={"services": {"wrong": {"image": "python:3.11"}}},
        )
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "build",
                "-c",
                str(tmp_path / "shade.yml"),
                "-f",
                str(tmp_path / "docker-compose.yml"),
                "-o",
                str(tmp_path / "out.yml"),
            ],
        )
        assert result.exit_code == 1
        assert "Error" in result.output


class TestValidateCommand:
    """Test the 'shade validate' CLI command."""

    def test_validate_success(self, tmp_path):
        _setup_project(
            tmp_path,
            shade_config={"app": {"name": "my-app"}, "cvm": {"domain": "example.com"}},
            compose={"services": {"my-app": {"image": "python:3.11"}}},
        )
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "validate",
                "-c",
                str(tmp_path / "shade.yml"),
                "-f",
                str(tmp_path / "docker-compose.yml"),
            ],
        )
        assert result.exit_code == 0
        assert "valid" in result.output.lower()

    def test_validate_errors(self, tmp_path):
        _setup_project(
            tmp_path,
            shade_config={"app": {"name": "my-app"}, "cvm": {"domain": "example.com"}},
            compose={"services": {"wrong": {"image": "python:3.11"}}},
        )
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "validate",
                "-c",
                str(tmp_path / "shade.yml"),
                "-f",
                str(tmp_path / "docker-compose.yml"),
            ],
        )
        assert result.exit_code == 1


class TestInitCommand:
    """Test the 'shade init' CLI command."""

    def test_init_success(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(cli, ["init", "-d", str(tmp_path)])
        assert result.exit_code == 0
        assert "Created" in result.output
        assert (tmp_path / "shade.yml").exists()

    def test_init_already_exists(self, tmp_path):
        (tmp_path / "shade.yml").write_text("existing")
        runner = CliRunner()
        result = runner.invoke(cli, ["init", "-d", str(tmp_path)])
        assert result.exit_code == 1
        assert "Error" in result.output


class TestPolicyFetchCommand:
    """Test the 'shade policy fetch' CLI command."""

    def test_policy_fetch_success_stdout(self, monkeypatch):
        def fake_get_atlas_policy(**kwargs):
            return AtlasPolicyFetchResult(
                repo=kwargs["repo"],
                cvm=kwargs["cvm"],
                ref=kwargs["ref"],
                policy_path="cvm/policies/dev/atlas-policy.json",
                url="https://raw.githubusercontent.com/acme/demo/main/cvm/policies/dev/atlas-policy.json",
                policy={"type": "dstack_tdx", "allowed_tcb_status": ["UpToDate"]},
            )

        monkeypatch.setattr("shade.cli.api.get_atlas_policy", fake_get_atlas_policy)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["policy", "fetch", "--repo", "acme/demo", "--cvm", "dev", "--ref", "main"],
        )
        assert result.exit_code == 0
        assert '"type": "dstack_tdx"' in result.output
        assert "Source URL:" in result.output

    def test_policy_fetch_writes_file(self, monkeypatch, tmp_path):
        def fake_get_atlas_policy(**kwargs):
            return AtlasPolicyFetchResult(
                repo="acme/demo",
                cvm="dev",
                ref="main",
                policy_path="cvm/policies/dev/atlas-policy.json",
                url="https://example.invalid/policy.json",
                policy={"type": "dstack_tdx"},
            )

        monkeypatch.setattr("shade.cli.api.get_atlas_policy", fake_get_atlas_policy)

        out = tmp_path / "policy.json"
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["policy", "fetch", "--repo", "acme/demo", "--cvm", "dev", "--output", str(out)],
        )
        assert result.exit_code == 0
        assert out.exists()
        assert '"type": "dstack_tdx"' in out.read_text()

    def test_policy_fetch_error(self, monkeypatch):
        def fake_get_atlas_policy(**kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr("shade.cli.api.get_atlas_policy", fake_get_atlas_policy)

        runner = CliRunner()
        result = runner.invoke(cli, ["policy", "fetch", "--repo", "acme/demo", "--cvm", "dev"])
        assert result.exit_code == 1
        assert "Error: boom" in result.output


class TestPolicyGenerateCommand:
    """Test the 'shade policy generate' CLI command."""

    _FAKE_POLICY = {
        "type": "dstack_tdx",
        "allowed_tcb_status": ["UpToDate"],
        "expected_bootchain": {"mrtd": "aa" * 48},
        "os_image_hash": "ee" * 32,
        "app_compose": {"docker_compose_file": "services: {}"},
    }

    def test_generate_with_domain(self, monkeypatch):
        monkeypatch.setattr(
            "shade.cli.api.generate_atlas_policy",
            lambda **kw: self._FAKE_POLICY,
        )
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["policy", "generate", "--domain", "example.com"],
        )
        assert result.exit_code == 0, result.output
        policy = json.loads(result.output)
        assert policy["type"] == "dstack_tdx"

    def test_generate_writes_file(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "shade.cli.api.generate_atlas_policy",
            lambda **kw: self._FAKE_POLICY,
        )
        out = tmp_path / "policy.json"
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["policy", "generate", "--domain", "example.com", "-o", str(out)],
        )
        assert result.exit_code == 0, result.output
        assert out.exists()
        policy = json.loads(out.read_text())
        assert policy["type"] == "dstack_tdx"

    def test_generate_dev_mode(self, monkeypatch):
        dev_policy = {"type": "dstack_tdx", "disable_runtime_verification": True}
        monkeypatch.setattr(
            "shade.cli.api.generate_atlas_policy",
            lambda **kw: dev_policy,
        )
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["policy", "generate", "--disable-runtime-verification"],
        )
        assert result.exit_code == 0, result.output
        policy = json.loads(result.output)
        assert policy["disable_runtime_verification"] is True
        assert "expected_bootchain" not in policy

    def test_generate_with_custom_tcb_status(self, monkeypatch):
        captured = {}

        def fake_generate(**kw):
            captured.update(kw)
            return {"type": "dstack_tdx", "allowed_tcb_status": kw.get("allowed_tcb_status")}

        monkeypatch.setattr("shade.cli.api.generate_atlas_policy", fake_generate)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "policy",
                "generate",
                "--domain",
                "example.com",
                "--allowed-tcb-status",
                "UpToDate,SWHardeningNeeded",
            ],
        )
        assert result.exit_code == 0, result.output
        assert captured["allowed_tcb_status"] == ["UpToDate", "SWHardeningNeeded"]

    def test_generate_with_compose_flag(self, monkeypatch, tmp_path):
        captured = {}

        def fake_generate(**kw):
            captured.update(kw)
            return self._FAKE_POLICY

        monkeypatch.setattr("shade.cli.api.generate_atlas_policy", fake_generate)

        compose_file = tmp_path / "docker-compose.shade.yml"
        compose_file.write_text("services:\n  app:\n    image: python:3.11\n")

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "policy",
                "generate",
                "--domain",
                "example.com",
                "--compose",
                str(compose_file),
            ],
        )
        assert result.exit_code == 0, result.output
        assert captured["docker_compose_file"] == "services:\n  app:\n    image: python:3.11\n"

    def test_generate_error(self, monkeypatch):
        def fake_generate(**kw):
            raise ValueError("domain is required")

        monkeypatch.setattr("shade.cli.api.generate_atlas_policy", fake_generate)
        runner = CliRunner()
        result = runner.invoke(cli, ["policy", "generate"])
        assert result.exit_code == 1
        assert "Error" in result.output
