"""Integration test: shade-generated policy works with Atlas aTLS.

Generates a policy using shade, then verifies it against a live CVM
(vllm.concrete-security.com) using atlas-node's createAtlsFetch.

Requires:
    - Node.js >= 18
    - atlas-node native binary built at /Users/jfrery/atlas/node/
    - Network access to vllm.concrete-security.com:443

Run with:
    pytest tests/test_atlas_integration.py -m integration -v
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from shade.policy import generate_atlas_policy

ATLAS_NODE_DIR = Path("/Users/jfrery/atlas/node")

NODE_BIN = "/opt/homebrew/Cellar/node/25.2.1/bin/node"

# JS helper template used by all aTLS tests
_VERIFY_SCRIPT_TEMPLATE = """\
import {{ createAtlsFetch }} from "{atlas_dir}/atls-fetch.js";
import {{ readFileSync }} from "fs";

const policy = JSON.parse(readFileSync("{policy_path}", "utf-8"));

const fetch = createAtlsFetch({{
    target: "vllm.concrete-security.com",
    policy: policy,
}});

try {{
    const response = await fetch("/v1/models");

    const result = {{
        ok: response.ok,
        status: response.status,
        trusted: response.attestation?.trusted ?? null,
        teeType: response.attestation?.teeType ?? null,
    }};

    console.log(JSON.stringify(result));
    setTimeout(() => process.exit(0), 100);
}} catch (err) {{
    console.error(JSON.stringify({{ error: err.message }}));
    setTimeout(() => process.exit(1), 100);
}}
"""


def _find_node() -> str | None:
    """Find a working Node.js binary."""
    if Path(NODE_BIN).is_file():
        return NODE_BIN
    # Fallback: check PATH
    result = subprocess.run(["which", "node"], capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout.strip()
    return None


def _run_verify_script(node: str, policy: dict, tmp_path: Path, name: str) -> dict:
    """Write policy + Node.js script, run it, return parsed JSON result."""
    policy_path = tmp_path / f"{name}-policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    script = _VERIFY_SCRIPT_TEMPLATE.format(
        atlas_dir=ATLAS_NODE_DIR,
        policy_path=policy_path,
    )

    script_path = tmp_path / f"{name}.mjs"
    script_path.write_text(script, encoding="utf-8")

    result = subprocess.run(
        [node, str(script_path)],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, (
        f"atlas-node {name} failed.\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )

    return json.loads(result.stdout.strip())


@pytest.mark.integration
class TestAtlasIntegration:
    """End-to-end tests: shade policy generation + Atlas aTLS verification."""

    def test_shade_generated_policy_works_with_atlas(self, tmp_path):
        """Generate a policy with shade, then verify aTLS with atlas-node."""
        node = _find_node()
        if node is None:
            pytest.skip("Node.js not found")
        if not ATLAS_NODE_DIR.is_dir():
            pytest.skip("atlas-node not found at expected path")

        policy = generate_atlas_policy(
            domain="vllm.concrete-security.com",
            allowed_tcb_status=["UpToDate", "SWHardeningNeeded"],
        )

        output = _run_verify_script(node, policy, tmp_path, "verify-prod")

        assert output["ok"] is True, f"Expected HTTP 200, got status={output.get('status')}"
        assert output["trusted"] is True, "Attestation should be trusted"
        assert output["teeType"] == "tdx", f"Expected teeType=tdx, got {output.get('teeType')}"

    def test_shade_dev_policy_works_with_atlas(self, tmp_path):
        """Dev mode policy (disable_runtime_verification) should also work."""
        node = _find_node()
        if node is None:
            pytest.skip("Node.js not found")
        if not ATLAS_NODE_DIR.is_dir():
            pytest.skip("atlas-node not found at expected path")

        policy = generate_atlas_policy(
            disable_runtime_verification=True,
            allowed_tcb_status=["UpToDate", "SWHardeningNeeded", "OutOfDate"],
        )

        output = _run_verify_script(node, policy, tmp_path, "verify-dev")

        assert output["ok"] is True
        assert output["trusted"] is True
        assert output["teeType"] == "tdx"
