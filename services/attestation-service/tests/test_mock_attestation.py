import hashlib
import hmac
import json
import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))

import attestation_service


def make_signed_ekm_header(ekm_hex: str, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), bytes.fromhex(ekm_hex), hashlib.sha256).hexdigest()
    return f"{ekm_hex}:{digest}"


def configure_mock_mode(monkeypatch, tmp_path: Path) -> Path:
    compose_path = tmp_path / "docker-compose.shade.yml"
    compose_path.write_text(
        "services:\n  app:\n    image: ghcr.io/example/app@sha256:1234\n", encoding="utf-8"
    )
    monkeypatch.setenv("ATTESTATION_MODE", "mock")
    monkeypatch.setenv("MOCK_ATTESTATION_COMPOSE_PATH", str(compose_path))
    monkeypatch.setenv(
        "EKM_SHARED_SECRET", "dev-mode-ekm-placeholder-not-for-production"
    )
    monkeypatch.delenv("MOCK_ATTESTATION_OS_IMAGE_HASH", raising=False)
    monkeypatch.delenv("MOCK_ATTESTATION_CA_CERT_HASH", raising=False)
    monkeypatch.setattr(attestation_service, "dstack_socket_present", lambda: False)
    attestation_service.reset_runtime_state()
    return compose_path


class TestMockAttestationEndpoint:
    def test_mock_mode_returns_deterministic_quote_payload(self, monkeypatch, tmp_path):
        compose_path = configure_mock_mode(monkeypatch, tmp_path)
        headers = {
            attestation_service.HEADER_TLS_EKM_CHANNEL_BINDING: make_signed_ekm_header(
                "ab" * 32, "dev-mode-ekm-placeholder-not-for-production"
            )
        }
        payload = {"nonce_hex": "cd" * 32}

        with TestClient(attestation_service.app) as client:
            response = client.post("/tdx_quote", json=payload, headers=headers)

        assert response.status_code == 200
        body = response.json()
        assert body["quote_type"] == attestation_service.MOCK_QUOTE_TYPE
        assert body["tcb_info"]["mock_mode"] is True
        assert body["tcb_info"]["os_image_hash"] == attestation_service.DEFAULT_MOCK_OS_IMAGE_HASH

        app_compose_str = body["tcb_info"]["app_compose"]
        assert body["tcb_info"]["compose_hash"] == hashlib.sha256(
            app_compose_str.encode("utf-8")
        ).hexdigest()
        assert str(compose_path) == str(attestation_service.get_mock_attestation_context().compose_path)

        quote = body["quote"]
        report_data = attestation_service.compute_report_data(payload["nonce_hex"], "ab" * 32)
        assert quote["report_data"] == "0x" + report_data.hex()
        assert len(bytes.fromhex(quote["quote"])) >= attestation_service.TDX_QUOTE_LEN

        event_log = json.loads(quote["event_log"])
        assert event_log[0]["event"] == "os-image-hash"
        assert event_log[1]["event"] == "app-id"
        assert event_log[3]["event"] == "compose-hash"

    def test_mock_mode_requires_valid_ekm_header(self, monkeypatch, tmp_path):
        configure_mock_mode(monkeypatch, tmp_path)
        payload = {"nonce_hex": "ef" * 32}

        with TestClient(attestation_service.app) as client:
            missing = client.post("/tdx_quote", json=payload)
            invalid = client.post(
                "/tdx_quote",
                json=payload,
                headers={
                    attestation_service.HEADER_TLS_EKM_CHANNEL_BINDING: make_signed_ekm_header(
                        "01" * 32, "wrong-secret-wrong-secret-wrong-secret!!"
                    )
                },
            )

        assert missing.status_code == 400
        assert invalid.status_code == 403

    def test_mock_mode_is_stable_for_same_inputs_and_changes_with_nonce_or_ekm(
        self, monkeypatch, tmp_path
    ):
        configure_mock_mode(monkeypatch, tmp_path)
        signed_header = make_signed_ekm_header(
            "11" * 32, "dev-mode-ekm-placeholder-not-for-production"
        )
        base_payload = {"nonce_hex": "22" * 32}

        with TestClient(attestation_service.app) as client:
            first = client.post(
                "/tdx_quote",
                json=base_payload,
                headers={attestation_service.HEADER_TLS_EKM_CHANNEL_BINDING: signed_header},
            ).json()
            second = client.post(
                "/tdx_quote",
                json=base_payload,
                headers={attestation_service.HEADER_TLS_EKM_CHANNEL_BINDING: signed_header},
            ).json()
            different_nonce = client.post(
                "/tdx_quote",
                json={"nonce_hex": "33" * 32},
                headers={attestation_service.HEADER_TLS_EKM_CHANNEL_BINDING: signed_header},
            ).json()
            different_ekm = client.post(
                "/tdx_quote",
                json=base_payload,
                headers={
                    attestation_service.HEADER_TLS_EKM_CHANNEL_BINDING: make_signed_ekm_header(
                        "44" * 32, "dev-mode-ekm-placeholder-not-for-production"
                    )
                },
            ).json()

        assert first["quote"] == second["quote"]
        assert first["tcb_info"] == second["tcb_info"]
        assert first["quote"]["report_data"] != different_nonce["quote"]["report_data"]
        assert first["quote"]["report_data"] != different_ekm["quote"]["report_data"]
        assert first["quote"]["quote"] != different_nonce["quote"]["quote"]
        assert first["quote"]["quote"] != different_ekm["quote"]["quote"]
