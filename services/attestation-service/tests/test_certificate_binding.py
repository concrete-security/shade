from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.testclient import TestClient

import attestation_service as service


NONCE = "11" * 32
EKM = "22" * 32
LEAF = "4d5d7122bc130f0fbc1c56bab84d3d7817287e2741154df3db8a267dde96a4da"
SECRET = "test-shade-derived-key-material!!"
MAC = "219105a610a85f5f5f77943c26e321511d7e1149446c05537fd49475f59c03d6"
HEADER = f"2:{EKM}:{LEAF}:{MAC}"
REPORT_DATA = bytes.fromhex(
    "ac581e1a1d64e43998269d090a9f2a6e488e983f74907eece302daa93135e1cbbf2"
    "b8a39bc6e1a1672f3b9e1d6f768544a00a4839e4957fdd083e879e70b5891"
)


@pytest.fixture
def dstack(monkeypatch):
    mock = SimpleNamespace(
        get_quote=AsyncMock(return_value=service.GetQuoteResponse(quote="", event_log="[]")),
        info=AsyncMock(return_value=SimpleNamespace(tcb_info=None)),
    )
    monkeypatch.setattr(service, "dstack_client", mock)
    monkeypatch.setattr(service, "EKM_SHARED_SECRET", SECRET)
    monkeypatch.setattr(service, "CERTIFICATE_BINDING", service.REPORT_DATA_V2)
    return mock


def test_v2_quote_uses_atlas_report_data_vector(dstack):
    response = TestClient(service.app).post(
        "/tdx_quote",
        json={"nonce_hex": NONCE},
        headers={service.HEADER_TLS_EKM_CHANNEL_BINDING: HEADER},
    )
    assert response.status_code == 200
    dstack.get_quote.assert_awaited_once_with(REPORT_DATA)


@pytest.mark.parametrize(
    "header",
    [
        HEADER.replace(LEAF, "00" * 32),
        HEADER.replace(EKM, "33" * 32),
        f"{EKM}:{MAC}",
        HEADER.upper(),
    ],
    ids=["wrong-leaf", "wrong-ekm", "legacy-header", "noncanonical-hex"],
)
def test_v2_rejects_header_before_requesting_a_quote(dstack, header):
    response = TestClient(service.app).post(
        "/tdx_quote",
        json={"nonce_hex": NONCE},
        headers={service.HEADER_TLS_EKM_CHANNEL_BINDING: header},
    )
    assert response.status_code == 403
    dstack.get_quote.assert_not_awaited()


def test_legacy_rejects_v2_header_before_requesting_a_quote(dstack, monkeypatch):
    monkeypatch.setattr(service, "CERTIFICATE_BINDING", "rtmr3-event")
    response = TestClient(service.app).post(
        "/tdx_quote",
        json={"nonce_hex": NONCE},
        headers={service.HEADER_TLS_EKM_CHANNEL_BINDING: HEADER},
    )
    assert response.status_code == 403
    dstack.get_quote.assert_not_awaited()


def test_v2_requires_tdx_key_derivation(monkeypatch):
    monkeypatch.setattr(service, "CERTIFICATE_BINDING", service.REPORT_DATA_V2)
    monkeypatch.setenv("EKM_SHARED_SECRET", SECRET)
    monkeypatch.setattr("dstack_sdk.DstackClient", Mock(side_effect=OSError("unavailable")))
    with pytest.raises(RuntimeError, match="requires a TDX-derived EKM key"):
        service._get_ekm_hmac_secret()
