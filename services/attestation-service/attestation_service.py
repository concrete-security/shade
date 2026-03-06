"""
Attestation Service

Provides TDX attestation endpoints using the dstack_sdk.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import stat
import time
import tomllib
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from dstack_sdk import AsyncDstackClient
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, field_validator

HEADER_TLS_EKM_CHANNEL_BINDING = "X-TLS-EKM-Channel-Binding"

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

dstack_client: Optional[AsyncDstackClient] = None
ekm_shared_secret: Optional[str] = None

ATTESTATION_MODE_REAL = "real"
ATTESTATION_MODE_MOCK = "mock"
MOCK_QUOTE_TYPE = "tdx.mock.v1"
REAL_QUOTE_TYPE = "tdx"
DEFAULT_MOCK_OS_IMAGE_HASH = hashlib.sha256(b"shade-mock-os-image-v1").hexdigest()
DEFAULT_MOCK_CA_CERT_HASH = hashlib.sha256(b"shade-mock-ca-cert-v1").hexdigest()
DEFAULT_MOCK_VM_CONFIG = {
    "image": "mock://shade-dev-stack",
    "cpu_count": 2,
    "memory_size": 2 * 1024**3,
    "num_gpus": 0,
}
MOCK_COMPOSE_CONTAINER_PATH = "/app/shade-compose.yml"
TDX_QUOTE_BODY_OFFSET = 48
TDX_MRTD_OFFSET = TDX_QUOTE_BODY_OFFSET + 136
TDX_RTMR0_OFFSET = TDX_QUOTE_BODY_OFFSET + 328
TDX_RTMR1_OFFSET = TDX_QUOTE_BODY_OFFSET + 376
TDX_RTMR2_OFFSET = TDX_QUOTE_BODY_OFFSET + 424
TDX_RTMR3_OFFSET = TDX_QUOTE_BODY_OFFSET + 472
TDX_QUOTE_LEN = TDX_RTMR3_OFFSET + 48


@dataclass
class MockAttestationContext:
    compose_path: Path
    compose_text: str
    raw_compose_hash: str
    app_compose_str: str
    compose_hash: str
    os_image_hash: str
    ca_cert_hash: str
    event_log: list[dict[str, Any]]
    rtmr3_history: list[str]
    mrtd: str
    rtmr0: str
    rtmr1: str
    rtmr2: str
    rtmr3: str
    vm_config: dict[str, Any]


mock_attestation_context: Optional[MockAttestationContext] = None


class QuoteRequest(BaseModel):
    nonce_hex: str

    @field_validator("nonce_hex")
    @classmethod
    def validate_nonce_hex(cls, v: str) -> str:
        """Validate that nonce_hex is a 64-character hex string (32 bytes)."""
        if len(v) != 64:
            raise ValueError("nonce_hex must be exactly 64 characters (32 bytes)")
        try:
            bytes.fromhex(v)
        except ValueError:
            raise ValueError("nonce_hex must be a valid hexadecimal string")
        return v


class HealthResponse(BaseModel):
    status: str
    service: str


class QuoteResponse(BaseModel):
    success: bool
    quote: Optional[dict[str, Any]] = None
    tcb_info: Optional[dict[str, Any]] = None
    timestamp: str
    quote_type: str
    error: Optional[str] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize runtime state for either real or mock attestation mode."""
    global dstack_client
    global mock_attestation_context

    mode = get_attestation_mode()
    logger.info("Starting attestation service in %s mode", mode)
    if mode == ATTESTATION_MODE_MOCK:
        if dstack_socket_present():
            raise RuntimeError(
                "ATTESTATION_MODE=mock is not allowed when /var/run/dstack.sock is present."
            )
        mock_attestation_context = load_mock_attestation_context()
    else:
        logger.info("Initializing async dstack client...")
        try:
            dstack_client = AsyncDstackClient()
        except Exception as e:
            logger.error(f"Failed to initialize dstack client: {e}")

    yield

    logger.info("Shutting down attestation service runtime state...")
    dstack_client = None
    mock_attestation_context = None


# Initialize FastAPI app
app = FastAPI(
    title="Attestation Service",
    description="TDX attestation endpoints using dstack_sdk",
    version=tomllib.load(open("pyproject.toml", "rb"))["project"]["version"],
    lifespan=lifespan,
)


def reset_runtime_state() -> None:
    """Reset process-level runtime caches for tests."""
    global dstack_client
    global ekm_shared_secret
    global mock_attestation_context

    dstack_client = None
    ekm_shared_secret = None
    mock_attestation_context = None


def get_attestation_mode() -> str:
    """Return the configured attestation mode."""
    mode = os.getenv("ATTESTATION_MODE", ATTESTATION_MODE_REAL).strip().lower()
    if mode not in {ATTESTATION_MODE_REAL, ATTESTATION_MODE_MOCK}:
        raise RuntimeError(f"Unsupported ATTESTATION_MODE '{mode}'")
    return mode


def dstack_socket_present() -> bool:
    """Return True only when the dstack socket path points to a real socket."""
    path = Path("/var/run/dstack.sock")
    try:
        return stat.S_ISSOCK(path.stat().st_mode)
    except FileNotFoundError:
        return False
    except OSError:
        return False


def get_ekm_hmac_secret() -> str:
    """Derive EKM HMAC key from TEE, falling back to env var for dev/test."""
    global ekm_shared_secret

    if ekm_shared_secret is not None:
        return ekm_shared_secret

    try:
        from dstack_sdk import DstackClient

        client = DstackClient()
        derived = client.get_key("ekm/hmac-key/v1").decode_key().hex()
        logger.info("EKM HMAC key derived from TEE (dstack)")
        ekm_shared_secret = derived
    except Exception as e:
        logger.warning(
            f"dstack key derivation failed ({e}), falling back to EKM_SHARED_SECRET env var"
        )
        env_secret = os.getenv("EKM_SHARED_SECRET")
        if not env_secret:
            logger.error("EKM_SHARED_SECRET not set - EKM headers will not be validated!")
            raise RuntimeError("EKM_SHARED_SECRET not set")
        if len(env_secret) < 32:
            logger.error("EKM_SHARED_SECRET is too short (minimum 32 characters recommended)")
            raise RuntimeError("EKM_SHARED_SECRET is too short")
        logger.info("EKM validation enabled with shared secret")
        ekm_shared_secret = env_secret

    return ekm_shared_secret


def validate_and_extract_ekm(signed_header: str, secret: str) -> str:
    """
    Validate HMAC signature and extract EKM value.

    Args:
        signed_header: Format "{ekm_hex}:{hmac_hex}" (129 chars)
        secret: Shared secret for HMAC validation

    Returns:
        ekm_hex: The validated EKM value (64 hex chars)

    Raises:
        ValueError: If validation fails
    """
    if len(signed_header) != 129 or signed_header[64] != ":":
        raise ValueError("Invalid EKM header format (expected: {ekm}:{hmac})")

    ekm_hex = signed_header[:64]
    ekm_raw = bytes.fromhex(ekm_hex)
    received_hmac = signed_header[65:]

    # Compute expected HMAC
    expected_hmac = hmac.new(secret.encode("utf-8"), ekm_raw, hashlib.sha256).hexdigest()

    # Constant-time comparison to prevent timing attacks
    if not secrets.compare_digest(received_hmac, expected_hmac):
        raise ValueError("HMAC validation failed")

    return ekm_hex


def compute_report_data(nonce_hex: str, ekm_hex: str) -> bytes:
    """
    Compute report_data from nonce and EKM using SHA512.

    This implements TLS channel binding for attestation.
    The nonce provides freshness and the EKM binds to the specific TLS session.
    Clients will verify that the same nonce and EKM were used.

    Args:
        nonce_hex: 64-character hex string (32 bytes)
        ekm_hex: 64-character hex string (32 bytes)

    Returns:
        64-byte SHA512 hash suitable for TDX report_data
    """
    if len(nonce_hex) != 64:
        raise ValueError("nonce_hex must be exactly 64 hex characters (32 bytes)")
    if len(ekm_hex) != 64:
        raise ValueError("ekm_hex must be exactly 64 hex characters (32 bytes)")
    nonce = bytes.fromhex(nonce_hex)
    ekm = bytes.fromhex(ekm_hex)
    return hashlib.sha512(nonce + ekm).digest()


def sha384_hex(label: str, value: str) -> str:
    """Return a deterministic SHA-384 hex digest for the provided mock input."""
    return hashlib.sha384(f"{label}:{value}".encode("utf-8")).hexdigest()


def rtmr_history_digest(seed: str, prefix: str) -> str:
    """Create an RTMR history digest whose first 64 chars remain externally meaningful."""
    return seed + hashlib.sha256(f"{prefix}:{seed}".encode("utf-8")).hexdigest()[:32]


def replay_rtmr(history: list[str]) -> str:
    """Replay RTMR history into a final SHA-384 measurement."""
    mr = bytes(48)
    for entry in history:
        payload = bytes.fromhex(entry)
        if len(payload) < 48:
            payload = payload.ljust(48, b"\0")
        mr = hashlib.sha384(mr + payload).digest()
    return mr.hex()


def load_mock_attestation_context() -> MockAttestationContext:
    """Load deterministic mock attestation inputs from the configured compose file."""
    compose_path = Path(
        os.getenv("MOCK_ATTESTATION_COMPOSE_PATH", MOCK_COMPOSE_CONTAINER_PATH)
    ).expanduser()
    if not compose_path.exists():
        raise RuntimeError(
            f"MOCK_ATTESTATION_COMPOSE_PATH '{compose_path}' does not exist in mock mode."
        )

    compose_text = compose_path.read_text(encoding="utf-8")
    raw_compose_hash = hashlib.sha256(compose_text.encode("utf-8")).hexdigest()
    app_compose = {
        "runner": "docker-compose",
        "docker_compose_file": compose_text,
    }
    app_compose_str = json.dumps(app_compose, separators=(",", ":"))
    compose_hash = hashlib.sha256(app_compose_str.encode("utf-8")).hexdigest()
    os_image_hash = os.getenv("MOCK_ATTESTATION_OS_IMAGE_HASH", DEFAULT_MOCK_OS_IMAGE_HASH).strip()
    ca_cert_hash = os.getenv("MOCK_ATTESTATION_CA_CERT_HASH", DEFAULT_MOCK_CA_CERT_HASH).strip()

    if len(os_image_hash) != 64 or any(c not in "0123456789abcdef" for c in os_image_hash):
        raise RuntimeError("MOCK_ATTESTATION_OS_IMAGE_HASH must be a lowercase 64-char hex string")
    if len(ca_cert_hash) != 64 or any(c not in "0123456789abcdef" for c in ca_cert_hash):
        raise RuntimeError("MOCK_ATTESTATION_CA_CERT_HASH must be a lowercase 64-char hex string")

    rootfs_digest = rtmr_history_digest(os_image_hash, "mock-rootfs")
    app_id_digest = rtmr_history_digest(raw_compose_hash, "mock-app-id")
    ca_digest = rtmr_history_digest(ca_cert_hash, "mock-ca-cert")
    history = [rootfs_digest, app_id_digest, ca_digest]
    event_log = [
        {
            "imr": 3,
            "event": "os-image-hash",
            "event_payload": os_image_hash,
            "digest": rootfs_digest,
        },
        {"imr": 3, "event": "app-id", "event_payload": raw_compose_hash, "digest": app_id_digest},
        {"imr": 3, "event": "ca-cert-hash", "event_payload": ca_cert_hash, "digest": ca_digest},
        {"event": "compose-hash", "event_payload": compose_hash},
        {"event": "mock-mode", "event_payload": "true"},
    ]

    return MockAttestationContext(
        compose_path=compose_path,
        compose_text=compose_text,
        raw_compose_hash=raw_compose_hash,
        app_compose_str=app_compose_str,
        compose_hash=compose_hash,
        os_image_hash=os_image_hash,
        ca_cert_hash=ca_cert_hash,
        event_log=event_log,
        rtmr3_history=history,
        mrtd=sha384_hex("mock-mrtd", compose_hash),
        rtmr0=sha384_hex("mock-rtmr0", os_image_hash),
        rtmr1=sha384_hex("mock-rtmr1", raw_compose_hash),
        rtmr2=sha384_hex("mock-rtmr2", ca_cert_hash),
        rtmr3=replay_rtmr(history),
        vm_config=DEFAULT_MOCK_VM_CONFIG.copy(),
    )


def get_mock_attestation_context() -> MockAttestationContext:
    """Return the initialized mock attestation context."""
    global mock_attestation_context

    if mock_attestation_context is None:
        mock_attestation_context = load_mock_attestation_context()
    return mock_attestation_context


def build_mock_quote_bytes(context: MockAttestationContext, report_data: bytes) -> str:
    """Build a synthetic quote blob with stable measurement offsets for local tooling."""
    quote = bytearray(TDX_QUOTE_LEN)
    quote[0:2] = (4).to_bytes(2, "little")
    quote[2:4] = (1).to_bytes(2, "little")
    quote[TDX_QUOTE_BODY_OFFSET : TDX_QUOTE_BODY_OFFSET + 16] = b"MOCKTDXQUOTEv1!!"
    quote[TDX_QUOTE_BODY_OFFSET + 64 : TDX_QUOTE_BODY_OFFSET + 64 + 64] = report_data
    quote[TDX_MRTD_OFFSET : TDX_MRTD_OFFSET + 48] = bytes.fromhex(context.mrtd)
    quote[TDX_RTMR0_OFFSET : TDX_RTMR0_OFFSET + 48] = bytes.fromhex(context.rtmr0)
    quote[TDX_RTMR1_OFFSET : TDX_RTMR1_OFFSET + 48] = bytes.fromhex(context.rtmr1)
    quote[TDX_RTMR2_OFFSET : TDX_RTMR2_OFFSET + 48] = bytes.fromhex(context.rtmr2)
    quote[TDX_RTMR3_OFFSET : TDX_RTMR3_OFFSET + 48] = bytes.fromhex(context.rtmr3)
    return quote.hex()


def build_mock_quote_payload(context: MockAttestationContext, report_data: bytes) -> dict[str, Any]:
    """Build the mock /tdx_quote payload."""
    return {
        "quote": build_mock_quote_bytes(context, report_data),
        "event_log": json.dumps(context.event_log),
        "report_data": "0x" + report_data.hex(),
        "vm_config": context.vm_config,
    }


def build_mock_tcb_info(context: MockAttestationContext) -> dict[str, Any]:
    """Build the mock tcb_info payload used by local tooling."""
    return {
        "app_compose": context.app_compose_str,
        "compose_hash": context.compose_hash,
        "os_image_hash": context.os_image_hash,
        "mock_mode": True,
    }


def dump_model(value: Any) -> Any:
    """Serialize Pydantic models from dstack_sdk without depending on their concrete classes."""
    if value is None:
        return None
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "dict"):
        return value.dict()
    return value


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(status="healthy", service="attestation-service")


@app.post("/tdx_quote", response_model=QuoteResponse)
async def post_tdx_quote(request: Request, data: QuoteRequest):
    """Get a TDX quote with report data."""

    logger.info("TDX quote with report data requested")

    # This header is forwarded by Nginx (or other proxies that terminates TLS) with HMAC
    # signature.
    # Format: "{ekm_hex}:{hmac_hex}" where HMAC = HMAC-SHA256(ekm_hex, EKM_SHARED_SECRET)
    # The signature is validated before trusting the EKM value to prevent header forgery.
    # In order for this to work, the entity sending the header (e.g., Nginx) and this
    # service must run in the same trusted execution environment (TLS terminated inside
    # the TEE).
    ekm_header = request.headers.get(HEADER_TLS_EKM_CHANNEL_BINDING)

    if not ekm_header:
        logger.error("Missing EKM header for TLS session binding")
        raise HTTPException(
            status_code=400,
            detail="Missing EKM header",
        )

    try:
        ekm_hex = validate_and_extract_ekm(ekm_header, get_ekm_hmac_secret())
    except ValueError as e:
        logger.error(f"EKM validation failed: {e}")
        raise HTTPException(
            status_code=403,
            detail="Invalid EKM header signature",
        )

    logger.info("TDX quote requested using EKM session binding")
    try:
        report_data = compute_report_data(data.nonce_hex, ekm_hex)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid hex encoding: {e}")

    if get_attestation_mode() == ATTESTATION_MODE_MOCK:
        context = get_mock_attestation_context()
        return QuoteResponse(
            success=True,
            quote=build_mock_quote_payload(context, report_data),
            tcb_info=build_mock_tcb_info(context),
            timestamp=str(int(time.time())),
            quote_type=MOCK_QUOTE_TYPE,
        )

    if dstack_client is None:
        logger.error("Dstack client not initialized")
        raise HTTPException(status_code=500, detail="Server not ready")

    try:
        quote, info_response = await asyncio.gather(
            dstack_client.get_quote(report_data), dstack_client.info()
        )
        logger.info("Successfully obtained TDX quote")
    except Exception as e:
        error_msg = f"{type(e).__name__}: {str(e)}"
        logger.exception(f"Error obtaining TDX quote or TCB info: {error_msg}", stack_info=True)
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "error": "Failed to obtain TDX quote or TCB info",
                "quote_type": "tdx",
            },
        )

    return QuoteResponse(
        success=True,
        quote=dump_model(quote),
        tcb_info=dump_model(info_response.tcb_info),
        timestamp=str(int(time.time())),
        quote_type=REAL_QUOTE_TYPE,
    )
