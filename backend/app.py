# backend/app.py
import hmac
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

import crypto
import db
from config import get_admin_token


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init_db()
    crypto.ensure_keypair()
    token = get_admin_token()
    print(f"[KeyAuth] Server ready. Admin token: {token}")
    yield


app = FastAPI(title="KeyAuth Licensing Server", version="1.0.0", lifespan=lifespan)
STATIC_DIR = Path(__file__).resolve().parent / "static"


class VerifyRequest(BaseModel):
    key: str = Field(..., min_length=3, max_length=128)
    device_id: str = Field(..., min_length=4, max_length=128)
    nonce: str = Field(..., min_length=4, max_length=128)
    app_version: str = Field(default="1.0.0", max_length=32)


class CreateKeysRequest(BaseModel):
    count: int = Field(default=1, ge=1, le=100)
    prefix: str = Field(default="KTAOV", min_length=1, max_length=16)
    duration_hours: int = Field(default=720, ge=1, le=87600)
    max_devices: int = Field(default=1, ge=1, le=20)
    note: str = Field(default="", max_length=200)
    activate_on_first_use: bool = Field(default=True)
    initial_device_id: str = Field(default="", max_length=128)


class BanRequest(BaseModel):
    reason: str = Field(default="Revoked by administrator", max_length=200)


class ExtendRequest(BaseModel):
    extra_hours: int = Field(..., ge=1, le=87600)


_RATE_LOCK = threading.Lock()
_RATE_BUCKETS: dict[str, deque[float]] = defaultdict(deque)


def _enforce_rate_limit(scope: str, key: str, limit: int, window_sec: int = 60) -> None:
    now = time.monotonic()
    bucket_key = f"{scope}:{key}"
    with _RATE_LOCK:
        dq = _RATE_BUCKETS[bucket_key]
        while dq and now - dq[0] > window_sec:
            dq.popleft()
        if len(dq) >= limit:
            raise HTTPException(status_code=429, detail="Too many requests, please retry later")
        dq.append(now)


def require_admin(request: Request, x_admin_token: str | None = Header(default=None)) -> str:
    client_ip = request.client.host if request.client else "unknown"
    _enforce_rate_limit("admin", client_ip, limit=180, window_sec=60)
    expected = get_admin_token()
    if not x_admin_token or not hmac.compare_digest(x_admin_token.strip(), expected):
        raise HTTPException(status_code=401, detail="Invalid or missing X-Admin-Token")
    return x_admin_token


@app.get("/", include_in_schema=False)
def admin_ui():
    return FileResponse(STATIC_DIR / "admin.html")


@app.get("/api/v1/public-key")
def get_public_key():
    _, pub_b64 = crypto.ensure_keypair()
    return {"algorithm": "Ed25519", "public_key_b64": pub_b64}


@app.post("/api/v1/verify")
def verify_license(body: VerifyRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _enforce_rate_limit("verify", client_ip, limit=60, window_sec=60)
    ok, status_code, message, record = db.verify_and_bind_key(
        license_key=body.key,
        device_id=body.device_id,
        client_ip=client_ip,
    )
    if not ok or record is None:
        return JSONResponse(status_code=status_code, content={"status": "denied", "error": message})

    signed_payload = {
        "status": "ok",
        "key": record["license_key"],
        "device_id": body.device_id.strip(),
        "expires_at": record["expires_at"],
        "issued_at": int(time.time()),
        "nonce": body.nonce.strip(),
    }
    payload_raw, signature_b64 = crypto.sign_payload(signed_payload)
    return {
        "status": "ok",
        "payload_raw": payload_raw,
        "signature": signature_b64,
        "payload": signed_payload,
    }


@app.get("/api/admin/keys", dependencies=[Depends(require_admin)])
def admin_list_keys(search: str = ""):
    return {"keys": db.list_keys(search)}


@app.post("/api/admin/keys", dependencies=[Depends(require_admin)])
def admin_create_keys(body: CreateKeysRequest):
    keys = db.create_keys(
        count=body.count,
        prefix=body.prefix,
        duration_hours=body.duration_hours,
        max_devices=body.max_devices,
        note=body.note,
        activate_on_first_use=body.activate_on_first_use,
        initial_device_id=body.initial_device_id,
    )
    return {"created": keys}


@app.post("/api/admin/keys/{license_key}/ban", dependencies=[Depends(require_admin)])
def admin_ban_key(license_key: str, body: BanRequest):
    if not db.set_ban_status(license_key, True, body.reason):
        raise HTTPException(status_code=404, detail="Key not found")
    return {"ok": True}


@app.post("/api/admin/keys/{license_key}/unban", dependencies=[Depends(require_admin)])
def admin_unban_key(license_key: str):
    if not db.set_ban_status(license_key, False, ""):
        raise HTTPException(status_code=404, detail="Key not found")
    return {"ok": True}


@app.post("/api/admin/keys/{license_key}/reset-device", dependencies=[Depends(require_admin)])
def admin_reset_device(license_key: str):
    if not db.reset_devices(license_key):
        raise HTTPException(status_code=404, detail="Key not found")
    return {"ok": True}


@app.post("/api/admin/keys/{license_key}/extend", dependencies=[Depends(require_admin)])
def admin_extend_key(license_key: str, body: ExtendRequest):
    if not db.extend_key(license_key, body.extra_hours):
        raise HTTPException(status_code=404, detail="Key not found")
    return {"ok": True}


@app.delete("/api/admin/keys/{license_key}", dependencies=[Depends(require_admin)])
def admin_delete_key(license_key: str):
    if not db.delete_key(license_key):
        raise HTTPException(status_code=404, detail="Key not found")
    return {"ok": True}


@app.get("/api/admin/logs", dependencies=[Depends(require_admin)])
def admin_list_logs(limit: int = 50):
    return {"logs": db.list_logs(limit)}
