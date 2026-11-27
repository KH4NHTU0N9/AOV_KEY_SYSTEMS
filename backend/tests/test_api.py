# backend/tests/test_api.py
import os
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import app as app_module  # noqa: E402
import crypto  # noqa: E402
import db  # noqa: E402


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("KEY_AUTH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("KEY_AUTH_ADMIN_TOKEN", "test-secret-token")
    with TestClient(app_module.app) as c:
        yield c


def test_full_license_lifecycle(client: TestClient):
    headers = {"X-Admin-Token": "test-secret-token"}

    # 1. Create a 24-hour key bound to 1 device on first use
    res = client.post(
        "/api/admin/keys",
        headers=headers,
        json={"count": 1, "prefix": "KTAOV", "duration_hours": 24, "max_devices": 1, "note": "unit-test"},
    )
    assert res.status_code == 200
    created = res.json()["created"]
    assert len(created) == 1
    key = created[0]["license_key"]
    assert key.startswith("KTAOV-")
    assert created[0]["computed_status"] == "unused"

    # 2. Fetch public key
    pub_b64 = client.get("/api/v1/public-key").json()["public_key_b64"]

    # 3. Verify on Device A (succeeds + activates + binds + valid Ed25519 signature)
    v1 = client.post(
        "/api/v1/verify",
        json={"key": key, "device_id": "DEVICE-AAA-111", "nonce": "nonce-001"},
    )
    assert v1.status_code == 200
    body = v1.json()
    assert body["status"] == "ok"
    assert crypto.verify_signature(body["payload_raw"], body["signature"], pub_b64) is True
    assert body["payload"]["nonce"] == "nonce-001"
    assert body["payload"]["device_id"] == "DEVICE-AAA-111"
    assert body["payload"]["expires_at"] > int(time.time())

    # 4. Same Device A verifies again -> succeeds
    v_repeat = client.post(
        "/api/v1/verify",
        json={"key": key, "device_id": "DEVICE-AAA-111", "nonce": "nonce-002"},
    )
    assert v_repeat.status_code == 200

    # 5. Different Device B tries same key -> rejected (device limit 1)
    v2 = client.post(
        "/api/v1/verify",
        json={"key": key, "device_id": "DEVICE-BBB-222", "nonce": "nonce-003"},
    )
    assert v2.status_code == 403
    assert "already bound" in v2.json()["error"].lower()

    # 6. Admin resets device binding -> Device B can now activate
    reset_res = client.post(f"/api/admin/keys/{key}/reset-device", headers=headers)
    assert reset_res.status_code == 200
    v3 = client.post(
        "/api/v1/verify",
        json={"key": key, "device_id": "DEVICE-BBB-222", "nonce": "nonce-004"},
    )
    assert v3.status_code == 200

    # 7. Admin bans key -> verification fails
    ban_res = client.post(f"/api/admin/keys/{key}/ban", headers=headers, json={"reason": "Chargeback"})
    assert ban_res.status_code == 200
    v4 = client.post(
        "/api/v1/verify",
        json={"key": key, "device_id": "DEVICE-BBB-222", "nonce": "nonce-005"},
    )
    assert v4.status_code == 403
    assert "Chargeback" in v4.json()["error"]


def test_expired_key_and_admin_auth(client: TestClient):
    # Admin endpoint without token must return 401
    unauth = client.get("/api/admin/keys")
    assert unauth.status_code == 401

    headers = {"X-Admin-Token": "test-secret-token"}
    res = client.post(
        "/api/admin/keys",
        headers=headers,
        json={"count": 1, "duration_hours": 1, "activate_on_first_use": False},
    )
    key = res.json()["created"][0]["license_key"]

    # Force expiry in DB to the past
    with db.get_conn() as conn:
        conn.execute("UPDATE licenses SET expires_at = ? WHERE license_key = ?", (int(time.time()) - 10, key))

    v = client.post("/api/v1/verify", json={"key": key, "device_id": "DEV-999", "nonce": "n-exp"})
    assert v.status_code == 403
    assert "expired" in v.json()["error"].lower()
