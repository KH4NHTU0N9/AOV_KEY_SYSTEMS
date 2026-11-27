# backend/config.py
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def get_data_dir() -> Path:
    """Return the data directory path, creating it if needed."""
    env_dir = os.environ.get("KEY_AUTH_DATA_DIR")
    data_dir = Path(env_dir) if env_dir else (BASE_DIR / "data")
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_db_path() -> Path:
    return get_data_dir() / "licenses.db"


def get_private_key_path() -> Path:
    return get_data_dir() / "ed25519_private.b64"


def get_public_key_path() -> Path:
    return get_data_dir() / "ed25519_public.b64"


def get_admin_token() -> str:
    """Return admin API token from env or persisted local secret file."""
    env_token = os.environ.get("KEY_AUTH_ADMIN_TOKEN")
    if env_token:
        return env_token.strip()

    token_file = get_data_dir() / ".admin_token"
    if token_file.exists():
        return token_file.read_text(encoding="utf-8").strip()

    token = secrets.token_urlsafe(24)
    token_file.write_text(token, encoding="utf-8")
    os.chmod(token_file, 0o600)
    return token
