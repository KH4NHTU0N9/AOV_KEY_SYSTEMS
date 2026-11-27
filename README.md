# KeyAuth System (FastAPI + SQLite + Ed25519 + Swift iOS SDK)

A complete key-based licensing & authorization system featuring:
- **Python FastAPI Backend** + **SQLite** persistence
- **Ed25519 Cryptographic Signatures** (prevents proxy/MitM response spoofing)
- **Device UDID/IDFV Binding** + expiration timers (`activate_on_first_use` or immediate)
- **Admin Web Dashboard** (`http://127.0.0.1:8000`) & **CLI Tool** (`cli.py`)
- **Swift + Obj-C iOS SDK (`KeyAuthSDK` + `KeyAuthBridge`)** with runtime `MenuLoad` gating (`KeyAuthGate`), iOS Keychain storage, `CryptoKit` verification, and UIKit login modal (`KeyPromptViewController`)
- **GitHub Actions Workflow** (`.github/workflows/build-ios-framework.yml`) to compile `KeyAuthSDK.framework` for iOS `arm64` without installing Xcode locally
- **Pure-Python IPA Injector** (`scripts/inject_ipa.py`) to embed `KeyAuthSDK.framework` directly into an uncracked `.ipa`

---

## 1. Run the Backend Server

```bash
cd /Users/trankhanhtuong/.gemini/antigravity/scratch/key-auth-system/backend
.venv/bin/uvicorn app:app --host 0.0.0.0 --port 8000
```

On first start, the server prints the **Admin Token** (and saves it to `data/.admin_token`).
Open **`http://127.0.0.1:8000`** in your browser, paste the Admin Token, and copy the **Ed25519 Public Key** shown in the top-right corner.

> For real iPhone testing over the internet or LAN, use your Mac's LAN IP (e.g., `http://192.168.1.x:8000`) or host behind an HTTPS domain/tunnel (Cloudflare Tunnel / Railway / VPS).

---

## 2. Manage Keys via CLI

```bash
cd /Users/trankhanhtuong/.gemini/antigravity/scratch/key-auth-system/backend

# Generate 5 keys valid for 30 days (720 hours), 1 device each
.venv/bin/python cli.py keygen -n 5 --prefix KTAOV --hours 720 --max-devices 1 --note "VIP User"

# List all keys
.venv/bin/python cli.py list

# Reset bound device (if user changes phone)
.venv/bin/python cli.py reset-device KTAOV-XXXX-XXXX-XXXX

# Ban / Extend / Print public key / Print admin token
.venv/bin/python cli.py ban KTAOV-XXXX-XXXX-XXXX --reason "Abuse"
.venv/bin/python cli.py extend KTAOV-XXXX-XXXX-XXXX 168
.venv/bin/python cli.py pubkey
.venv/bin/python cli.py token
```

---

## 3. Build `KeyAuthSDK.framework` via GitHub Actions (No Local Xcode Needed)

1. Push the `key-auth-system` folder to a GitHub repository.
2. Open the **Actions** tab on GitHub and run **Build KeyAuthSDK iOS Framework** (or push to `main`).
3. When the `build-ios-framework` job finishes, download the **`KeyAuthSDK-ios-arm64`** artifact and unzip `KeyAuthSDK.framework.zip`.

*(You only need to compile `KeyAuthSDK.framework` once—the server URL and public key are injected via `Info.plist` in Step 4.)*

---

## 4. Inject Your Key System into the Uncracked IPA

Once you have `KeyAuthSDK.framework` from GitHub Actions, inject it into the original uncracked `.ipa`:

```bash
cd /Users/trankhanhtuong/.gemini/antigravity/scratch/key-auth-system

PUBKEY=$(backend/.venv/bin/python backend/cli.py pubkey)

backend/.venv/bin/python scripts/inject_ipa.py \
  --ipa /Users/trankhanhtuong/Downloads/lqi/83e7b991-1ee4-4da6-a42a-64ed61f3bed0.ipa \
  --framework /path/to/KeyAuthSDK.framework \
  --server-url https://your-server-domain.com \
  --public-key "$PUBKEY" \
  --menu-name "KT AOV" \
  --out /Users/trankhanhtuong/Downloads/lqi/ktaov_mykey.ipa
```

Then sideload `ktaov_mykey.ipa` onto your iPhone via **Sideloadly**, **ESign**, or **AltStore** (which re-signs the outer bundle with your Apple certificate).

---

## 5. Run Automated Tests

```bash
# Python backend, Ed25519 signature, and Mach-O injector tests
cd /Users/trankhanhtuong/.gemini/antigravity/scratch/key-auth-system/backend && .venv/bin/pytest -v

# Swift package build check
cd /Users/trankhanhtuong/.gemini/antigravity/scratch/key-auth-system/ios-sdk && swift build
```
