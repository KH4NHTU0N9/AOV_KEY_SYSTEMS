# AOV_KEY_SYSTEMS — Hệ thống Quản lý & Xác thực Key KT AOV (FastAPI + SQLite + Ed25519)

Hệ thống cấp phép và xác thực Key bản quyền cho **KT AOV** (hỗ trợ cả **iOS `.ipa`** và **Android `.apk`**), tích hợp sẵn cổng **Get-Key qua quảng cáo ([AOV_KEY_GET](https://github.com/KH4NHTU0N9/AOV_KEY_GET))**:

* **Backend Python FastAPI + SQLite** (`backend/app.py`, `backend/db.py`)
* **Chữ ký số Ed25519** (`backend/crypto.py`) — chống giả mạo response / bypass qua proxy/MitM
* **Khóa theo thiết bị (Device ID Binding)** + tự đếm ngược thời hạn từ lần kích hoạt đầu (`activate_on_first_use`)
* **Trang quản trị Web Admin** (`http://127.0.0.1:8000`) & **Công cụ dòng lệnh** (`backend/cli.py`)
* **iOS Swift + Obj-C SDK** (`ios-sdk/`) + **GitHub Actions** build `KeyAuthSDK.framework` (`arm64`) không cần cài Xcode trên máy
* **Trình inject IPA bằng Python thuần** (`scripts/inject_ipa.py`)

---

## 1. Kiến trúc tổng thể & Tích hợp với `AOV_KEY_GET`

```
┌─────────────────────────────────────────────────────────────────────────┐
│  1. Người chơi mở Web Get-Key: AOV_KEY_GET (cổng 8010)                  │
│     └─ Xác minh Cloudflare Turnstile / Challenge + vượt link quảng cáo  │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │ POST /api/admin/keys
                                    │ Header: X-ADMIN-TOKEN
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  2. Server Key gốc: AOV_KEY_SYSTEMS (cổng 8000)                         │
│     ├─ Sinh key thật lưu SQLite (VD: KTAOVFREE-XXXX-XXXX-XXXX, 24h)     │
│     └─ Quản lý: tạo key VIP, ban, gia hạn, reset thiết bị, xem log      │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │ POST /api/v1/verify
                                    │ Ký Ed25519 payload_raw
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  3. App KT AOV (iOS IPA & Android APK)                                  │
│     ├─ Kiểm tra chữ ký Ed25519 bằng Public Key nhúng sẵn                │
│     └─ Hợp lệ -> Mở khóa Menu KT AOV                                    │
└─────────────────────────────────────────────────────────────────────────┘
```

### Luồng phối hợp giữa 2 repo:
1. **`AOV_KEY_SYSTEMS`** (cổng `8000`) giữ **SQLite danh sách key** và **Private Key Ed25519**. Đây là nơi duy nhất kiểm tra key (`POST /api/v1/verify`) cho app iOS & Android.
2. **`AOV_KEY_GET`** (cổng `8010`) đóng vai trò **cổng phát key miễn phí qua vượt link quảng cáo** (`yeumoney` / `link4m` / `layma` / `traffic1s`) + chống bot.
3. Sau khi người dùng vượt quảng cáo xong, `AOV_KEY_GET` gọi API sang `AOV_KEY_SYSTEMS` (`POST /api/admin/keys`) để đúc ra key thật có chữ ký Ed25519 hợp lệ cho game.

---

## 2. Khởi chạy Server `AOV_KEY_SYSTEMS`

```bash
cd /Users/trankhanhtuong/.gemini/antigravity/scratch/key-auth-system/backend
.venv/bin/uvicorn app:app --host 0.0.0.0 --port 8000
```

* Khi khởi động lần đầu, server tự sinh cặp khóa Ed25519 (`backend/data/`) và **Admin Token** (`backend/data/.admin_token`).
* Mở trình duyệt vào `http://127.0.0.1:8000`, dán Admin Token để vào trang quản trị Web Admin và xem **Ed25519 Public Key** ở góc trên bên phải.
* **Lấy Admin Token & Public Key nhanh bằng CLI:**
  ```bash
  cd /Users/trankhanhtuong/.gemini/antigravity/scratch/key-auth-system/backend
  .venv/bin/python cli.py token
  .venv/bin/python cli.py pubkey
  ```

> **Lưu ý khi dùng trên điện thoại thật:** đặt server sau HTTPS domain / Cloudflare Tunnel (VD: `https://key.yourdomain.com`) hoặc dùng IP LAN của máy Mac (VD: `http://192.168.1.215:8000`).

---

## 3. Hướng dẫn kết nối sang `AOV_KEY_GET`

Để `AOV_KEY_GET` tự động tạo key thật vào database của `AOV_KEY_SYSTEMS`:

1. Đảm bảo `AOV_KEY_SYSTEMS` đang chạy ở cổng **`8000`**.
2. Lấy Admin Token của `AOV_KEY_SYSTEMS`:
   ```bash
   cat /Users/trankhanhtuong/.gemini/antigravity/scratch/key-auth-system/backend/data/.admin_token
   ```
3. Mở file `.env` bên repo **`aov-key-get`** và cấu hình:
   ```env
   KEYAUTH_URL=http://127.0.0.1:8000
   KEYAUTH_ADMIN_TOKEN=<DAN_ADMIN_TOKEN_VAO_DAY>
   FREE_KEY_DURATION_HOURS=24
   FREE_KEY_PREFIX=KTAOVFREE
   ```
   *(Nếu deploy 2 server trên 2 VPS khác nhau, thay `http://127.0.0.1:8000` bằng URL/IP nội bộ của `AOV_KEY_SYSTEMS`.)*
4. Khởi chạy `AOV_KEY_GET` trên cổng **`8010`** (đứng **đúng thư mục `aov-key-get`**, không chạy nhầm trong thư mục `key-auth-system`):
   ```bash
   cd /Users/trankhanhtuong/.gemini/antigravity/scratch/aov-key-get
   backend/.venv/bin/uvicorn app:app --app-dir backend --host 0.0.0.0 --port 8010
   ```
5. Kiểm tra kết nối: gọi `GET http://127.0.0.1:8010/api/admin/overview` (kèm header `X-ADMIN-TOKEN` của `AOV_KEY_GET`), trường `"keyauth_connected": true` là đã thông.

### API nội bộ mà `AOV_KEY_GET` gọi sang `AOV_KEY_SYSTEMS`:
* **Endpoint:** `POST /api/admin/keys`
* **Header:** `X-ADMIN-TOKEN: <ADMIN_TOKEN>`
* **Body JSON:**
  ```json
  {
    "count": 1,
    "prefix": "KTAOVFREE",
    "duration_hours": 24,
    "max_devices": 1,
    "note": "Free GetKey code=...",
    "activate_on_first_use": true
  }
  ```

---

## 4. Quản lý Key bằng CLI (`backend/cli.py`)

```bash
cd /Users/trankhanhtuong/.gemini/antigravity/scratch/key-auth-system/backend

# Tạo 5 key VIP thời hạn 30 ngày (720 giờ), mỗi key 1 thiết bị
.venv/bin/python cli.py keygen -n 5 --prefix KTAOV --hours 720 --max-devices 1 --note "VIP User"

# Xem danh sách toàn bộ key (bao gồm cả key KTAOVFREE từ AOV_KEY_GET)
.venv/bin/python cli.py list

# Reset thiết bị đã gắn (khi người dùng đổi máy)
.venv/bin/python cli.py reset-device KTAOV-XXXX-XXXX-XXXX

# Khóa key (Ban) / Gia hạn thêm giờ
.venv/bin/python cli.py ban KTAOV-XXXX-XXXX-XXXX --reason "Vi phạm"
.venv/bin/python cli.py extend KTAOV-XXXX-XXXX-XXXX 168

# In Public Key Ed25519 / Admin Token
.venv/bin/python cli.py pubkey
.venv/bin/python cli.py token
```

---

## 5. Kết nối App iOS (`.ipa`) & Android (`.apk`)

### A. Build `KeyAuthSDK.framework` cho iOS qua GitHub Actions
1. Push repo lên GitHub → mở tab **Actions** → chạy workflow **Build KeyAuthSDK iOS Framework** (`.github/workflows/build-ios-framework.yml`).
2. Tải artifact **`KeyAuthSDK-ios-arm64`** và giải nén lấy `KeyAuthSDK.framework`.

### B. Inject hệ thống Key vào file `.ipa`
```bash
cd /Users/trankhanhtuong/.gemini/antigravity/scratch/key-auth-system

PUBKEY=$(backend/.venv/bin/python backend/cli.py pubkey)

backend/.venv/bin/python scripts/inject_ipa.py \
  --ipa /duong/dan/toi/file_goc.ipa \
  --framework /duong/dan/toi/KeyAuthSDK.framework \
  --server-url https://key.yourdomain.com \
  --public-key "$PUBKEY" \
  --menu-name "KT AOV" \
  --out /duong/dan/toi/ktaov_mykey.ipa
```
Sau đó cài `ktaov_mykey.ipa` lên iPhone qua **Sideloadly**, **ESign**, hoặc **AltStore**.

### C. Kết nối từ Android APK (`KT AOV`)
* Client Android gọi `POST <server_url>/api/v1/verify` với JSON `{ key, device_id, nonce, app_version }` và xác thực chữ ký **Ed25519** bằng Public Key tương ứng từ `cli.py pubkey`.
* Trong hộp thoại đăng nhập của app `KT AOV`, có thể bấm nút **Server** để đổi URL backend ngay trên máy mà không cần build lại APK.

---

## 6. Kiểm thử tự động

```bash
# Kiểm thử backend Python, chữ ký Ed25519 và bộ inject IPA
cd /Users/trankhanhtuong/.gemini/antigravity/scratch/key-auth-system/backend && .venv/bin/pytest -v

# Kiểm tra biên dịch Swift SDK (trên macOS có Xcode/Swift)
cd /Users/trankhanhtuong/.gemini/antigravity/scratch/key-auth-system/ios-sdk && swift build
```
