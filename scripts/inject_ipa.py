# scripts/inject_ipa.py
import argparse
import os
import plistlib
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlparse

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
LC_RPATH = 0x8000001C


def _extract_zip_preserving_attrs(zip_path: Path, dest_dir: Path) -> None:
    """Extract zip archive while preserving Unix executable bits and symlinks."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            target = dest_dir / info.filename
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                link_target = zf.read(info.filename).decode("utf-8")
                if target.exists() or target.is_symlink():
                    target.unlink()
                os.symlink(link_target, target)
                continue
            with zf.open(info, "r") as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
            if mode & 0o777:
                os.chmod(target, mode & 0o777)


def _write_zip_preserving_attrs(src_dir: Path, out_zip: Path) -> None:
    """Write directory tree to zip while preserving executable permissions and symlinks."""
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for root, dirs, files in os.walk(src_dir, followlinks=False):
            root_path = Path(root)
            for d in dirs:
                d_full = root_path / d
                if d_full.is_symlink():
                    rel = str(d_full.relative_to(src_dir))
                    zi = zipfile.ZipInfo(rel)
                    zi.create_system = 3
                    zi.external_attr = (stat.S_IFLNK | 0o777) << 16
                    zout.writestr(zi, os.readlink(d_full).encode("utf-8"))
            for file in files:
                full = root_path / file
                rel = str(full.relative_to(src_dir))
                if full.is_symlink():
                    zi = zipfile.ZipInfo(rel)
                    zi.create_system = 3
                    zi.external_attr = (stat.S_IFLNK | 0o777) << 16
                    zout.writestr(zi, os.readlink(full).encode("utf-8"))
                else:
                    st = full.stat()
                    zi = zipfile.ZipInfo.from_file(full, rel)
                    zi.create_system = 3
                    zi.external_attr = ((st.st_mode & 0xFFFF) << 16)
                    with open(full, "rb") as f:
                        zout.writestr(zi, f.read(), compress_type=zipfile.ZIP_DEFLATED)


def list_rpaths(macho_bytes: bytes | bytearray) -> list[str]:
    """Return LC_RPATH entries encoded in a 64-bit Mach-O binary."""
    if len(macho_bytes) < 32:
        return []
    magic, _, _, _, ncmds, _, _, _ = struct.unpack("<8I", macho_bytes[:32])
    if magic != MH_MAGIC_64:
        return []
    pos = 32
    rpaths: list[str] = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack("<II", macho_bytes[pos : pos + 8])
        if cmd == LC_RPATH:
            name_off = struct.unpack("<I", macho_bytes[pos + 8 : pos + 12])[0]
            raw_name = macho_bytes[pos + name_off : pos + cmdsize].split(b"\x00", 1)[0]
            rpaths.append(raw_name.decode("utf-8", errors="ignore"))
        pos += cmdsize
    return rpaths


def inject_load_dylib(macho_bytes: bytearray, dylib_path: str) -> bool:
    """Insert an LC_LOAD_DYLIB load command into a 64-bit Mach-O binary in-place."""
    if len(macho_bytes) < 32:
        raise ValueError("File too small to be a valid Mach-O binary")

    magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack("<8I", macho_bytes[:32])
    if magic in (FAT_MAGIC, FAT_CIGAM):
        raise ValueError("FAT universal Mach-O binaries are not supported; thin to arm64 first with lipo")
    if magic != MH_MAGIC_64:
        raise ValueError(f"Unsupported Mach-O magic: 0x{magic:08x} (expected 64-bit ARM64 Mach-O)")

    pos = 32
    first_sect_off = len(macho_bytes)
    target_bytes = dylib_path.encode("utf-8")

    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack("<II", macho_bytes[pos : pos + 8])
        if cmd == LC_LOAD_DYLIB:
            name_off = struct.unpack("<I", macho_bytes[pos + 8 : pos + 12])[0]
            raw_name = macho_bytes[pos + name_off : pos + cmdsize].split(b"\x00", 1)[0]
            if raw_name == target_bytes:
                return False  # Already injected
        elif cmd == LC_SEGMENT_64:
            segname = macho_bytes[pos + 8 : pos + 24].split(b"\x00", 1)[0]
            nsects = struct.unpack("<I", macho_bytes[pos + 64 : pos + 68])[0]
            if segname == b"__TEXT" and nsects > 0:
                for s in range(nsects):
                    sect_base = pos + 72 + (s * 80)
                    sect_off = struct.unpack("<I", macho_bytes[sect_base + 48 : sect_base + 52])[0]
                    if sect_off > 0:
                        first_sect_off = min(first_sect_off, sect_off)
        pos += cmdsize

    cmd_end = 32 + sizeofcmds
    raw_len = 24 + len(target_bytes) + 1
    cmdsize = (raw_len + 7) & ~7

    if cmd_end + cmdsize > first_sect_off:
        raise RuntimeError(
            f"Not enough Mach-O header padding: need {cmdsize} bytes, have {first_sect_off - cmd_end}"
        )
    if any(b != 0 for b in macho_bytes[cmd_end : cmd_end + cmdsize]):
        raise RuntimeError("Header padding bytes are non-zero; refusing to overwrite")

    load_cmd = struct.pack("<IIIIII", LC_LOAD_DYLIB, cmdsize, 24, 2, 0x00010000, 0x00010000)
    load_cmd += target_bytes + b"\x00" * (cmdsize - 24 - len(target_bytes))
    macho_bytes[cmd_end : cmd_end + cmdsize] = load_cmd
    struct.pack_into("<II", macho_bytes, 16, ncmds + 1, sizeofcmds + cmdsize)
    return True


def patch_awscognito_optional(
    data: bytearray,
    menu_name: str | None,
    github_url: str | None = "https://github.com/KH4NHTU0N9",
) -> None:
    """Neutralize fallback third-party login UI when patching legacy AWSCognito packages."""
    fallback_ret_offsets = [0x13A7C94, 0x1372B9C, 0x13C37B0, 0x137520C, 0x138A198, 0x1394408, 0x135C994]
    if len(data) > 0x2600000 and data[0x2550CD3 : 0x2550CD3 + 15] == b"AovCheat || 257":
        for off in fallback_ret_offsets:
            struct.pack_into("<I", data, off, 0xD65F03C0)  # ret

        if menu_name:
            encoded = menu_name.encode("ascii")
            if len(encoded) > 15:
                raise ValueError("menu_name must be <= 15 ASCII characters")
            data[0x2550CD3 : 0x2550CD3 + 16] = encoded + b"\x00" * (16 - len(encoded))
            struct.pack_into("<Q", data, 0x2A2A9D8 + 24, len(encoded))
            struct.pack_into("<I", data, 0x241F040, 0xAA0803F6)

        if data[0x2550B9F : 0x2550B9F + 8] == b"TUMADAM\x00":
            brand = (menu_name or "KT AOV").encode("ascii")[:7]
            data[0x2550B9F : 0x2550B9F + 8] = brand + b"\x00" * (8 - len(brand))
            struct.pack_into("<Q", data, 0x2A2A598 + 24, len(brand))

        for off in [0x25512A9, 0x25512CA, 0x25512E4]:
            if data[off : off + 8] == b"TUMADAM.":
                data[off : off + 8] = b"KT_AOV_."

        if github_url and data[0x2550E73 : 0x2550E8C] == b"Telegram\x00Discord\x00Website\x00":
            url_bytes = github_url.strip().encode("ascii")
            if len(url_bytes) > 82:
                raise ValueError("github_url too long for inline string slot (max 82 bytes)")
            data[0x2550E73 : 0x2550E7C] = b"GitHub\x00\x00\x00"
            struct.pack_into("<Q", data, 0x2A2B138 + 24, 6)
            data[0x2550E7C : 0x2550EE0] = b"\x00" * (0x2550EE0 - 0x2550E7C)
            data[0x2550E8C : 0x2550E8C + len(url_bytes)] = url_bytes
            struct.pack_into("<Q", data, 0x2A2B198 + 24, len(url_bytes))
            if struct.unpack("<I", data[0x2426998 : 0x242699C])[0] == 0x52800063:
                struct.pack_into("<I", data, 0x2426998, 0x52800023)
                struct.pack_into("<I", data, 0x24269DC, 0x52800023)
                struct.pack_into("<I", data, 0x24269FC, 0x1E6E1000)
                struct.pack_into("<I", data, 0x2426D28, 0xF100067F)


def normalize_get_key_url(raw_url: str | None) -> str:
    """Validate and normalize `--get-key-url` for KeyAuthSDK.framework/Info.plist."""
    if not raw_url:
        return ""
    cleaned = raw_url.strip().rstrip("/")
    parsed = urlparse(cleaned)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"Invalid --get-key-url (must be http/https with host): {raw_url}")
    return cleaned


def configure_framework_plist(
    framework_dir: Path,
    server_url: str,
    public_key: str,
    title: str,
    subtitle: str,
    get_key_url: str = "",
) -> None:
    """Write KeyAuth server URL, Get-Key URL, and Ed25519 public key into Info.plist."""
    plist_path = framework_dir / "Info.plist"
    if plist_path.exists():
        with plist_path.open("rb") as f:
            plist_data = plistlib.load(f)
    else:
        plist_data = {
            "CFBundleExecutable": "KeyAuthSDK",
            "CFBundleIdentifier": "com.ktaov.KeyAuthSDK",
            "CFBundleName": "KeyAuthSDK",
            "CFBundlePackageType": "FMWK",
            "CFBundleShortVersionString": "1.0",
            "CFBundleVersion": "1",
            "MinimumOSVersion": "14.0",
        }

    plist_data["KeyAuthServerURL"] = server_url.strip().rstrip("/")
    plist_data["KeyAuthPublicKey"] = public_key.strip()
    plist_data["KeyAuthTitle"] = title
    plist_data["KeyAuthSubtitle"] = subtitle
    clean_getkey = normalize_get_key_url(get_key_url)
    if clean_getkey:
        plist_data["KeyAuthGetKeyURL"] = clean_getkey
    else:
        plist_data.pop("KeyAuthGetKeyURL", None)

    with plist_path.open("wb") as f:
        plistlib.dump(plist_data, f)


def configure_app_plist(
    app_dir: Path,
    bundle_id: str | None,
    allow_http: bool = False,
    enable_120hz: bool = False,
) -> list[Path]:
    """Update app Info.plist (ATS, 120Hz ProMotion, optional rebrand) and return updated nested frameworks."""
    updated_frameworks: list[Path] = []
    app_plist = app_dir / "Info.plist"
    if app_plist.exists():
        data = plistlib.loads(app_plist.read_bytes())
        if bundle_id and "tumadam" in str(data.get("CFBundleIdentifier", "")).lower():
            data["CFBundleIdentifier"] = bundle_id
        data.pop("DecryptedBy", None)
        if allow_http:
            ats = dict(data.get("NSAppTransportSecurity") or {})
            ats["NSAllowsArbitraryLoads"] = True
            data["NSAppTransportSecurity"] = ats
        if enable_120hz:
            data["CADisableMinimumFrameDurationOnPhone"] = True
        app_plist.write_bytes(plistlib.dumps(data))

    rt_fw = app_dir / "Frameworks" / "Runtime9r53i.framework"
    rt_plist = rt_fw / "Info.plist"
    if bundle_id and rt_plist.exists():
        rdata = plistlib.loads(rt_plist.read_bytes())
        if "tumadam" in str(rdata.get("CFBundleIdentifier", "")).lower():
            rdata["CFBundleIdentifier"] = f"{bundle_id}.embedded.runtime9r53i"
            rt_plist.write_bytes(plistlib.dumps(rdata))
            updated_frameworks.append(rt_fw)
    return updated_frameworks


def resolve_injection_target(app_dir: Path, target_mode: str) -> tuple[Path, Path | None, str]:
    """Resolve binary path, enclosing framework path (if any), and dylib install path for injection."""
    frameworks_dir = app_dir / "Frameworks"
    unity_fw = frameworks_dir / "UnityFramework.framework"
    unity_bin = unity_fw / "UnityFramework"
    aws_fw = frameworks_dir / "AWSCognito.framework"
    aws_bin = aws_fw / "AWSCognito"

    app_plist = app_dir / "Info.plist"
    exec_name = app_dir.stem
    if app_plist.exists():
        pdata = plistlib.loads(app_plist.read_bytes())
        exec_name = str(pdata.get("CFBundleExecutable") or exec_name)
    main_bin = app_dir / exec_name

    if target_mode == "awscognito":
        if not aws_bin.exists():
            raise RuntimeError(f"Expected AWSCognito binary at {aws_bin}")
        return aws_bin, aws_fw, "@rpath/KeyAuthSDK.framework/KeyAuthSDK"

    if target_mode == "unity":
        if not unity_bin.exists():
            raise RuntimeError(f"Expected UnityFramework binary at {unity_bin}")
        return unity_bin, unity_fw, "@rpath/KeyAuthSDK.framework/KeyAuthSDK"

    if target_mode == "main":
        if not main_bin.exists():
            raise RuntimeError(f"Expected main executable at {main_bin}")
        return main_bin, None, "@executable_path/Frameworks/KeyAuthSDK.framework/KeyAuthSDK"

    # auto: prefer UnityFramework on clean IPAs, fallback to main binary
    if unity_bin.exists():
        return unity_bin, unity_fw, "@rpath/KeyAuthSDK.framework/KeyAuthSDK"
    if main_bin.exists():
        return main_bin, None, "@executable_path/Frameworks/KeyAuthSDK.framework/KeyAuthSDK"
    if aws_bin.exists():
        return aws_bin, aws_fw, "@rpath/KeyAuthSDK.framework/KeyAuthSDK"
    raise RuntimeError("No supported target binary (UnityFramework, main executable, or AWSCognito) found in .app")


def build_ipa(
    ipa_path: Path,
    framework_path: Path,
    server_url: str,
    public_key: str,
    out_path: Path,
    get_key_url: str = "",
    target_mode: str = "auto",
    menu_name: str | None = "KT AOV",
    github_url: str | None = "https://github.com/KH4NHTU0N9",
    bundle_id: str = "com.ktaov.aovx",
    title: str = "KT AOV",
    subtitle: str = "Enter your activation key",
    allow_http: bool = False,
    enable_120hz: bool = False,
    sign: bool = True,
) -> None:
    if not ipa_path.exists():
        raise FileNotFoundError(f"IPA not found: {ipa_path}")
    if not framework_path.exists():
        raise FileNotFoundError(
            f"KeyAuthSDK.framework not found at '{framework_path}'. "
            "Push AOV_KEY_SYSTEMS to GitHub, run 'Build KeyAuthSDK iOS Framework', and download 'KeyAuthSDK-ios-arm64'."
        )

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        payload_stage = work / "ipa_stage"

        if framework_path.is_file() and framework_path.suffix.lower() == ".zip":
            fw_unzip_dir = work / "_fw_unzip"
            _extract_zip_preserving_attrs(framework_path, fw_unzip_dir)
            found_fw = list(fw_unzip_dir.rglob("KeyAuthSDK.framework"))
            if not found_fw:
                for iz in list(fw_unzip_dir.rglob("*.zip")):
                    _extract_zip_preserving_attrs(iz, fw_unzip_dir)
                found_fw = list(fw_unzip_dir.rglob("KeyAuthSDK.framework"))
            if not found_fw:
                raise FileNotFoundError(f"KeyAuthSDK.framework not found inside archive {framework_path}")
            framework_path = found_fw[0]

        if not (framework_path / "KeyAuthSDK").exists():
            raise FileNotFoundError(f"KeyAuthSDK binary missing inside {framework_path}")

        print("[1] Unpacking IPA (preserving executable modes)...")
        _extract_zip_preserving_attrs(ipa_path, payload_stage)

        app_dirs = list((payload_stage / "Payload").glob("*.app"))
        if not app_dirs:
            raise RuntimeError("No .app bundle found under Payload/")
        app_dir = app_dirs[0]
        frameworks_dir = app_dir / "Frameworks"
        frameworks_dir.mkdir(exist_ok=True)

        target_bin, target_fw, dylib_install = resolve_injection_target(app_dir, target_mode)
        print(f"[2] Target binary: {target_bin.relative_to(payload_stage)} ({dylib_install})")

        print("[3] Installing & configuring KeyAuthSDK.framework...")
        dst_fw = frameworks_dir / "KeyAuthSDK.framework"
        if dst_fw.exists():
            shutil.rmtree(dst_fw)
        shutil.copytree(framework_path, dst_fw, symlinks=True)
        configure_framework_plist(dst_fw, server_url, public_key, title, subtitle, get_key_url=get_key_url)

        raw_target = bytearray(target_bin.read_bytes())
        if "@rpath" in dylib_install:
            rpaths = list_rpaths(raw_target)
            if not rpaths and app_dir.joinpath(app_dir.stem).exists():
                rpaths = list_rpaths(app_dir.joinpath(app_dir.stem).read_bytes())
            if not rpaths:
                dylib_install = "@executable_path/Frameworks/KeyAuthSDK.framework/KeyAuthSDK"

        added = inject_load_dylib(raw_target, dylib_install)
        print(f"    LC_LOAD_DYLIB added ({dylib_install}): {added}")
        if target_mode == "awscognito" or (target_fw and target_fw.name == "AWSCognito.framework"):
            patch_awscognito_optional(raw_target, menu_name, github_url=github_url)
        target_bin.write_bytes(raw_target)
        os.chmod(target_bin, 0o755)

        extra_signed_fws = configure_app_plist(
            app_dir,
            bundle_id=bundle_id,
            allow_http=allow_http,
            enable_120hz=enable_120hz,
        )

        if sign and sys.platform == "darwin":
            print("[4] Ad-hoc codesigning modified bundles...")
            bundles = [dst_fw] + ([target_fw] if target_fw else []) + extra_signed_fws
            for fw in bundles:
                subprocess.check_call(["codesign", "-f", "-s", "-", str(fw)])
                subprocess.check_call(["codesign", "-v", str(fw)])
        else:
            print("[4] Skipping codesign (re-sign via Sideloadly/ESign/AltStore before installing)")

        print(f"[5] Writing output IPA to {out_path}...")
        _write_zip_preserving_attrs(payload_stage, out_path)
        print("[6] Done!")


def main() -> None:
    parser = argparse.ArgumentParser(description="Inject KeyAuthSDK.framework into an IPA (standalone Unity or legacy)")
    parser.add_argument("--ipa", required=True, help="Path to source .ipa")
    parser.add_argument("--framework", required=True, help="Path to built KeyAuthSDK.framework or artifact zip")
    parser.add_argument("--server-url", required=True, help="Your KeyAuth FastAPI server URL")
    parser.add_argument("--public-key", required=True, help="Ed25519 base64 public key from cli.py pubkey")
    parser.add_argument("--get-key-url", default="", help="Optional AOV_KEY_GET portal URL for the Get Key button")
    parser.add_argument("--target", choices=["auto", "unity", "main", "awscognito"], default="auto", help="Injection target binary")
    parser.add_argument("--menu-name", default="KT AOV", help="Menu header name (legacy AWSCognito <= 15 ASCII chars)")
    parser.add_argument("--github-url", default="https://github.com/KH4NHTU0N9", help="Single social link URL")
    parser.add_argument("--bundle-id", default="com.ktaov.aovx", help="App CFBundleIdentifier")
    parser.add_argument("--title", default="KT AOV", help="Key prompt modal title")
    parser.add_argument("--subtitle", default="Enter your activation key", help="Key prompt modal subtitle")
    parser.add_argument("--allow-http", action="store_true", help="Enable NSAllowsArbitraryLoads in .app/Info.plist for LAN HTTP tests")
    parser.add_argument("--enable-120hz", action="store_true", help="Enable CADisableMinimumFrameDurationOnPhone in .app/Info.plist")
    parser.add_argument("--out", required=True, help="Output .ipa path")
    parser.add_argument("--no-sign", action="store_true", help="Skip macOS ad-hoc codesign")
    args = parser.parse_args()

    build_ipa(
        ipa_path=Path(args.ipa),
        framework_path=Path(args.framework),
        server_url=args.server_url,
        public_key=args.public_key,
        out_path=Path(args.out),
        get_key_url=args.get_key_url,
        target_mode=args.target,
        menu_name=args.menu_name,
        github_url=args.github_url,
        bundle_id=args.bundle_id,
        title=args.title,
        subtitle=args.subtitle,
        allow_http=args.allow_http,
        enable_120hz=args.enable_120hz,
        sign=not args.no_sign,
    )


if __name__ == "__main__":
    main()
