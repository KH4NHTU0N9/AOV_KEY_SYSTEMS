# scripts/inject_ipa.py
import argparse
import os
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC


def inject_load_dylib(macho_bytes: bytearray, dylib_path: str) -> bool:
    """Insert an LC_LOAD_DYLIB load command into a 64-bit Mach-O binary in-place."""
    if len(macho_bytes) < 32:
        raise ValueError("File too small to be a valid Mach-O binary")

    magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack("<8I", macho_bytes[:32])
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

    # Pack LC_LOAD_DYLIB command
    load_cmd = struct.pack("<IIIIII", LC_LOAD_DYLIB, cmdsize, 24, 2, 0x00010000, 0x00010000)
    load_cmd += target_bytes + b"\x00" * (cmdsize - 24 - len(target_bytes))
    macho_bytes[cmd_end : cmd_end + cmdsize] = load_cmd

    # Update Mach-O header counts
    struct.pack_into("<II", macho_bytes, 16, ncmds + 1, sizeofcmds + cmdsize)
    return True


def patch_awscognito_optional(
    data: bytearray,
    menu_name: str | None,
    github_url: str | None = "https://github.com/KH4NHTU0N9",
) -> None:
    """Neutralize fallback third-party login UI, rebrand header/TUMADAM strings, and keep only GitHub link."""
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
            struct.pack_into("<I", data, 0x241F040, 0xAA0803F6)  # mov x22, x8

        # Replace "TUMADAM" brand label at 0x2550b9f (CFString 0x2a2a598)
        if data[0x2550B9F : 0x2550B9F + 8] == b"TUMADAM\x00":
            brand = (menu_name or "KT AOV").encode("ascii")[:7]
            data[0x2550B9F : 0x2550B9F + 8] = brand + b"\x00" * (8 - len(brand))
            struct.pack_into("<Q", data, 0x2A2A598 + 24, len(brand))

        # Replace TUMADAM. cache prefix strings preserving exact 8-byte length
        for off in [0x25512A9, 0x25512CA, 0x25512E4]:
            if data[off : off + 8] == b"TUMADAM.":
                data[off : off + 8] = b"KT_AOV_."

        # Keep only 1 social button ("GitHub") pointing to github_url
        if github_url and data[0x2550E73 : 0x2550E8C] == b"Telegram\x00Discord\x00Website\x00":
            url_bytes = github_url.strip().encode("ascii")
            if len(url_bytes) > 82:
                raise ValueError("github_url too long for inline string slot (max 82 bytes)")

            data[0x2550E73 : 0x2550E7C] = b"GitHub\x00\x00\x00"
            struct.pack_into("<Q", data, 0x2A2B138 + 24, 6)

            # Wipe Telegram/Discord/Website URLs and write GitHub URL
            data[0x2550E7C : 0x2550EE0] = b"\x00" * (0x2550EE0 - 0x2550E7C)
            data[0x2550E8C : 0x2550E8C + len(url_bytes)] = url_bytes
            struct.pack_into("<Q", data, 0x2A2B198 + 24, len(url_bytes))

            # Patch array counts, button width divisor, and loop bound from 3 -> 1
            if struct.unpack("<I", data[0x2426998 : 0x242699C])[0] == 0x52800063:
                struct.pack_into("<I", data, 0x2426998, 0x52800023)  # mov w3, #1 (titles)
                struct.pack_into("<I", data, 0x24269DC, 0x52800023)  # mov w3, #1 (urls)
                struct.pack_into("<I", data, 0x24269FC, 0x1E6E1000)  # fmov d0, #1.0
                struct.pack_into("<I", data, 0x2426D28, 0xF100067F)  # cmp x19, #1


def configure_framework_plist(framework_dir: Path, server_url: str, public_key: str, title: str, subtitle: str) -> None:
    """Write KeyAuth server URL and Ed25519 public key into KeyAuthSDK.framework/Info.plist."""
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

    plist_data["KeyAuthServerURL"] = server_url.rstrip("/")
    plist_data["KeyAuthPublicKey"] = public_key.strip()
    plist_data["KeyAuthTitle"] = title
    plist_data["KeyAuthSubtitle"] = subtitle

    with plist_path.open("wb") as f:
        plistlib.dump(plist_data, f)


def rebrand_plists(app_dir: Path, bundle_id: str) -> list[Path]:
    """Replace third-party tumadam bundle identifiers and decrypt attribution tags."""
    updated_frameworks: list[Path] = []
    app_plist = app_dir / "Info.plist"
    if app_plist.exists():
        data = plistlib.loads(app_plist.read_bytes())
        if "tumadam" in str(data.get("CFBundleIdentifier", "")).lower():
            data["CFBundleIdentifier"] = bundle_id
        data.pop("DecryptedBy", None)
        app_plist.write_bytes(plistlib.dumps(data))

    rt_fw = app_dir / "Frameworks" / "Runtime9r53i.framework"
    rt_plist = rt_fw / "Info.plist"
    if rt_plist.exists():
        rdata = plistlib.loads(rt_plist.read_bytes())
        if "tumadam" in str(rdata.get("CFBundleIdentifier", "")).lower():
            rdata["CFBundleIdentifier"] = f"{bundle_id}.embedded.runtime9r53i"
            rt_plist.write_bytes(plistlib.dumps(rdata))
            updated_frameworks.append(rt_fw)
    return updated_frameworks


def build_ipa(
    ipa_path: Path,
    framework_path: Path,
    server_url: str,
    public_key: str,
    out_path: Path,
    menu_name: str | None = "KT AOV",
    github_url: str | None = "https://github.com/KH4NHTU0N9",
    bundle_id: str = "com.ktaov.aovx",
    title: str = "KT AOV",
    subtitle: str = "Enter your activation key",
    sign: bool = True,
) -> None:
    if not ipa_path.exists():
        raise FileNotFoundError(f"IPA not found: {ipa_path}")
    if not framework_path.exists():
        raise FileNotFoundError(
            f"KeyAuthSDK.framework not found at '{framework_path}'. "
            "You must first push key-auth-system to GitHub, run the 'Build KeyAuthSDK iOS Framework' Action, "
            "and download the 'KeyAuthSDK-ios-arm64' artifact."
        )

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)

        if framework_path.is_file() and framework_path.suffix.lower() == ".zip":
            fw_unzip_dir = work / "_fw_unzip"
            with zipfile.ZipFile(framework_path, "r") as fz:
                fz.extractall(fw_unzip_dir)
            found_fw = list(fw_unzip_dir.rglob("KeyAuthSDK.framework"))
            if not found_fw:
                # GitHub artifact zips often wrap KeyAuthSDK.framework.zip inside KeyAuthSDK-ios-arm64.zip
                inner_zips = list(fw_unzip_dir.rglob("*.zip"))
                for iz in inner_zips:
                    with zipfile.ZipFile(iz, "r") as izf:
                        izf.extractall(fw_unzip_dir)
                found_fw = list(fw_unzip_dir.rglob("KeyAuthSDK.framework"))
            if not found_fw:
                raise FileNotFoundError(f"KeyAuthSDK.framework not found inside archive {framework_path}")
            framework_path = found_fw[0]

        if not (framework_path / "KeyAuthSDK").exists():
            raise FileNotFoundError(f"KeyAuthSDK binary missing inside {framework_path}")

        print("[1] Unpacking IPA...")
        with zipfile.ZipFile(ipa_path, "r") as z:
            z.extractall(work)

        app_dirs = list((work / "Payload").glob("*.app"))
        if not app_dirs:
            raise RuntimeError("No .app bundle found under Payload/")
        app_dir = app_dirs[0]
        frameworks_dir = app_dir / "Frameworks"

        aws_fw = frameworks_dir / "AWSCognito.framework"
        aws_bin = aws_fw / "AWSCognito"
        if not aws_bin.exists():
            raise RuntimeError(f"Expected AWSCognito binary at {aws_bin}")

        print("[2] Installing & configuring KeyAuthSDK.framework...")
        dst_fw = frameworks_dir / "KeyAuthSDK.framework"
        if dst_fw.exists():
            shutil.rmtree(dst_fw)
        shutil.copytree(framework_path, dst_fw)
        configure_framework_plist(dst_fw, server_url, public_key, title, subtitle)

        print("[3] Injecting LC_LOAD_DYLIB & rebranding AWSCognito...")
        raw_aws = bytearray(aws_bin.read_bytes())
        added = inject_load_dylib(raw_aws, "@rpath/KeyAuthSDK.framework/KeyAuthSDK")
        print(f"    LC_LOAD_DYLIB added: {added}")
        patch_awscognito_optional(raw_aws, menu_name, github_url=github_url)
        aws_bin.write_bytes(raw_aws)
        extra_signed_fws = rebrand_plists(app_dir, bundle_id)

        if sign and sys.platform == "darwin":
            print("[4] Ad-hoc codesigning modified frameworks...")
            for fw in [dst_fw, aws_fw, *extra_signed_fws]:
                subprocess.check_call(["codesign", "-f", "-s", "-", str(fw)])
                subprocess.check_call(["codesign", "-v", str(fw)])
        else:
            print("[4] Skipping codesign (re-sign via Sideloadly/ESign/AltStore before installing)")

        print(f"[5] Writing output IPA to {out_path}...")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zout:
            for root, _dirs, files in os.walk(work):
                for file in files:
                    full = Path(root) / file
                    rel = full.relative_to(work)
                    zout.write(full, str(rel))
        print("[6] Done!")


def main() -> None:
    parser = argparse.ArgumentParser(description="Inject KeyAuthSDK.framework into an uncracked IPA")
    parser.add_argument("--ipa", required=True, help="Path to original uncracked .ipa")
    parser.add_argument("--framework", required=True, help="Path to built KeyAuthSDK.framework")
    parser.add_argument("--server-url", required=True, help="Your KeyAuth FastAPI server URL")
    parser.add_argument("--public-key", required=True, help="Ed25519 base64 public key from cli.py pubkey")
    parser.add_argument("--menu-name", default="KT AOV", help="Menu header name (<= 15 ASCII chars)")
    parser.add_argument("--github-url", default="https://github.com/KH4NHTU0N9", help="Single social link URL")
    parser.add_argument("--bundle-id", default="com.ktaov.aovx", help="App CFBundleIdentifier")
    parser.add_argument("--title", default="KT AOV", help="Key prompt modal title")
    parser.add_argument("--subtitle", default="Enter your activation key", help="Key prompt modal subtitle")
    parser.add_argument("--out", required=True, help="Output .ipa path")
    parser.add_argument("--no-sign", action="store_true", help="Skip macOS ad-hoc codesign")
    args = parser.parse_args()

    build_ipa(
        ipa_path=Path(args.ipa),
        framework_path=Path(args.framework),
        server_url=args.server_url,
        public_key=args.public_key,
        out_path=Path(args.out),
        menu_name=args.menu_name,
        github_url=args.github_url,
        bundle_id=args.bundle_id,
        title=args.title,
        subtitle=args.subtitle,
        sign=not args.no_sign,
    )


if __name__ == "__main__":
    main()
