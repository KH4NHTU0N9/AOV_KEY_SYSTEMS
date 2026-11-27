# backend/tests/test_inject.py
import plistlib
import struct
import subprocess
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import inject_ipa  # noqa: E402


def _make_minimal_macho64() -> bytearray:
    """Create a minimal 64-bit Mach-O file with one __TEXT segment and header padding."""
    buf = bytearray(4096)
    ncmds = 1
    # LC_SEGMENT_64 (72 bytes) + 1 section (80 bytes) = 152 bytes
    sizeofcmds = 152
    struct.pack_into("<8I", buf, 0, 0xFEEDFACF, 0x0100000C, 0, 0x6, ncmds, sizeofcmds, 0, 0)

    # LC_SEGMENT_64 at offset 32
    struct.pack_into("<II", buf, 32, 0x19, 152)
    buf[40:46] = b"__TEXT"
    struct.pack_into("<QQQQIIII", buf, 56, 0, 4096, 0, 4096, 5, 5, 1, 0)

    # First section at offset 104: __text starting at file offset 2048
    buf[104:110] = b"__text"
    buf[120:126] = b"__TEXT"
    struct.pack_into("<QQIIII", buf, 136, 2048, 64, 2048, 2, 0, 0)
    return buf


def test_inject_load_dylib_and_plist(tmp_path: Path):
    macho = _make_minimal_macho64()
    target = "@rpath/KeyAuthSDK.framework/KeyAuthSDK"

    assert inject_ipa.inject_load_dylib(macho, target) is True
    # Second call must be idempotent
    assert inject_ipa.inject_load_dylib(macho, target) is False

    test_bin = tmp_path / "TestBin"
    test_bin.write_bytes(macho)

    if sys.platform == "darwin":
        out = subprocess.check_output(["otool", "-L", str(test_bin)]).decode("utf-8")
        assert target in out

    fw_dir = tmp_path / "KeyAuthSDK.framework"
    fw_dir.mkdir()
    inject_ipa.configure_framework_plist(
        fw_dir,
        server_url="https://auth.example.com/",
        public_key="PUBKEY_B64",
        title="KT AOV",
        subtitle="Enter key",
    )
    plist_data = plistlib.loads((fw_dir / "Info.plist").read_bytes())
    assert plist_data["KeyAuthServerURL"] == "https://auth.example.com"
    assert plist_data["KeyAuthPublicKey"] == "PUBKEY_B64"
    assert plist_data["KeyAuthTitle"] == "KT AOV"
    assert "KeyAuthGetKeyURL" not in plist_data


def test_build_standalone_unity_ipa_preserves_exec_bits_and_getkey_url(tmp_path: Path):
    import plistlib
    import zipfile

    app_root = tmp_path / "Payload" / "TestGame.app"
    unity_dir = app_root / "Frameworks" / "UnityFramework.framework"
    unity_dir.mkdir(parents=True)
    app_root.joinpath("Info.plist").write_bytes(
        plistlib.dumps({"CFBundleExecutable": "TestGame", "CFBundleIdentifier": "com.test.game"})
    )
    main_bin = app_root / "TestGame"
    main_bin.write_bytes(_make_minimal_macho64())
    main_bin.chmod(0o755)

    unity_bin = unity_dir / "UnityFramework"
    unity_bin.write_bytes(_make_minimal_macho64())
    unity_bin.chmod(0o755)

    ipa_in = tmp_path / "clean_in.ipa"

    # Build clean zip containing only Payload/
    stage_in = tmp_path / "stage_in"
    (stage_in / "Payload").mkdir(parents=True)
    import shutil
    shutil.copytree(app_root, stage_in / "Payload" / "TestGame.app")
    inject_ipa._write_zip_preserving_attrs(stage_in, ipa_in)

    fw_in = tmp_path / "KeyAuthSDK.framework"
    fw_in.mkdir()
    fw_bin = fw_in / "KeyAuthSDK"
    fw_bin.write_bytes(_make_minimal_macho64())
    fw_bin.chmod(0o755)

    ipa_out = tmp_path / "patched_out.ipa"
    inject_ipa.build_ipa(
        ipa_path=ipa_in,
        framework_path=fw_in,
        server_url="https://auth.ktaov.vn/",
        public_key="PUBKEY_B64",
        out_path=ipa_out,
        get_key_url="https://get.ktaov.vn/",
        target_mode="unity",
        allow_http=True,
        enable_120hz=True,
        sign=False,
    )

    with zipfile.ZipFile(ipa_out, "r") as zf:
        names = set(zf.namelist())
        assert "Payload/TestGame.app/Frameworks/KeyAuthSDK.framework/KeyAuthSDK" in names
        assert "_fw_unzip" not in " ".join(names)

        fw_info = plistlib.loads(zf.read("Payload/TestGame.app/Frameworks/KeyAuthSDK.framework/Info.plist"))
        assert fw_info["KeyAuthGetKeyURL"] == "https://get.ktaov.vn"

        app_info = plistlib.loads(zf.read("Payload/TestGame.app/Info.plist"))
        assert app_info["NSAppTransportSecurity"]["NSAllowsArbitraryLoads"] is True
        assert app_info["CADisableMinimumFrameDurationOnPhone"] is True

        exec_info = zf.getinfo("Payload/TestGame.app/TestGame")
        assert (exec_info.external_attr >> 16) & 0o111 == 0o111

        patched_unity = zf.read("Payload/TestGame.app/Frameworks/UnityFramework.framework/UnityFramework")
        assert b"KeyAuthSDK.framework/KeyAuthSDK" in patched_unity
