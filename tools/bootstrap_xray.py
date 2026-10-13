#!/usr/bin/env python3
"""Install a pinned official Xray-core Linux binary with a checked SHA-256 digest.

Version and digests were taken from the official XTLS/Xray-core GitHub release metadata.
Update the pin and both digests together after reviewing an official release.
"""
from __future__ import annotations

import hashlib
import io
import os
import platform
import urllib.request
import zipfile
from pathlib import Path

VERSION = "v26.3.27"
ASSETS = {
    "x86_64": (
        "Xray-linux-64.zip",
        "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
    ),
    "amd64": (
        "Xray-linux-64.zip",
        "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
    ),
    "aarch64": (
        "Xray-linux-arm64-v8a.zip",
        "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c",
    ),
    "arm64": (
        "Xray-linux-arm64-v8a.zip",
        "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c",
    ),
}
ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = ROOT / "bin"


def main() -> None:
    if platform.system() != "Linux":
        raise SystemExit("Automatic Xray bootstrap currently supports Linux hosts only.")
    machine = platform.machine().lower()
    asset = ASSETS.get(machine)
    if asset is None:
        raise SystemExit(f"Unsupported CPU architecture for automatic Xray install: {machine}")
    filename, expected_digest = asset
    url = f"https://github.com/XTLS/Xray-core/releases/download/{VERSION}/{filename}"
    request = urllib.request.Request(url, headers={"User-Agent": "NovaPanel-bootstrap/0.5.0"})
    print(f"[NovaPanel] Downloading official Xray-core {VERSION} ({filename})")
    with urllib.request.urlopen(request, timeout=90) as response:
        payload = response.read()
    digest = hashlib.sha256(payload).hexdigest()
    if digest != expected_digest:
        raise SystemExit(
            f"Xray archive SHA-256 mismatch. Expected {expected_digest}; got {digest}. "
            "Refusing to install an unverified binary."
        )

    BIN_DIR.mkdir(parents=True, exist_ok=True)
    copied: set[str] = set()
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        available = {Path(info.filename).name: info for info in archive.infolist() if not info.is_dir()}
        if "xray" not in available:
            raise SystemExit("Official Xray archive did not contain the expected xray binary.")
        for name in ("xray", "geoip.dat", "geosite.dat", "LICENSE", "README.md"):
            info = available.get(name)
            if info is None:
                continue
            target = BIN_DIR / name
            with archive.open(info, "r") as source, target.open("wb") as destination:
                while True:
                    block = source.read(1024 * 1024)
                    if not block:
                        break
                    destination.write(block)
            if name == "xray":
                target.chmod(0o755)
            copied.add(name)

    binary = BIN_DIR / "xray"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SystemExit("Xray binary installation did not complete.")
    print(f"[NovaPanel] Verified Xray-core {VERSION} installed at {binary}")
    if not {"geoip.dat", "geosite.dat"}.issubset(copied):
        print("[NovaPanel] Warning: geodata files were not included; geodata-based routes may need adjustment.")


if __name__ == "__main__":
    main()
