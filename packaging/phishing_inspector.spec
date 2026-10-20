# -*- mode: python ; coding: utf-8 -*-
# Builds both language variants: pyinstaller packaging/phishing_inspector.spec
# All paths are relative to the repository, so the build works from any checkout.

import re
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).resolve().parent
SRC = ROOT / "src"
VERSION = re.search(
    r'__version__\s*=\s*"([^"]+)"',
    (SRC / "phishing_inspector" / "__init__.py").read_text(encoding="utf-8"),
).group(1)

DATAS = [(str(ROOT / "assets"), "assets")]
# Offline Public Suffix List snapshot; without it domain parsing falls back to a short list.
DATAS += collect_data_files("tldextract")
HIDDEN = collect_submodules("py7zr")
try:
    HIDDEN += collect_submodules("extract_msg")
except Exception:
    pass


def build(language: str, suffix: str):
    a = Analysis(
        [str(ROOT / "packaging" / f"launcher_{language}.py")],
        pathex=[str(SRC)],
        binaries=[],
        datas=DATAS,
        hiddenimports=HIDDEN,
        hookspath=[],
        hooksconfig={},
        runtime_hooks=[],
        excludes=["pytest"],
        noarchive=False,
        optimize=0,
    )
    pyz = PYZ(a.pure)
    return EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name=f"PhishingInspector-{VERSION}{suffix}",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=True,
        upx_exclude=[],
        runtime_tmpdir=None,
        console=False,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )


build("pl", "")
build("en", "-EN")
