# -*- mode: python ; coding: utf-8 -*-
# Microsoft Store build: one folder (onedir) with a single PhishingInspector.exe
# that picks PL/EN from the Windows display language. Used by build_msix.ps1.
# onedir starts faster than onefile and lets MSIX deduplicate files between updates.

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).resolve().parents[1]
SRC = ROOT / "src"

DATAS = [(str(ROOT / "assets"), "assets")]
DATAS += collect_data_files("tldextract")
HIDDEN = collect_submodules("py7zr")
try:
    HIDDEN += collect_submodules("extract_msg")
except Exception:
    pass

a = Analysis(
    [str(ROOT / "packaging" / "launcher_store.py")],
    pathex=[str(SRC)],
    datas=DATAS,
    hiddenimports=HIDDEN,
    excludes=["pytest"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="PhishingInspector",
    console=False,
    upx=False,
    icon=str(ROOT / "packaging" / "msix" / "app.ico"),
)
coll = COLLECT(exe, a.binaries, a.datas, name="PhishingInspector", upx=False)
