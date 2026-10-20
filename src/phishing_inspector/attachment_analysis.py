from __future__ import annotations

import hashlib
import io
import re
import zipfile
from pathlib import Path

from .html_links import scan_html
from .models import AttachmentInfo


HIGH_RISK_EXTENSIONS = {
    ".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".msi", ".dll", ".cpl",
    ".pif", ".msc", ".jar", ".chm", ".xll", ".iqy", ".slk", ".url", ".reg",
    ".appx", ".msix", ".appinstaller", ".application", ".wsc", ".sct",
    ".psm1", ".ps1xml", ".settingcontent-ms", ".one", ".onepkg", ".msp",
    ".gadget", ".inf", ".scf", ".library-ms", ".search-ms",
}

MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".xlam", ".dotm", ".xltm", ".ppsm", ".potm"}

# Web pages and SVG images open in the browser and can show a fake login
# page or run script ("HTML smuggling").
HTML_EXTENSIONS = {".html", ".htm", ".shtml", ".xhtml", ".svg", ".svgz", ".mht", ".mhtml"}

# Disk images: opening one mounts it and hides the "downloaded from the
# Internet" mark from the files inside.
DISK_IMAGE_EXTENSIONS = {".iso", ".img", ".vhd", ".vhdx"}

ARCHIVE_EXTENSIONS = {
    ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab", ".arj", ".lzh", ".ace",
}

_PDF_URI = re.compile(rb"/URI\s*\(([^)]{4,2000})\)")
_PDF_JS = re.compile(rb"/(?:JavaScript|JS|Launch|EmbeddedFile)\b")
_HTML_ACTIVE = re.compile(
    r"<script|window\.location|document\.write|atob\(|eval\(|"
    r"\.submit\(|fetch\(|xmlhttprequest|<meta[^>]+refresh",
    re.I,
)


def _detect_double_extension(filename: str) -> bool:
    name = filename.lower()
    common_decoys = (
        ".pdf.", ".doc.", ".docx.", ".xls.", ".xlsx.",
        ".jpg.", ".jpeg.", ".png.", ".txt.",
    )
    return any(decoy in name for decoy in common_decoys)


def _classify_archive_names(names: list[str]) -> tuple[list[str], bool]:
    notes: list[str] = []
    dangerous = False

    files = [name for name in names if name and not name.endswith(("/", "\\"))]
    notes.append(
        f"Archive inspected without extracting or executing files: {len(files)} file(s) found"
    )

    high_risk: list[str] = []
    macros: list[str] = []
    nested: list[str] = []
    deceptive: list[str] = []
    web: list[str] = []
    images: list[str] = []

    for name in files:
        suffix = Path(name).suffix.lower()

        if suffix in HIGH_RISK_EXTENSIONS:
            high_risk.append(name)

        if suffix in MACRO_EXTENSIONS:
            macros.append(name)

        if suffix in ARCHIVE_EXTENSIONS:
            nested.append(name)

        if suffix in HTML_EXTENSIONS:
            web.append(name)

        if suffix in DISK_IMAGE_EXTENSIONS:
            images.append(name)

        if _detect_double_extension(name):
            deceptive.append(name)

    if high_risk:
        dangerous = True
        notes.append(
            "Archive contains executable/script file(s): " + ", ".join(high_risk[:5])
        )

    if macros:
        dangerous = True
        notes.append(
            "Archive contains macro-enabled Office file(s): " + ", ".join(macros[:5])
        )

    if deceptive:
        dangerous = True
        notes.append(
            "Archive contains deceptive double-extension file(s): "
            + ", ".join(deceptive[:5])
        )

    if web:
        dangerous = True
        notes.append("Archive contains web page / SVG file(s): " + ", ".join(web[:5]))

    if images:
        dangerous = True
        notes.append("Archive contains disk image file(s): " + ", ".join(images[:5]))

    if nested:
        notes.append(
            "Archive contains nested archive(s): " + ", ".join(nested[:5])
        )

    if not (high_risk or macros or deceptive or web or images):
        notes.append(
            "No high-risk filename indicators were found inside the archive; "
            "file contents were not executed"
        )

    return notes, dangerous


def _archive_codes(notes: list[str]) -> list[str]:
    joined = " ".join(notes).lower()
    codes: list[str] = []

    if "executable/script" in joined or "double-extension" in joined:
        codes.append("ATTACHMENT_EXECUTABLE")
    if "macro-enabled" in joined:
        codes.append("ATTACHMENT_MACRO")
    if "web page / svg" in joined:
        codes.append("ATTACHMENT_HTML")
    if "disk image" in joined:
        codes.append("ATTACHMENT_DISK_IMAGE")

    return codes


def _inspect_zip(payload: bytes) -> tuple[list[str], bool, bool]:
    """(notes, dangerous, encrypted)"""
    try:
        with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
            infos = archive.infolist()
            encrypted = any(info.flag_bits & 0x1 for info in infos)
            notes, dangerous = _classify_archive_names([info.filename for info in infos])
            if encrypted:
                notes.append(
                    "Archive is password-protected, so mail filters could not scan it"
                )
            return notes, dangerous, encrypted
    except zipfile.BadZipFile:
        return ["Archive could not be parsed as a valid ZIP file"], True, False
    except Exception as exc:
        return [f"ZIP archive inspection failed: {type(exc).__name__}: {exc}"], True, False


def _inspect_7z(payload: bytes) -> tuple[list[str], bool, bool]:
    try:
        import py7zr  # type: ignore
    except ImportError:
        return [
            "7z archive detected, but contents could not be inspected because "
            "the py7zr component is not installed"
        ], False, False

    try:
        with py7zr.SevenZipFile(io.BytesIO(payload), mode="r") as archive:
            encrypted = bool(getattr(archive, "needs_password", lambda: False)())
            notes, dangerous = _classify_archive_names(list(archive.getnames()))
            if encrypted:
                notes.append(
                    "Archive is password-protected, so mail filters could not scan it"
                )
            return notes, dangerous, encrypted
    except Exception as exc:
        text = f"{type(exc).__name__}: {exc}"
        encrypted = "password" in text.lower()
        notes = [f"7z archive contents could not be inspected safely: {text}"]
        if encrypted:
            notes.append("Archive is password-protected, so mail filters could not scan it")
        return notes, True, encrypted


def _sniff_text(payload: bytes, limit: int = 2_000_000) -> str:
    return payload[:limit].decode("utf-8", errors="replace")


def extract_attachment_urls(filename: str | None, content_type: str, payload: bytes) -> list[tuple[str, str]]:
    """Links inside HTML/SVG and PDF attachments as (url, link text)."""
    suffix = Path(filename or "").suffix.lower()
    found: list[tuple[str, str]] = []

    if suffix in HTML_EXTENSIONS or content_type in {"text/html", "image/svg+xml"}:
        scan = scan_html(_sniff_text(payload))
        for link in scan.links:
            found.append((link.href, link.text))
    elif suffix == ".pdf" or content_type == "application/pdf" or payload[:5] == b"%PDF-":
        for match in _PDF_URI.finditer(payload[:20_000_000]):
            raw = match.group(1).decode("latin-1", errors="replace").replace("\\", "")
            found.append((raw, ""))

    return found


def analyze_attachment(
    filename: str | None,
    content_type: str,
    payload: bytes,
) -> AttachmentInfo:
    safe_filename = filename or "unnamed-attachment"
    suffix = Path(safe_filename).suffix.lower()

    reasons: list[str] = []
    codes: list[str] = []
    suspicious = False

    def flag(code: str, reason: str) -> None:
        nonlocal suspicious
        suspicious = True
        if code not in codes:
            codes.append(code)
        reasons.append(reason)

    if suffix in HIGH_RISK_EXTENSIONS:
        flag("ATTACHMENT_EXECUTABLE", f"High-risk executable or script extension: {suffix}")

    if suffix in MACRO_EXTENSIONS:
        flag("ATTACHMENT_MACRO", f"Macro-enabled Office document: {suffix}")

    if _detect_double_extension(safe_filename):
        flag("ATTACHMENT_DOUBLE_EXTENSION", "Attachment uses a potentially deceptive double extension")

    if content_type in {
        "application/x-msdownload",
        "application/x-dosexec",
        "application/vnd.microsoft.portable-executable",
    }:
        flag("ATTACHMENT_EXECUTABLE", f"Executable MIME type detected: {content_type}")

    # The real file type, whatever the name says.
    if payload[:2] == b"MZ" and suffix not in HIGH_RISK_EXTENSIONS:
        flag(
            "ATTACHMENT_EXECUTABLE",
            "File content is a Windows executable (MZ header) despite its name",
        )

    head = payload[:1024].lstrip().lower()
    looks_html = head.startswith((b"<!doctype html", b"<html", b"<svg", b"<?xml"))

    if suffix in HTML_EXTENSIONS or (looks_html and suffix not in {".xml", ".txt", ""}):
        text = _sniff_text(payload)
        scan = scan_html(text)
        active = (
            scan.has_password_field
            or scan.has_script
            or bool(_HTML_ACTIVE.search(text))
            or any(link.kind == "form" for link in scan.links)
        )

        if active:
            flag(
                "ATTACHMENT_HTML_ACTIVE",
                "Web page / SVG attachment contains a form, password field or script "
                "and can show a fake login page",
            )
        else:
            flag(
                "ATTACHMENT_HTML",
                "Web page / SVG attachment opens in the browser and is a common way "
                "to deliver fake login pages",
            )

        if suffix not in HTML_EXTENSIONS:
            reasons.append(f"File content is a web page despite the {suffix} extension")

    if suffix in DISK_IMAGE_EXTENSIONS:
        flag(
            "ATTACHMENT_DISK_IMAGE",
            f"Disk image attachment ({suffix}) can hide executable files from security warnings",
        )

    if suffix == ".pdf" or payload[:5] == b"%PDF-":
        if _PDF_JS.search(payload[:20_000_000]):
            flag(
                "ATTACHMENT_PDF_ACTIVE",
                "PDF contains JavaScript, a launch action or an embedded file",
            )

    archive_notes: list[str] = []
    archive_suspicious = False
    encrypted = False

    if suffix == ".zip" or (payload[:4] == b"PK\x03\x04" and suffix in ARCHIVE_EXTENSIONS):
        archive_notes, archive_suspicious, encrypted = _inspect_zip(payload)
    elif suffix == ".7z":
        archive_notes, archive_suspicious, encrypted = _inspect_7z(payload)
    elif suffix in ARCHIVE_EXTENSIONS:
        archive_notes = [
            f"Archive/container attachment detected: {suffix}. "
            "Contents were not automatically extracted or executed"
        ]

    if archive_notes:
        reasons.extend(archive_notes)
        for code in _archive_codes(archive_notes):
            if code not in codes:
                codes.append(code)
        suspicious = suspicious or archive_suspicious

        if archive_suspicious and not _archive_codes(archive_notes):
            codes.append("ATTACHMENT_ARCHIVE_UNREADABLE")

    if encrypted:
        flag("ATTACHMENT_ENCRYPTED_ARCHIVE", "Password-protected archive")
        reasons.pop()  # the archive note above already explains it

    sha256 = hashlib.sha256(payload).hexdigest()

    return AttachmentInfo(
        filename=safe_filename,
        content_type=content_type,
        size=len(payload),
        sha256=sha256,
        suspicious=suspicious,
        reasons=reasons,
        rule_codes=codes,
    )
