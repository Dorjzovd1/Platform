"""Metadata нормчлол — MIME төрөл, хэмжээ, severity, timeline үүсгэх."""
from __future__ import annotations

import mimetypes
import os
from datetime import datetime

from app.models import Finding, Severity, TimelineEvent
from app.services import tools

# Forensic ач холбогдол өндөр өргөтгөлүүд (severity тооцоход).
_SENSITIVE_EXT = {
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "csv",
    "key", "pem", "kdbx", "zip", "rar", "7z", "sql", "db",
}
_SENSITIVE_KEYWORDS = (
    "password", "secret", "confidential", "leak", "private", "passwords",
    "нууц", "private_key", "backup",
)


def guess_mime(path: str, file_name: str = "") -> str:
    """MIME төрлийг `file` команд эсвэл өргөтгөлөөр тодорхойлно."""
    if path and os.path.exists(path) and tools.is_available("file"):
        result = tools.run(["file", "--brief", "--mime-type", path])
        if result.ok and result.stdout.strip():
            return result.stdout.strip()
    name = file_name or path
    mime, _ = mimetypes.guess_type(name)
    return mime or "application/octet-stream"


def assess_severity(file_name: str, original_path: str, recovered: bool) -> Severity:
    """Файлын нэр/зам дээр үндэслэн сэжигтэй байдлын зэрэглэл тооцно."""
    text = f"{file_name} {original_path}".lower()
    ext = os.path.splitext(file_name)[1].lstrip(".").lower()

    if any(kw in text for kw in _SENSITIVE_KEYWORDS):
        return Severity.HIGH
    if ext in _SENSITIVE_EXT:
        return Severity.MEDIUM if recovered else Severity.LOW
    return Severity.INFO


def build_timeline_events(finding: Finding) -> list[TimelineEvent]:
    """Finding-ийн MAC timestamp бүрээс timeline үйл явдал үүсгэнэ."""
    events: list[TimelineEvent] = []
    mapping: list[tuple[datetime | None, str, str]] = [
        (finding.crtime, "B", "Born (үүссэн)"),
        (finding.mtime, "M", "Modified (өөрчилсөн)"),
        (finding.atime, "A", "Accessed (хандсан)"),
        (finding.ctime, "C", "Changed (метадата өөрчлөгдсөн)"),
    ]
    label = finding.file_name or finding.original_path or finding.inode
    for ts, kind, desc in mapping:
        if ts is None:
            continue
        events.append(
            TimelineEvent(
                scan_id=finding.scan_id,
                timestamp=ts,
                event_type=kind,
                description=f"{desc}: {label}",
            )
        )
    return events
