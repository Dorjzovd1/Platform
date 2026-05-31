"""Forensic parser-уудын нэгж тест (CLI шаардахгүй)."""
from __future__ import annotations

import struct
from datetime import datetime, timezone

from app.services import recycle
from app.services.metadata import assess_severity
from app.models import Severity


def test_filetime_conversion():
    # 2021-01-01 00:00:00 UTC-ийн FILETIME.
    dt = datetime(2021, 1, 1, tzinfo=timezone.utc)
    seconds = dt.timestamp()
    filetime = int((seconds + recycle._FILETIME_EPOCH_DIFF) * 10_000_000)
    back = recycle._filetime_to_dt(filetime)
    assert back is not None
    assert abs((back - dt).total_seconds()) < 2


def test_parse_i_file_v2(tmp_path):
    # $I файл (version 2) бэлтгэнэ.
    path_str = "C:\\Users\\x\\secret.txt"
    encoded = path_str.encode("utf-16-le") + b"\x00\x00"
    name_len = len(path_str) + 1
    data = (
        struct.pack("<q", 2)
        + struct.pack("<q", 12345)
        + struct.pack("<q", 132_000_000_000_000_000)
        + struct.pack("<i", name_len)
        + encoded
    )
    f = tmp_path / "$IABCDEF"
    f.write_bytes(data)
    art = recycle.parse_i_file(str(f))
    assert art is not None
    assert art.size == 12345
    assert "secret.txt" in art.original_path


def test_severity_keywords():
    assert assess_severity("passwords.txt", "/x/passwords.txt", True) == Severity.HIGH
    assert assess_severity("report.docx", "/x/report.docx", True) == Severity.MEDIUM
    assert assess_severity("random.bin", "/x/random.bin", False) == Severity.INFO


def test_trashinfo(tmp_path):
    info_dir = tmp_path / ".Trash-1000" / "info"
    info_dir.mkdir(parents=True)
    ti = info_dir / "leak.zip.trashinfo"
    ti.write_text(
        "[Trash Info]\nPath=/home/u/leak.zip\nDeletionDate=2021-05-01T12:00:00\n",
        encoding="utf-8",
    )
    art = recycle.parse_trashinfo(str(ti))
    assert art is not None
    assert art.original_path == "/home/u/leak.zip"
    assert art.deleted_time is not None
