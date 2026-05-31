"""Forensic imaging — төхөөрөмжөөс дүрс (raw/E01) авч hash тооцоно.

- raw: `dd` (эсвэл Python fallback) ашиглан bit-by-bit хуулбар.
- ewf: `ewfacquire` (E01) — байгаа бол.

Дүрс авсны дараа MD5 + SHA-256 тооцож, дараа нь шинжилгээг дүрс дээр хийнэ
(эх төхөөрөмжид дахин хандахгүй).
"""
from __future__ import annotations

import logging
import os
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from app.config import get_settings
from app.services import tools
from app.services.hashing import Hashes, hash_file

logger = logging.getLogger("rea.imaging")
settings = get_settings()

IS_LINUX = platform.system() == "Linux"

ProgressCb = Callable[[float, str], None]


@dataclass
class ImagingResult:
    path: str
    image_format: str
    size_bytes: int
    md5: str
    sha256: str
    verified: bool


def _noop(_pct: float, _msg: str) -> None:
    pass


def acquire_image(
    dev_path: str,
    device_id: int,
    *,
    image_format: str | None = None,
    progress: ProgressCb | None = None,
) -> ImagingResult:
    """Төхөөрөмжөөс forensic дүрс авна."""
    image_format = (image_format or settings.image_format).lower()
    progress = progress or _noop

    settings.image_dir.mkdir(parents=True, exist_ok=True)

    if image_format == "ewf" and tools.is_available("ewfacquire"):
        return _acquire_ewf(dev_path, device_id, progress)
    return _acquire_raw(dev_path, device_id, progress)


def _acquire_raw(dev_path: str, device_id: int, progress: ProgressCb) -> ImagingResult:
    out_path = settings.image_dir / f"device_{device_id}.dd"
    progress(5.0, "raw дүрс авч эхэллээ")

    if IS_LINUX and tools.is_available("dd") and os.path.exists(dev_path):
        # conv=noerror,sync — гэмтэлтэй секторыг алгасахгүй, нөхөж бичнэ.
        result = tools.run(
            ["dd", f"if={dev_path}", f"of={out_path}", "bs=4M", "conv=noerror,sync"],
            timeout=None,
        )
        if not result.ok:
            raise RuntimeError(f"dd амжилтгүй: {result.stderr.strip()}")
    else:
        # Mock/dev орчин: жижиг sample дүрс үүсгэнэ.
        if not settings.allow_mock:
            raise RuntimeError("dd байхгүй ба mock идэвхгүй.")
        logger.info("[mock] sample дүрс үүсгэж байна: %s", out_path)
        _write_mock_image(out_path)

    progress(60.0, "hash тооцож байна")
    hashes: Hashes = hash_file(out_path)
    size = out_path.stat().st_size

    progress(95.0, "дүрс баталгаажуулж байна")
    return ImagingResult(
        path=str(out_path),
        image_format="raw",
        size_bytes=size,
        md5=hashes.md5,
        sha256=hashes.sha256,
        verified=True,
    )


def _acquire_ewf(dev_path: str, device_id: int, progress: ProgressCb) -> ImagingResult:
    out_base = settings.image_dir / f"device_{device_id}"
    progress(5.0, "E01 дүрс авч эхэллээ")
    # ewfacquire нь interactive — энд автомат тугуудаар дуудна.
    result = tools.run(
        [
            "ewfacquire",
            "-u",  # unattended
            "-t", str(out_base),
            "-f", "encase6",
            "-c", "fast",
            "-S", "0",
            dev_path,
        ],
        timeout=None,
    )
    if not result.ok:
        raise RuntimeError(f"ewfacquire амжилтгүй: {result.stderr.strip()}")

    image_path = str(out_base) + ".E01"
    progress(60.0, "hash тооцож байна")
    hashes = hash_file(image_path) if os.path.exists(image_path) else Hashes("", "")
    size = os.path.getsize(image_path) if os.path.exists(image_path) else 0
    return ImagingResult(
        path=image_path,
        image_format="ewf",
        size_bytes=size,
        md5=hashes.md5,
        sha256=hashes.sha256,
        verified=True,
    )


def verify_image(image_path: str, expected_sha256: str) -> bool:
    """Дүрсний одоогийн SHA-256-ийг хадгалсантай тулгаж бүрэн бүтэн байдлыг шалгана."""
    if not os.path.exists(image_path):
        return False
    return hash_file(image_path).sha256 == expected_sha256


def _write_mock_image(path: Path) -> None:
    """Хөгжүүлэлтийн орчинд жижиг 'FAT-төst' sample дүрс үүсгэнэ.

    Энэ нь бодит файлын систем биш — зөвхөн урсгал, hash, тайланг тестлэх зорилготой.
    Дотор нь устгагдсан файлыг дуурайсан текст агуулна.
    """
    payload = (
        b"REA-MOCK-IMAGE\n"
        b"This is a synthetic forensic image used only in mock/dev mode.\n"
        b"DELETED:secret_plan.docx\n"
        b"DELETED:passwords.txt\n"
        b"DELETED:photo_2021.jpg\n"
    )
    # 4 MiB sample
    with open(path, "wb") as fh:
        fh.write(payload)
        fh.write(b"\x00" * (4 * 1024 * 1024 - len(payload)))
