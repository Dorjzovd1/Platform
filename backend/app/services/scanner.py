"""Deleted File Detection оркестратор.

Нэг scan ажлыг (ScanJob) гүйцэтгэх логик:
  1. Шинжлэх эх сурвалж бэлтгэх (forensic дүрс эсвэл device).
  2. Хуваалт бүрээс устгагдсан файл илрүүлэх (TSK) + сэргээх.
  3. Unallocated/slack space-аас carving.
  4. Recycle/Trash artifact задлах.
  5. Metadata нормчлол + timeline үүсгэх.

Энэ функц нь тусдаа thread дотор ажиллаж, явцыг DB болон WebSocket hub руу мэдээлнэ.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from app.config import get_settings
from app.core import audit
from app.core.events import hub
from app.database import SessionLocal
from app.models import (
    Device,
    DeviceState,
    EvidenceImage,
    Finding,
    FindingType,
    ScanJob,
    ScanStatus,
)
from app.services import carving, imaging, metadata, recycle, tsk, writeblock
from app.services.hashing import hash_file

logger = logging.getLogger("rea.scanner")
settings = get_settings()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _progress(db, job: ScanJob, pct: float, step: str) -> None:
    job.progress = round(pct, 1)
    job.current_step = step
    db.add(job)
    db.commit()
    hub.publish(
        "scan_progress",
        {"scan_id": job.id, "progress": job.progress, "step": step, "status": job.status.value},
    )
    logger.info("[scan %s] %.1f%% — %s", job.id, pct, step)


def run_scan(scan_id: int) -> None:
    """ScanJob-ийг бүрэн гүйцэтгэнэ (background thread дотор)."""
    db = SessionLocal()
    try:
        job = db.get(ScanJob, scan_id)
        if job is None:
            logger.error("ScanJob %s олдсонгүй.", scan_id)
            return

        device = db.get(Device, job.device_id)
        options = job.options or {}

        job.status = ScanStatus.RUNNING
        job.started_at = _utcnow()
        db.add(job)
        db.commit()
        case_id = device.case_id if device else None
        audit.record(db, action="scan_started", target=device.dev_path if device else "", case_id=case_id, detail={"scan_id": scan_id})

        _progress(db, job, 2, "Эх сурвалж бэлтгэж байна")
        source_path, byte_offsets, mount_point = _prepare_source(db, job, device, options)

        total_findings = 0

        # 1) Устгагдсан файлууд (TSK) ----------------------------------------
        _progress(db, job, 15, "Устгагдсан файл хайж байна (TSK)")
        for off in byte_offsets:
            deleted = tsk.list_deleted(source_path, off)
            for entry in deleted:
                f = _finding_from_deleted(job.id, entry)
                _maybe_recover(source_path, off, entry, f, options)
                _finalize_finding(db, f)
                total_findings += 1

        # 2) Carving (unallocated/slack) -------------------------------------
        if options.get("run_carving", True):
            _progress(db, job, 50, "Unallocated/slack space carving")
            total_findings += _run_carving(db, job, source_path, byte_offsets)

        # 3) Recycle / Trash artifact ----------------------------------------
        if options.get("run_recycle", True):
            _progress(db, job, 75, "Recycle/Trash artifact задлаж байна")
            total_findings += _run_recycle(db, job, mount_point)

        # 4) Timeline --------------------------------------------------------
        _progress(db, job, 90, "Timeline үүсгэж байна")
        _build_timeline(db, job)

        if mount_point:
            writeblock.unmount(mount_point)

        job.status = ScanStatus.COMPLETED
        job.finished_at = _utcnow()
        job.progress = 100.0
        job.current_step = f"Дууссан — {total_findings} ул мөр илэрсэн"
        db.add(job)
        db.commit()
        audit.record(db, action="scan_completed", target=str(scan_id), case_id=case_id, detail={"findings": total_findings})
        hub.publish("scan_completed", {"scan_id": scan_id, "findings": total_findings})

    except Exception as exc:  # noqa: BLE001
        logger.exception("Scan %s алдаа", scan_id)
        db.rollback()
        job = db.get(ScanJob, scan_id)
        if job:
            job.status = ScanStatus.FAILED
            job.error = str(exc)
            job.finished_at = _utcnow()
            db.add(job)
            db.commit()
            hub.publish("scan_failed", {"scan_id": scan_id, "error": str(exc)})
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Source preparation
# --------------------------------------------------------------------------- #
def _prepare_source(db, job: ScanJob, device: Device, options: dict):
    """Шинжлэх эх сурвалж (дүрс эсвэл device) болон хуваалтын offset-уудыг бэлтгэнэ."""
    source_path = device.dev_path if device else ""
    mount_point: str | None = None

    if options.get("use_image", True):
        image = None
        if job.image_id:
            image = db.get(EvidenceImage, job.image_id)
        if image is None and device:
            image = (
                db.query(EvidenceImage)
                .filter(EvidenceImage.device_id == device.id)
                .order_by(EvidenceImage.id.desc())
                .first()
            )
        if image and os.path.exists(image.path):
            source_path = image.path
            job.image_id = image.id
            db.add(job)
            db.commit()

    # Хуваалтын offset-ууд (mmls).
    partitions = tsk.list_partitions(source_path)
    byte_offsets = [p.byte_offset for p in partitions] or [0]

    # Recycle artifact-д зориулж read-only mount оролдоно.
    if options.get("run_recycle", True) and device:
        try:
            mount_point = writeblock.mount_read_only(device.dev_path)
        except Exception as exc:  # noqa: BLE001
            logger.info("Read-only mount амжилтгүй (mock/dev байж болно): %s", exc)
            mount_point = None

    return source_path, byte_offsets, mount_point


# --------------------------------------------------------------------------- #
# Finding builders
# --------------------------------------------------------------------------- #
def _finding_from_deleted(scan_id: int, entry: tsk.DeletedEntry) -> Finding:
    file_name = os.path.basename(entry.name.rstrip("/")) or entry.name
    return Finding(
        scan_id=scan_id,
        finding_type=FindingType.DELETED_FILE,
        file_name=file_name,
        original_path=entry.name,
        inode=entry.inode,
        size_bytes=entry.size,
        mtime=entry.mtime,
        atime=entry.atime,
        ctime=entry.ctime,
        crtime=entry.crtime,
        source_tool="tsk",
        meta=entry.meta,
    )


def _maybe_recover(source_path, byte_offset, entry, finding: Finding, options: dict) -> None:
    if not options.get("recover_files", True) or entry.file_type != "r":
        return
    max_bytes = int(options.get("max_recover_size_mb", 512)) * 1024 * 1024
    if entry.size and entry.size > max_bytes:
        finding.meta = {**finding.meta, "skipped": "size_limit"}
        return
    dest = settings.recovered_dir / f"scan_{finding.scan_id}" / f"{entry.inode.replace('/', '_')}_{finding.file_name}"
    ok = tsk.recover_inode(source_path, entry.inode, str(dest), byte_offset)
    if ok and os.path.exists(dest):
        finding.recovered = True
        finding.recovered_path = str(dest)


def _apply_risk(finding: Finding) -> None:
    """Эрсдэлийн үнэлгээ хийж, severity + шалтгааныг meta-д хадгална."""
    risk = metadata.assess_risk(
        finding_type=finding.finding_type,
        file_name=finding.file_name,
        original_path=finding.original_path,
        recovered=finding.recovered,
    )
    finding.severity = risk.severity
    finding.meta = {
        **(finding.meta or {}),
        "risk_score": risk.score,
        "risk_reasons": risk.reasons,
        "risk_level": risk.severity.value,
    }


def _finalize_finding(db, finding: Finding) -> None:
    """Hash, MIME, severity нөхөж DB-д хадгална."""
    if finding.recovered and finding.recovered_path and os.path.exists(finding.recovered_path):
        try:
            h = hash_file(finding.recovered_path)
            finding.md5 = h.md5
            finding.sha256 = h.sha256
        except OSError:
            pass
        finding.mime_type = metadata.guess_mime(finding.recovered_path, finding.file_name)
    else:
        finding.mime_type = metadata.guess_mime("", finding.file_name)
    _apply_risk(finding)
    db.add(finding)
    db.commit()


def _run_carving(db, job: ScanJob, source_path: str, byte_offsets: list[int]) -> int:
    count = 0
    work_dir = settings.recovered_dir / f"scan_{job.id}" / "carved"
    work_dir.mkdir(parents=True, exist_ok=True)

    # Unallocated блокуудыг гаргаж, тэрхүү blob дээр carve хийнэ.
    blob = str(work_dir / "unallocated.blk")
    extracted = carving.extract_unallocated(source_path, blob, byte_offsets[0]) or source_path

    carved_files = carving.carve(extracted, str(work_dir / "out"))
    for cf in carved_files:
        h = hash_file(cf.path) if os.path.exists(cf.path) else None
        finding = Finding(
            scan_id=job.id,
            finding_type=FindingType.CARVED_FILE,
            file_name=cf.file_name,
            original_path="",
            size_bytes=cf.size,
            recovered=True,
            recovered_path=cf.path,
            mime_type=metadata.guess_mime(cf.path, cf.file_name),
            md5=h.md5 if h else "",
            sha256=h.sha256 if h else "",
            source_tool=cf.source_tool,
            meta=cf.meta,
        )
        _apply_risk(finding)
        db.add(finding)
        count += 1
    db.commit()

    # Slack/unallocated string ул мөр (нэг нэгтгэсэн finding).
    if os.path.exists(blob):
        strings = carving.scan_slack_strings(blob)
        if strings:
            slack = Finding(
                scan_id=job.id,
                finding_type=FindingType.SLACK_SPACE,
                file_name="unallocated_strings.txt",
                size_bytes=os.path.getsize(blob),
                source_tool="blkls",
                meta={"sample_strings": strings[:50], "total": len(strings)},
            )
            _apply_risk(slack)
            db.add(slack)
            count += 1
            db.commit()
    return count


def _run_recycle(db, job: ScanJob, mount_point: str | None) -> int:
    count = 0
    artifacts = recycle.scan_recycle(mount_point)
    for art in artifacts:
        file_name = os.path.basename(art.original_path.replace("\\", "/")) or art.original_path
        finding = Finding(
            scan_id=job.id,
            finding_type=FindingType.RECYCLE_ARTIFACT,
            file_name=file_name,
            original_path=art.original_path,
            size_bytes=art.size,
            mtime=art.deleted_time,
            recovered=bool(art.content_path),
            recovered_path=art.content_path,
            source_tool=art.source,
            meta=art.meta,
        )
        _apply_risk(finding)
        if art.content_path and os.path.exists(art.content_path):
            try:
                h = hash_file(art.content_path)
                finding.md5, finding.sha256 = h.md5, h.sha256
            except OSError:
                pass
        db.add(finding)
        count += 1
    db.commit()
    return count


def _build_timeline(db, job: ScanJob) -> None:
    findings = db.query(Finding).filter(Finding.scan_id == job.id).all()
    for f in findings:
        for event in metadata.build_timeline_events(f):
            event.finding_id = f.id
            db.add(event)
    db.commit()


# --------------------------------------------------------------------------- #
# Imaging trigger (scan-аас тусдаа дуудагдаж болно)
# --------------------------------------------------------------------------- #
def acquire_for_device(device_id: int) -> int:
    """Төхөөрөмжөөс дүрс авч EvidenceImage үүсгэн ID-г буцаана."""
    db = SessionLocal()
    try:
        device = db.get(Device, device_id)
        if device is None:
            raise ValueError("Device олдсонгүй")

        # Read-only баталгаажуулна.
        try:
            writeblock.set_read_only(device.dev_path)
            device.read_only = True
            device.state = DeviceState.READ_ONLY
            db.add(device)
            db.commit()
            audit.record(db, action="set_read_only", target=device.dev_path, case_id=device.case_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Read-only тохируулж чадсангүй: %s", exc)

        def _cb(pct: float, msg: str) -> None:
            hub.publish("imaging_progress", {"device_id": device_id, "progress": pct, "step": msg})

        result = imaging.acquire_image(device.dev_path, device.id, progress=_cb)
        image = EvidenceImage(
            device_id=device.id,
            path=result.path,
            image_format=result.image_format,
            size_bytes=result.size_bytes,
            md5=result.md5,
            sha256=result.sha256,
            verified=result.verified,
        )
        db.add(image)
        device.state = DeviceState.IMAGED
        db.add(device)
        db.commit()
        db.refresh(image)
        audit.record(
            db,
            action="image_acquired",
            target=device.dev_path,
            case_id=device.case_id,
            detail={"image_id": image.id, "sha256": result.sha256, "md5": result.md5},
        )
        hub.publish("imaging_completed", {"device_id": device_id, "image_id": image.id, "sha256": result.sha256})
        return image.id
    finally:
        db.close()
