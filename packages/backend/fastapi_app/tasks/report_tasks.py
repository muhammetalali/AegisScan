from __future__ import annotations

import calendar
import csv
import hashlib
import io
import json
import logging
import os
import textwrap
from datetime import datetime, timedelta, timezone
from html import escape
from typing import Any

import django
from django.core.files.base import ContentFile
from django.db import close_old_connections, connection, transaction
from django.utils import timezone as django_timezone

from ..celery_app import celery_app

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_project.settings")
django.setup()

from reports.models import Report  # noqa: E402

logger = logging.getLogger(__name__)


def _prepare_database_connection() -> None:
    """Refresh stale DB connections without breaking active test transactions."""
    if connection.in_atomic_block:
        return
    close_old_connections()


def _cleanup_database_connection() -> None:
    """Run Django connection cleanup only when it is safe to do so."""
    if connection.in_atomic_block:
        return
    close_old_connections()


def _snapshot(report: Report, config: dict[str, Any]) -> dict[str, Any]:
    scan = report.scan
    return {
        "report_id": str(report.id),
        "title": report.title,
        "report_type": report.report_type,
        "format": report.format,
        "project": {"id": str(report.project_id), "name": report.project.name},
        "scan": (
            {
                "id": str(scan.id),
                "name": scan.name,
                "status": scan.status,
                "security_score": scan.security_score,
                "risk_level": scan.risk_level,
                "findings_count": scan.findings_count,
                "critical_count": scan.critical_count,
                "high_count": scan.high_count,
                "medium_count": scan.medium_count,
                "low_count": scan.low_count,
            }
            if scan
            else None
        ),
        "input_snapshot": report.data_snapshot or {},
        "config": config,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _markdown(snapshot: dict[str, Any]) -> str:
    scan = snapshot.get("scan") or {}
    lines = [
        f"# {snapshot['title']}",
        "",
        f"- **Project:** {snapshot['project']['name']}",
        f"- **Report type:** {snapshot['report_type']}",
        f"- **Generated at:** {snapshot['generated_at']}",
    ]
    if scan:
        lines.extend(
            [
                "",
                "## Scan summary",
                "",
                f"- **Scan:** {scan['name']}",
                f"- **Status:** {scan['status']}",
                f"- **Security score:** {scan['security_score']}",
                f"- **Risk level:** {scan['risk_level'] or 'not classified'}",
                f"- **Findings:** {scan['findings_count']} (critical: {scan['critical_count']}, high: {scan['high_count']})",
            ]
        )
    if snapshot.get("input_snapshot"):
        lines.extend(
            [
                "",
                "## Evidence snapshot",
                "",
                "```json",
                json.dumps(snapshot["input_snapshot"], indent=2, default=str),
                "```",
            ]
        )
    return "\n".join(lines) + "\n"


def _csv(snapshot: dict[str, Any]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["section", "key", "value"])
    for section, values in snapshot.items():
        if isinstance(values, dict):
            for key, value in values.items():
                writer.writerow(
                    [
                        section,
                        key,
                        json.dumps(value, default=str)
                        if isinstance(value, (dict, list))
                        else value,
                    ]
                )
        else:
            writer.writerow(["report", section, values])
    return output.getvalue()


def _pdf(markdown: str) -> bytes:
    lines: list[str] = []
    for raw_line in markdown.splitlines():
        clean_line = raw_line.replace("#", "").replace("`", "").strip()
        lines.extend(textwrap.wrap(clean_line, width=92) or [""])
    lines = lines[:44] or ["AegisScan report"]
    commands = ["BT", "/F1 11 Tf", "50 760 Td"]
    for index, line in enumerate(lines):
        safe_line = (
            line.encode("latin-1", "replace")
            .decode("latin-1")
            .replace("\\", "\\\\")
            .replace("(", "\\(")
            .replace(")", "\\)")
        )
        if index:
            commands.append("0 -16 Td")
        commands.append(f"({safe_line}) Tj")
    commands.append("ET")
    stream = "\n".join(commands).encode("latin-1")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, body in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{number} 0 obj\n".encode())
        pdf.extend(body)
        pdf.extend(b"\nendobj\n")
    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode())
    pdf.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode()
    )
    return bytes(pdf)


def _render(report: Report, snapshot: dict[str, Any]) -> tuple[str, bytes | None, str]:
    markdown = _markdown(snapshot)
    if report.format == Report.Format.JSON:
        return json.dumps(snapshot, indent=2, ensure_ascii=False, default=str), None, "json"
    if report.format == Report.Format.CSV:
        return _csv(snapshot), None, "csv"
    if report.format == Report.Format.HTML:
        return f"<html><body><pre>{escape(markdown)}</pre></body></html>", None, "html"
    if report.format == Report.Format.PDF:
        return markdown, _pdf(markdown), "pdf"
    if report.format == Report.Format.MARKDOWN:
        return markdown, None, "markdown"
    raise ValueError(f"Unsupported report format: {report.format}")


def _advance_schedule(current: datetime, frequency: str) -> datetime:
    if frequency == "daily":
        return current + timedelta(days=1)
    if frequency == "weekly":
        return current + timedelta(days=7)
    months = 1 if frequency == "monthly" else 3
    month = current.month - 1 + months
    year = current.year + month // 12
    month = month % 12 + 1
    day = min(current.day, calendar.monthrange(year, month)[1])
    return current.replace(year=year, month=month, day=day)


@celery_app.task(
    bind=True,
    name="fastapi_app.tasks.report_tasks.generate_report",
    max_retries=2,
    default_retry_delay=30,
)
def generate_report(self, report_id: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Generate a durable report and persist its artifact metadata."""

    started = datetime.now(timezone.utc)
    _prepare_database_connection()
    try:
        report = Report.objects.select_related("project", "scan").get(pk=report_id)
        report.status = Report.Status.GENERATING
        report.error_message = ""
        report.save(update_fields=["status", "error_message", "updated_at"])

        snapshot = _snapshot(report, config or {})
        content, binary_content, extension = _render(report, snapshot)
        content_bytes = binary_content or content.encode("utf-8")

        if binary_content:
            report.file.save(f"{report.id}.{extension}", ContentFile(binary_content), save=False)
        elif report.file:
            report.file.delete(save=False)
            report.file = None

        report.content = content
        report.data_snapshot = snapshot
        report.file_size = len(content_bytes)
        report.file_hash = hashlib.sha256(content_bytes).hexdigest()
        report.generation_duration = (datetime.now(timezone.utc) - started).total_seconds()
        report.status = Report.Status.COMPLETED
        report.save()
        return {
            "report_id": str(report.id),
            "status": report.status,
            "file_size": report.file_size,
            "file_hash": report.file_hash,
        }
    except Report.DoesNotExist:
        logger.error("Report %s does not exist", report_id)
        raise
    except Exception as exc:
        logger.exception("Report generation failed for %s", report_id)
        try:
            if not connection.in_atomic_block:
                _prepare_database_connection()
                Report.objects.filter(pk=report_id).update(
                    status=Report.Status.FAILED,
                    error_message=str(exc),
                    generation_duration=(datetime.now(timezone.utc) - started).total_seconds(),
                )
            else:
                logger.warning(
                    "Skipping FAILED-state persistence inside an active transaction for report %s",
                    report_id,
                )
        except Exception:
            logger.exception("Failed to persist FAILED state for report %s", report_id)
        raise
    finally:
        _cleanup_database_connection()


@celery_app.task(
    name="fastapi_app.tasks.report_tasks.generate_scheduled_reports",
)
def generate_scheduled_reports() -> dict[str, int]:
    """Create and queue reports whose schedules are due."""

    from reports.models import ReportSchedule

    _prepare_database_connection()
    try:
        now = django_timezone.now()
        queued = 0
        for schedule in ReportSchedule.objects.select_related(
            "project", "template", "created_by"
        ).filter(is_active=True, next_generation__lte=now):
            with transaction.atomic():
                schedule = (
                    ReportSchedule.objects
                    .select_for_update(of=("self",))
                    .select_related("project", "template", "created_by")
                    .get(pk=schedule.pk)
                )
                if not schedule.is_active or schedule.next_generation > now:
                    continue
                report = Report.objects.create(
                    project=schedule.project,
                    title=f"{schedule.name} - {now.date().isoformat()}",
                    report_type=schedule.template.report_type,
                    format=schedule.template.format,
                    template_used=str(schedule.template.id),
                    data_snapshot={
                        "schedule_id": str(schedule.id),
                        "template_id": str(schedule.template.id),
                        "recipients": schedule.recipients,
                    },
                    generated_by=schedule.created_by,
                )
                schedule.last_generated = now
                schedule.next_generation = _advance_schedule(now, schedule.frequency)
                schedule.save(update_fields=["last_generated", "next_generation", "updated_at"])
            generate_report.delay(str(report.id), {"scheduled": True, "schedule_id": str(schedule.id)})
            queued += 1
        return {"queued": queued}
    finally:
        _cleanup_database_connection()
