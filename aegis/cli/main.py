"""Aegis CLI — واجهة سطر الأوامر (Typer + Rich)."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

from aegis import __version__
from aegis.core.audit_logger import AuditLogger
from aegis.core.config_manager import ConfigManager
from aegis.core.data_manager import DataManager
from aegis.core.event_bus import EventBus
from aegis.core.crypto import load_or_create_key
from aegis.core.orchestrator import AegisOrchestrator
from aegis.core.platform_orchestrator import PlatformOrchestrator

app = typer.Typer(
    name="aegis",
    help="Aegis — منصة الأمن السيبراني الذكية (Security Decision Platform)",
    no_args_is_help=True,
)
console = Console()


def _setup(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_time=False)],
    )


def _components(config: ConfigManager):
    key = load_or_create_key(config.get("storage.key_file", ".aegis.key"))
    data = DataManager(
        db_path=config.get("database.path", "aegis.db"),
        key=key,
        encrypt_raw_data=bool(config.get("storage.encrypt_raw_data", False)),
    )
    audit = AuditLogger(
        log_file=config.get("security.audit_log_file", "audit.log"),
        key_file=config.get("security.audit_key_file", ".aegis_audit.key"),
        strict=bool(config.get("security.audit_strict", False)),
    )
    return data, audit


# ═══════════════════════════════════════════════════════════════
#  scan — الفحص الشامل (الدورة الكاملة)
# ═══════════════════════════════════════════════════════════════

@app.command()
def scan(
    code: Optional[str] = typer.Option(None, "--code", "-c", help="مسار الكود المصدري"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="عنوان URL الهدف"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="حفظ التقرير JSON"),
    markdown: Optional[str] = typer.Option(None, "--markdown", "-m", help="حفظ التقرير Markdown"),
    external: bool = typer.Option(True, "--external/--no-external", help="تفعيل الاستخبارات الخارجية"),
    analysis: bool = typer.Option(True, "--analysis/--no-analysis", help="تفعيل محركات التحليل"),
    remediate: bool = typer.Option(False, "--remediate", "-r", help="توليد إصلاحات تلقائية"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """فحص أمني شامل: جمع أدلة + تحليل + استدلال + إصلاح + تقرير."""
    _setup(verbose)
    if not code and not url:
        console.print("[red]حدّد --code أو --url على الأقل[/red]")
        raise typer.Exit(1)

    console.print(Panel.fit(
        f"[bold blue]Aegis Security Scan[/]\n"
        f"الكود: [green]{code or '—'}[/]\n"
        f"URL: [green]{url or '—'}[/]\n"
        f"استخبارات خارجية: {'مفعّلة' if external else 'معطّلة'}\n"
        f"تحليل: {'مفعّل' if analysis else 'معطّل'}\n"
        f"إصلاح: {'مفعّل' if remediate else 'معطّل'}",
        title=f"Aegis v{__version__}",
    ))

    config = ConfigManager()
    data, audit = _components(config)
    bus = EventBus()
    orch = AegisOrchestrator(bus, data, config, audit)

    async def run():
        await bus.start()
        try:
            return await orch.run_full_cycle(
                code_path=code, target_url=url,
                enable_external_intel=external,
                enable_analysis=analysis,
                enable_remediation=remediate,
            )
        finally:
            await bus.stop()

    report = asyncio.run(run())
    data.close()
    _show_report(report)

    if output:
        # حفظ JSON (بدون report_markdown)
        save_data = {k: v for k, v in report.items() if k != "report_markdown"}
        Path(output).write_text(
            json.dumps(save_data, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        console.print(f"\n[green]JSON: {output}[/green]")

    if markdown:
        md = report.get("report_markdown", "")
        Path(markdown).write_text(md, encoding="utf-8")
        console.print(f"\n[green]Markdown: {markdown}[/green]")


# ═══════════════════════════════════════════════════════════════
#  validate — منصة التحقق الأمني الكاملة (10 مراحل)
# ═══════════════════════════════════════════════════════════════

@app.command()
def validate(
    code: Optional[str] = typer.Option(None, "--code", "-c", help="مسار الكود المصدري"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="عنوان URL الهدف"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="حفظ التقرير JSON"),
    markdown: Optional[str] = typer.Option(None, "--markdown", "-m", help="حفظ التقرير Markdown"),
    external: bool = typer.Option(True, "--external/--no-external", help="الاستخبارات الخارجية"),
    analysis: bool = typer.Option(True, "--analysis/--no-analysis", help="محركات التحليل"),
    validation: bool = typer.Option(True, "--validation/--no-validation", help="التحقق الأمني"),
    remediate: bool = typer.Option(False, "--remediate", "-r", help="إصلاح تلقائي"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """منصة التحقق الأمني — 10 مراحل: استطلاع، تحليل، استخبارات، تحقق، معرفة، قرار."""
    _setup(verbose)
    if not code and not url:
        console.print("[red]حدّد --code أو --url على الأقل[/red]")
        raise typer.Exit(1)

    console.print(Panel.fit(
        f"[bold cyan]Aegis Security Validation Platform[/]\n"
        f"الكود: [green]{code or '—'}[/]\n"
        f"URL: [green]{url or '—'}[/]\n"
        f"استخبارات: {'✅' if external else '❌'} | "
        f"تحليل: {'✅' if analysis else '❌'} | "
        f"تحقق: {'✅' if validation else '❌'} | "
        f"إصلاح: {'✅' if remediate else '❌'}",
        title=f"Aegis Platform v{__version__}",
    ))

    config = ConfigManager()
    data, audit = _components(config)
    bus = EventBus()
    platform = PlatformOrchestrator(bus, data, config, audit)

    async def run():
        await bus.start()
        try:
            return await platform.run_full_cycle(
                code_path=code, target_url=url,
                enable_external_intel=external,
                enable_analysis=analysis,
                enable_validation=validation,
                enable_remediation=remediate,
            )
        finally:
            await bus.stop()

    report = asyncio.run(run())
    data.close()
    _show_platform_report(report)

    if output:
        save_data = {k: v for k, v in report.items()
                     if k not in ("report_markdown", "executive_dashboard")}
        Path(output).write_text(
            json.dumps(save_data, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        console.print(f"\n[green]JSON: {output}[/green]")

    if markdown:
        md = report.get("report_markdown", "")
        Path(markdown).write_text(md, encoding="utf-8")
        console.print(f"\n[green]Markdown: {markdown}[/green]")


# ═══════════════════════════════════════════════════════════════
#  init — تهيئة مشروع جديد
# ═══════════════════════════════════════════════════════════════

@app.command()
def init() -> None:
    """تهيئة مشروع Aegis جديد."""
    config = ConfigManager()
    for d in ("aegis/plugins", "reports"):
        Path(d).mkdir(parents=True, exist_ok=True)
        console.print(f"[green]📁 {d}/[/green]")
    console.print("[green]✅ config.yaml جاهز[/green]")
    console.print("\n[bold]التالي:[/] aegis scan --code <مسار> أو --url <عنوان>")


# ═══════════════════════════════════════════════════════════════
#  findings — عرض الثغرات
# ═══════════════════════════════════════════════════════════════

@app.command()
def findings(
    severity: Optional[str] = typer.Option(None, "--severity", "-s"),
    limit: int = typer.Option(50, "--limit", "-l"),
) -> None:
    """عرض الثغرات المخزنة."""
    _setup(False)
    config = ConfigManager()
    data, _ = _components(config)
    rows = data.list_findings(severity=severity, limit=limit)
    data.close()

    if not rows:
        console.print("[yellow]لا ثغرات مطابقة.[/yellow]")
        return

    table = Table(title="الثغرات")
    table.add_column("العنوان", max_width=45)
    table.add_column("الخطورة")
    table.add_column("الثقة", justify="right")
    table.add_column("الفئة")
    colors = {"critical": "bold red", "high": "red",
              "medium": "yellow", "low": "green"}
    for r in rows:
        sev = r.get("severity", "?")
        table.add_row(
            str(r.get("title"))[:45],
            f"[{colors.get(sev, 'white')}]{sev}[/]",
            f"{float(r.get('confidence_score', 0)):.0%}",
            str(r.get("category")),
        )
    console.print(table)


# ═══════════════════════════════════════════════════════════════
#  status — إحصائيات
# ═══════════════════════════════════════════════════════════════

@app.command()
def status() -> None:
    """إحصائيات قاعدة البيانات."""
    _setup(False)
    config = ConfigManager()
    data, _ = _components(config)
    stats = data.get_stats()
    data.close()

    table = Table(title="حالة Aegis")
    table.add_column("المكوّن")
    table.add_column("العدد", justify="right")
    labels = {"projects": "المشاريع", "scans": "الفحوصات", "evidences": "الأدلة",
              "findings": "الثغرات", "remediations": "الإصلاحات",
              "assets": "الأصول", "graph_nodes": "عقد الرسم البياني",
              "graph_edges": "حواف الرسم البياني"}
    for k, v in stats.items():
        table.add_row(labels.get(k, k), str(v))
    console.print(table)


# ═══════════════════════════════════════════════════════════════
#  version — إصدار
# ═══════════════════════════════════════════════════════════════

@app.command()
def version() -> None:
    """إصدار Aegis."""
    console.print(Panel.fit(
        f"[bold]Aegis v{__version__}[/]\n"
        "حزمة CLI مثبتة وقابلة للتشغيل.\n"
        "حالة المحركات والتكاملات تُقاس بالتنفيذ الفعلي ونتائج CI،\n"
        "ولا يعلن أمر الإصدار الجاهزية الإنتاجية أو اكتمال المنصة."
    ))


# ═══════════════════════════════════════════════════════════════
#  _show_report — عرض التقرير
# ═══════════════════════════════════════════════════════════════

def _show_platform_report(report: dict) -> None:
    """عرض تقرير منصة التحقق."""
    console.print(f"\n[bold cyan]═══ منصة التحقق الأمني ═══[/]")
    console.print(f"الفحص: {report.get('scan_id', '')} | الإصدار: {report.get('platform_version', '')}")

    # ── الاستطلاع ──
    recon = report.get("recon_summary", {})
    assets = report.get("discovered_assets", [])
    console.print(f"\n[bold]① الاستطلاع:[/] {recon.get('total_assets', 0)} أصل مكتشف")
    for a in assets[:5]:
        console.print(f"   • {a['name']} ({a['type']})")

    # ── التحليل ──
    findings = report.get("findings") or []
    sev_dist = report.get("severity_distribution", {})
    console.print(f"\n[bold]② التحليل:[/] {len(findings)} نتيجة")
    for sev in ("critical", "high", "medium", "low"):
        count = sev_dist.get(sev, 0)
        if count:
            color = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}.get(sev, "white")
            console.print(f"   [{color}]{sev}: {count}[/]")

    # ── الاستخبارات ──
    vuln = report.get("vuln_intel_summary", {})
    console.print(f"\n[bold]③ الاستخبارات:[/] {vuln.get('total_vulns', 0)} ثغرة مسجلة")

    # ── التحقق ──
    val = report.get("validation_summary", {})
    console.print(f"\n[bold]⑤ التحقق:[/] {val.get('total_validations', 0)} تحقق | "
                  f"نسبة التأكيد: {val.get('confirmation_rate', 0):.0%}")

    # ── مسارات الهجوم ──
    ap = report.get("attack_paths", {})
    console.print(f"\n[bold]④ مسارات الهجوم:[/] {ap.get('total', 0)} مسار | "
                  f"حرجة: {ap.get('critical', 0)}")
    for rec in ap.get("recommendations", []):
        console.print(f"   • {rec}")

    # ── المعرفة ──
    know = report.get("knowledge_summary", {})
    console.print(f"\n[bold]⑥ المعرفة:[/] {know.get('total_items', 0)} عنصر")

    # ── الوضع الأمني ──
    posture = report.get("posture", {})
    console.print(f"\n[bold]⑧ الوضع الأمني:[/] {posture.get('overall_score', 0)}/100 ({posture.get('rating', '—')})")

    # ── الامتثال ──
    compliance = report.get("compliance", {})
    for fw, data in compliance.items():
        console.print(f"   • {fw}: {data.get('compliance_pct', 0)}%")

    # ── لوحة القيادة ──
    exec_sum = report.get("executive_summary", {})
    console.print(f"\n[bold cyan]═══ ملخص تنفيذي ═══[/]")
    console.print(f"المخاطر: [bold]{exec_sum.get('overall_risk', '—')}[/] ({exec_sum.get('risk_score', 0)}/100)")
    for insight in exec_sum.get("key_insights", []):
        console.print(f"   • {insight}")
    console.print(f"\n[bold]بنود الإجراء:[/]")
    for item in exec_sum.get("action_items", []):
        console.print(f"   → {item}")

    # ── التوصيات ──
    recs = report.get("recommendations", [])
    if recs:
        console.print(f"\n[bold]توصيات:[/]")
        for rec in recs[:5]:
            console.print(f"  • {rec}")


def _show_report(report: dict) -> None:
    summary = report.get("summary", {})

    # ── ملخص الفحص ──
    console.print(f"\n[bold]الفحص:[/] {report['scan_id']}")
    console.print(
        f"الأدلة: {report.get('evidence_count', 0)} "
        f"(داخلية: {report.get('evidence_count', 0) - report.get('external_evidence_count', 0)}, "
        f"خارجية: {report.get('external_evidence_count', 0)}) | "
        f"المدة: {report.get('duration_seconds', 0):.1f}s"
    )

    # ── ملخص المخاطرة ──
    risk = report.get("risk_summary", {})
    if risk:
        console.print(f"\n[bold]تقييم المخاطرة:[/]")
        console.print(
            f"  متوسط الدرجة: [bold]{risk.get('average_score', 0):.1f}[/]/100 | "
            f"حرج: {risk.get('critical', 0)} | "
            f"عالي: {risk.get('high', 0)} | "
            f"متوسط: {risk.get('medium', 0)} | "
            f"منخفض: {risk.get('low', 0)}"
        )
        risk_exp = report.get("risk_explanation", "")
        if risk_exp:
            console.print(f"  [dim]{risk_exp}[/dim]")

    # ── الرسم البياني ──
    kg = report.get("knowledge_graph", {})
    if kg:
        console.print(f"\n[bold]الرسم البياني:[/] {kg.get('nodes', 0)} عقدة / {kg.get('edges', 0)} حافة")

    # ── قصة الهجوم ──
    story = report.get("attack_story")
    if story:
        console.print(f"\n[bold]{story.get('title', '')}[/]")
        console.print(story.get("summary", ""))

    # ── الثغرات ──
    findings_list = report.get("findings") or []
    if not findings_list:
        console.print("\n[yellow]لا ثغرات مؤكدة (قاعدة الدليلين المستقلين).[/yellow]")
        return

    table = Table(title=f"ثغرات مؤكدة ({len(findings_list)})")
    table.add_column("العنوان", max_width=40)
    table.add_column("الخطورة")
    table.add_column("الثقة", justify="right")
    table.add_column("المخاطرة", justify="right")
    table.add_column("المصادر")

    risk_assessments = {r["finding_id"]: r for r in report.get("risk_assessments", [])}

    for f in findings_list:
        fid = f.get("id", "")
        ctx = f.get("context", {}) or {}
        sources = ", ".join(ctx.get("unique_sources", []))
        risk_item = risk_assessments.get(fid, {})
        risk_score = risk_item.get("risk_score", 0)
        risk_color = (
            "bold red" if risk_score >= 75 else
            "red" if risk_score >= 50 else
            "yellow" if risk_score >= 25 else
            "green"
        )
        table.add_row(
            f["title"][:40],
            f"[bold red]{f['severity']}[/]"
            if f["severity"] == "critical" else f["severity"],
            f"{f['confidence_score']:.0%}",
            f"[{risk_color}]{risk_score:.0f}[/]",
            sources,
        )
    console.print(table)

    # ── التوصيات ──
    for rec in report.get("recommendations", []):
        console.print(f"  • {rec}")

    # ── ملخص الإصلاحات ──
    remediations = report.get("remediations") or []
    if remediations:
        console.print(f"\n[bold]إصلاحات:[/] {len(remediations)} مولّدة")


def run() -> None:
    app()


if __name__ == "__main__":
    run()
