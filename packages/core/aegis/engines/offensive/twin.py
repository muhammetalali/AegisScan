"""Digital Twin — التوأم الرقمي بعزل شبكي حقيقي (الطبقة 3).

إصلاح الثغرة الحرجة من التصميم السابق:
- التنفيذ يتم حصراً داخل الحاويات عبر `docker compose exec`
  وليس على الجهاز المضيف إطلاقاً.
- الشبكة `internal: true` = لا إنترنت ولا وصول للشبكة المحلية.
- لا تُعتبر البيئة جاهزة قبل التحقق العملي من العزل.
- أي تكوين Compose بدون شبكة داخلية معزولة → رفض البناء.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("aegis.offensive.twin")

try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:  # pragma: no cover
    _HAS_YAML = False

DEFAULT_SANDBOX_COMPOSE = """\
# Aegis Digital Twin - شبكة داخلية معزولة تماماً (لا إنترنت)
services:
  sandbox:
    image: alpine:3.20
    container_name: {container}
    command: ["sleep", "infinity"]
    networks:
      - twin_net

networks:
  twin_net:
    name: {network}
    internal: true
    driver: bridge
"""


class TwinState(str, Enum):
    IDLE = "idle"
    BUILDING = "building"
    READY = "ready"
    DRIFT_DETECTED = "drift_detected"
    DESTROYED = "destroyed"


@dataclass
class TwinConfig:
    """إعدادات التوأم."""

    name: str = "aegis_twin"
    compose_file: Optional[str] = None          # بيئة المستخدم الخاصة (اختياري)
    sandbox_dir: str = "aegis_sandbox"
    project_name: str = ""                       # docker compose -p
    test_base_url: str = "http://sandbox:80"     # القاعدة الوحيدة المسموح استهدافها
    max_drift_threshold: float = 5.0

    def __post_init__(self) -> None:
        if not self.project_name:
            self.project_name = f"aegis_twin_{self.name}"


from aegis.core.exceptions import SafetyViolationError


def validate_compose_security(compose_path: str) -> List[str]:
    """فحص ملف Compose: كل خدمة يجب أن تكون على شبكة داخلية معزولة.

    Returns:
        قائمة المخالفات (فارغة = آمن).
    """
    violations: List[str] = []
    if not _HAS_YAML:
        return ["PyYAML غير متوفر — لا يمكن فحص التكوين"]

    try:
        with open(compose_path, "r", encoding="utf-8") as f:
            doc = _yaml.safe_load(f) or {}
    except Exception as exc:
        return [f"تعذر قراءة الملف: {exc}"]

    services = doc.get("services") or {}
    networks = doc.get("networks") or {}
    internal_nets = {
        name for name, cfg in networks.items()
        if isinstance(cfg, dict) and cfg.get("internal") is True
    }
    # شبكات خارجية معرّفة بمرجع خارجي قد تكون معزولة أصلاً — نحتفظ بالتشدد
    if not services:
        violations.append("لا توجد خدمات في الملف")
        return violations

    for svc_name, svc in services.items():
        svc = svc or {}
        nets = svc.get("networks")
        if not nets:
            violations.append(
                f"الخدمة '{svc_name}' على الشبكة الافتراضية (غير معزولة)"
            )
            continue
        net_names = (
            list(nets.keys()) if isinstance(nets, dict)
            else [str(n) for n in nets]
        )
        # اسم الشبكة الفعلي قد يختلف عن المفتاح عبر name:
        resolved_ok = False
        for n in net_names:
            if n in internal_nets:
                resolved_ok = True
                continue
            cfg = networks.get(n) or {}
            if isinstance(cfg, dict) and cfg.get("internal") is True:
                resolved_ok = True
        if not resolved_ok:
            violations.append(
                f"الخدمة '{svc_name}' غير مرتبطة بأي شبكة internal:true "
                f"(شبكاتها: {net_names})"
            )

    ports = any(
        (svc or {}).get("ports")
        for svc in services.values()
    )
    if ports:
        violations.append("نشر منافذ (ports:) يكسر العزل — ممنوع في التوأم")

    return violations


class DigitalTwin:
    """بيئة اختبار معزولة بإدارة Docker Compose.

    ضمانات السلامة:
    1. exec داخل الحاوية فقط (docker compose exec).
    2. شبكة internal — بلا إنترنت، بلا LAN.
    3. READY فقط بعد اجتياز فحص العزل عملياً.
    4. Kill Switch فوري عبر abort().
    """

    def __init__(self, config: TwinConfig) -> None:
        self.config = config
        self.base_dir = Path(config.sandbox_dir) / config.name
        self.state = TwinState.IDLE
        self.created_at: Optional[datetime] = None
        self.last_sync: Optional[datetime] = None
        self._drift_pct = 0.0
        self._aborted = False
        self.compose_file_used: Optional[Path] = None
        self.isolation_verified = False

    # ─── دورة الحياة ──────────────────────────────────────────

    def build(self) -> bool:
        """بناء البيئة المعزولة والتحقق من عزلها قبل اعتبارها جاهزة."""
        self._aborted = False
        self.state = TwinState.BUILDING
        logger.info("بناء التوأم: %s", self.config.name)

        try:
            self.base_dir.mkdir(parents=True, exist_ok=True)

            if self.config.compose_file:
                shutil.copy(
                    self.config.compose_file,
                    self.base_dir / "docker-compose.yml",
                )
                violations = validate_compose_security(
                    str(self.base_dir / "docker-compose.yml")
                )
                if violations:
                    logger.error("تكوين غير آمن: %s", violations)
                    self.state = TwinState.IDLE
                    raise SafetyViolationError(
                        f"رفض بناء توأم بتكوين غير معزول: {violations}"
                    )
            else:
                (self.base_dir / "docker-compose.yml").write_text(
                    DEFAULT_SANDBOX_COMPOSE.format(
                        container=f"{self.config.project_name}_sandbox",
                        network=f"{self.config.project_name}_net",
                    ),
                    encoding="utf-8",
                )

            self.compose_file_used = self.base_dir / "docker-compose.yml"

            if not self._compose(["up", "-d", "--quiet-pull"]):
                self.state = TwinState.IDLE
                return False

            self.created_at = datetime.now(timezone.utc)

            # ── بوابة العزل الإلزامية ──
            if not self.verify_isolation():
                logger.error("فشل التحقق من العزل — هدم البيئة")
                self.destroy()
                return False

            self.state = TwinState.READY
            self.isolation_verified = True
            logger.info("التوأم جاهز ومعزول: %s", self.config.name)
            return True

        except SafetyViolationError:
            raise
        except Exception as exc:
            logger.error("فشل البناء: %s", exc)
            self.state = TwinState.IDLE
            return False

    def destroy(self) -> None:
        """هدم البيئة وتنظيف كل شيء."""
        logger.info("هدم التوأم: %s", self.config.name)
        try:
            if self.compose_file_used and self.compose_file_used.exists():
                self._compose(["down", "-v", "--remove-orphans"], check=False)
        finally:
            if self.base_dir.exists():
                shutil.rmtree(self.base_dir, ignore_errors=True)
            self.state = TwinState.DESTROYED
            self.isolation_verified = False

    def abort(self) -> None:
        """Kill Switch — يمنع أي تنفيذ جديد."""
        logger.warning("KILL SWITCH مفعل للتوأم %s", self.config.name)
        self._aborted = True

    # ─── التنفيذ داخل الحاوية حصراً ───────────────────────────

    def exec_in_sandbox(
        self, service: str, command: List[str], timeout: int = 60
    ) -> Dict[str, Any]:
        """تنفيذ أمر داخل حاوية الخدمة — مستحيل أن يمس المضيف."""
        if self._aborted:
            raise SafetyViolationError("Kill Switch مفعل")

        if not self.is_safe_to_test:
            raise SafetyViolationError(
                f"التوأم غير جاهز (الحالة: {self.state.value}) — تنفيذ مرفوض"
            )

        result = self._run(
            ["docker", "compose", "-p", self.config.project_name,
             "-f", str(self.compose_file_used),
             "exec", "-T", service, *command],
            timeout=timeout,
        )
        return result

    def verify_isolation(self) -> bool:
        """برهان عملي: محاولة وصول للإنترنت من الداخل يجب أن تفشل."""
        if self.state != TwinState.BUILDING or not self.compose_file_used:
            return False

        # أثناء البناء نستخدم نفس مسار Docker المعزول، دون المرور ببوابة
        # exec_in_sandbox التي لا تسمح بالأوامر قبل READY.
        probe = self._run(
            ["docker", "compose", "-p", self.config.project_name,
             "-f", str(self.compose_file_used), "exec", "-T", "sandbox",
             "sh", "-c",
             "wget -q -T 5 -O /dev/null http://example.com 2>/dev/null; echo $?"],
            timeout=30,
        )

        exit_code = probe.get("stdout", "").strip()
        isolated = bool(probe["success"]) and exit_code != "0"
        logger.info("فحص العزل: exit=%s → معزول=%s", exit_code, isolated)
        return isolated

    @property
    def is_safe_to_test(self) -> bool:
        return (
            self.state == TwinState.READY
            and self.isolation_verified
            and not self._aborted
        )

    # ─── المزامنة والانحراف ───────────────────────────────────

    def sync_code(self, source_dir: str) -> bool:
        """نسخ نسخة الكود إلى مجلد مشترك داخل البيئة المعزولة."""
        src = Path(source_dir)
        if not src.exists():
            return False
        dest = self.base_dir / "code"
        try:
            shutil.copytree(src, dest, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns(*_IGNORE))
            self.last_sync = datetime.now(timezone.utc)
            self._drift_pct = 0.0
            if self.state == TwinState.DRIFT_DETECTED:
                self.state = TwinState.READY
            return True
        except OSError as exc:
            logger.error("فشل المزامنة: %s", exc)
            return False

    def check_drift(self) -> float:
        if self.last_sync is None:
            return 0.0
        hours = (datetime.now(timezone.utc) - self.last_sync).total_seconds() / 3600
        self._drift_pct = min(hours * 0.5, 100.0)
        if (
            self._drift_pct > self.config.max_drift_threshold
            and self.state == TwinState.READY
        ):
            self.state = TwinState.DRIFT_DETECTED
        return round(self._drift_pct, 2)

    # ─── دوocker منخفض المستوى ────────────────────────────────

    def _compose(self, args: List[str], check: bool = True) -> Optional[Dict]:
        result = self._run(
            ["docker", "compose", "-p", self.config.project_name,
             "-f", str(self.compose_file_used), *args],
            timeout=300,
            check=check,
        )
        return result

    @staticmethod
    def _run(cmd: List[str], timeout: int, check: bool = True) -> Dict[str, Any]:
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, shell=False,
            )
            out = {
                "success": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": proc.stdout or "",
                "stderr": proc.stderr or "",
            }
            if check and not out["success"]:
                logger.error("أمر فاشل %s: %s", cmd[:4], out["stderr"][:300])
            return out
        except FileNotFoundError:
            return {"success": False, "returncode": -1,
                    "stdout": "", "stderr": "Docker غير مثبت"}
        except subprocess.TimeoutExpired:
            return {"success": False, "returncode": -1,
                    "stdout": "", "stderr": f"Timeout ({timeout}s)"}

    def __enter__(self) -> "DigitalTwin":
        self.build()
        return self

    def __exit__(self, *exc) -> None:
        self.destroy()


_IGNORE = {
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    "aegis.db", "*.log", ".aegis.key", ".aegis_audit.key", "reports",
}
