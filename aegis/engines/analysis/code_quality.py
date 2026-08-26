"""Code Quality Engine — محرك تحليل جودة الكود.

يحلل تعقيد الكود، التكرار، التوابل، والخيوط غير الآمنة.
يُنتج Evidence لكل مشكلة مكتشفة.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from aegis.core.event_bus import EventBus
from aegis.models.evidence import Evidence, EvidenceCategory, EvidenceType

logger = logging.getLogger("aegis.analysis.quality")

# الثوابط المُ烈ّدة الصراحة
SUSPICIOUS_PATTERNS: Dict[str, Dict[str, Any]] = {
    "eval_usage": {
        "pattern": r"\beval\s*\(",
        "severity": "high",
        "category": EvidenceCategory.INJECTION,
        "description": "استخدام eval() — خطير subsidized资助 الاستWonderرDanceر استWonder",
    },
    "exec_usage": {
        "pattern": r"\bexec\s*\(",
        "severity": "high",
        "category": EvidenceCategory.INJECTION,
        "description": "استخدام exec() — تنفيذ كود عشوائي",
    },
    "pickle_load": {
        "pattern": r"pickle\.load",
        "severity": "high",
        "category": EvidenceCategory.INJECTION,
        "description": "تحميل pickle من مصادر غير موثوقة — استWonderLog استWonder",
    },
    "md5_usage": {
        "pattern": r"\bhashlib\.md5\b",
        "severity": "medium",
        "category": EvidenceCategory.CRYPTOGRAPHY,
        "description": "استخدام MD5 — خوارزمية ضعيفة للتشفير",
    },
    "shell_true": {
        "pattern": r"subprocess\..*\bshell\s*=\s*True\b",
        "severity": "high",
        "category": EvidenceCategory.INJECTION,
        "description": "subprocess مع shell=True — ثغرة أوامر",
    },
    "hardcoded_secret": {
        "pattern": r"(?i)(password|secret|api_key|token)\s*=\s*['\"][^'\"]{8,}['\"]",
        "severity": "medium",
        "category": EvidenceCategory.SECRETS,
        "description": "كلمة سر مكتوبة مباشرة في الكود",
    },
    "todo_fixme": {
        "pattern": r"(?i)\b(TODO|FIXME|HACK|XXX)\b",
        "severity": "low",
        "category": EvidenceCategory.UNKNOWN,
        "description": "تعليق غير مكتمل — قد يدل على إصلاح مؤقت",
    },
}


class CodeQualityEngine:
    """محرك تحليل جودة الكود — يفحص ملفات Python للثغرات والتعقيد."""

    name = "CodeQualityEngine"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus

    async def analyze_codebase(
        self,
        code_path: str,
        scan_id: str,
        patterns: Optional[List[str]] = None,
    ) -> List[Evidence]:
        """تحليل مسار كود كامل."""
        path = Path(code_path)
        if not path.exists():
            logger.warning("مسار غير موجود: %s", code_path)
            return []

        target_patterns = patterns or list(SUSPICIOUS_PATTERNS.keys())
        all_evidences: List[Evidence] = []

        if path.is_file():
            evs = await self._analyze_file(path, scan_id, target_patterns)
            all_evidences.extend(evs)
        else:
            for py_file in path.rglob("*.py"):
                evs = await self._analyze_file(py_file, scan_id, target_patterns)
                all_evidences.extend(evs)

        # نشر عبر EventBus
        for ev in all_evidences:
            await self.event_bus.publish(
                topic="evidence.new", payload=ev.to_dict(), source=self.name
            )

        logger.info("تحليل %s: %d أدلة", code_path, len(all_evidences))
        return all_evidences

    async def _analyze_file(
        self,
        file_path: Path,
        scan_id: str,
        patterns: List[str],
    ) -> List[Evidence]:
        """تحليل ملف واحد."""
        evidences: List[Evidence] = []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        # فحص الأنماط المشبوهة
        import re
        for pattern_key in patterns:
            pat = SUSPICIOUS_PATTERNS.get(pattern_key)
            if not pat:
                continue
            import re as _re
            for m in _re.finditer(pat["pattern"], content, _re.IGNORECASE):
                line_no = content[:m.start()].count("\n") + 1
                sev = pat["severity"]

                evidences.append(Evidence(
                    scan_id=scan_id,
                    source_tool="CodeQuality.pattern",
                    evidence_type=EvidenceType.AST,
                    category=pat["category"],
                    description=f"{pat['description']} ({file_path.name}:{line_no})",
                    location=str(file_path),
                    context={
                        "file": str(file_path),
                        "line": line_no,
                        "pattern": pattern_key,
                        "match": m.group()[:100],
                        "severity": sev,
                    },
                ))

        # تعقيد الدوال (AST)
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    issues = self._analyze_function(node, str(file_path))
                    for issue in issues:
                        evidences.append(Evidence(
                            scan_id=scan_id,
                            source_tool="CodeQuality.complexity",
                            evidence_type=EvidenceType.AST,
                            category=issue["category"],
                            description=issue["description"],
                            location=str(file_path),
                            context={
                                "file": str(file_path),
                                "line": node.lineno,
                                "function": node.name,
                                **issue.get("context", {}),
                            },
                        ))
        except SyntaxError:
            pass

        return evidences

    @staticmethod
    def _analyze_function(
        node: ast.FunctionDef | ast.AsyncFunctionDef, file_path: str
    ) -> List[Dict[str, Any]]:
        """تحليل دالة واحدة — تعقيد وطول."""
        issues: List[Dict[str, Any]] = []

        # عدد الأسطر
        if hasattr(node, "end_lineno") and node.end_lineno:
            length = node.end_lineno - node.lineno + 1
            if length > 50:
                issues.append({
                    "description": f"دالة طويلة ({length} سطر): {node.name}",
                    "category": EvidenceCategory.UNKNOWN,
                    "context": {"length": length},
                })

        # عمق التداخل (ивается حسب الت/support/المgal支持 الدعم)
        max_depth = 0
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.For, ast.While, ast.With)):
                max_depth += 1
        if max_depth > 4:
            issues.append({
                "description": f"تداخل عميق ({max_depth} مستويات): {node.name}",
                "category": EvidenceCategory.UNKNOWN,
                "context": {"depth": max_depth},
            })

        # عدد المعاملات
        args = node.args
        total_args = (
            len(args.args) + len(args.posonlyargs) + len(args.kwonlyargs)
        )
        if total_args > 7:
            issues.append({
                "description": f"دالة بـ {total_args} معاملات: {node.name}",
                "category": EvidenceCategory.UNKNOWN,
                "context": {"arg_count": total_args},
            })

        return issues
