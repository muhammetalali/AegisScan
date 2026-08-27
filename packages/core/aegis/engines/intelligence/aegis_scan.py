"""AegisScan — محلل الكود الذكي (الطبقة 1).

المحركات:
1. كشف الأسرار (أنماط + إنتروبيا شانون) — لا يخزّن السر نفسه أبداً.
2. تحليل AST لبايثون: الدوال الخطرة + مؤشر دمج النصوص (حقن محتمل).
3. تحليل التبعيات (requirements.txt / package.json / go.mod).
ملاحظة إصلاح: مطابقة أي <obj>.execute وليس cursor فقط.
"""

from __future__ import annotations

import ast
import json
import logging
import math
import re
from pathlib import Path
from typing import Any, List, Optional, Tuple

from aegis.core.data_manager import DataManager
from aegis.core.event_bus import EventBus
from aegis.models.evidence import Evidence, EvidenceCategory, EvidenceType

logger = logging.getLogger("aegis.intelligence.aegis_scan")

DANGEROUS_SINKS = {
    "os.system": "injection",
    "os.popen": "injection",
    "subprocess.call": "injection",
    "subprocess.Popen": "injection",
    "subprocess.run": "injection",
    "eval": "injection",
    "exec": "injection",
    "compile": "injection",
    "__import__": "injection",
}

SECRET_PATTERNS: List[Tuple[str, str]] = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----", "Private Key"),
    (r"(?i)api[_-]?key\s*=\s*['\"][A-Za-z0-9_\-]{20,}['\"]", "API Key"),
    (r"(?i)password\s*=\s*['\"][^'\"]{8,}['\"]", "Hardcoded Password"),
    (r"(?i)secret\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "Hardcoded Secret"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Token"),
    (r"xox[baprs]-[A-Za-z0-9\-]{10,}", "Slack Token"),
]

CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".go", ".php", ".java", ".rb", ".cs",
    ".yml", ".yaml", ".json", ".env", ".ini", ".cfg", ".conf",
}
EXCLUDED_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", "aegis_sandbox", ".aegis",
}

DEPENDENCY_FILES = {
    "requirements.txt": "python",
    "package.json": "javascript",
    "go.mod": "go",
}


def entropy_confidence(value: str) -> float:
    """ثقة بناءً على إنتروبيا شانون (نصوص عشوائية عالية = سر محتمل)."""
    if not value:
        return 0.4
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(value)
    ent = 0.0
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    if ent > 4.0:
        return 0.9
    if ent > 3.5:
        return 0.75
    if ent > 3.0:
        return 0.6
    return 0.45


class AegisScan:
    """محرك تحليل الكود — ينتج Evidence موحدة ويحفظها وينشرها."""

    name = "AegisScan"

    def __init__(self, event_bus: EventBus, data_manager: DataManager) -> None:
        self.event_bus = event_bus
        self.data_manager = data_manager

    async def analyze_project(self, code_path: str, scan_id: str) -> List[Evidence]:
        root = Path(code_path)
        if not root.exists():
            logger.error("مسار الكود غير موجود: %s", code_path)
            return []

        logger.info("بدء تحليل المشروع: %s", code_path)
        evidences: List[Evidence] = []

        for file_path in self._iter_files(root):
            evidences.extend(self._analyze_file(file_path, scan_id))

        evidences.extend(self._analyze_dependencies(root, scan_id))

        for evidence in evidences:
            self.data_manager.save_evidence(evidence.to_dict())
            await self.event_bus.publish(
                topic="evidence.new",
                payload=evidence.to_dict(),
                source=evidence.source_tool,
            )

        logger.info("اكتمل التحليل: %d دليل", len(evidences))
        return evidences

    # ─── ملف واحد ─────────────────────────────────────────────

    def _analyze_file(self, file_path: Path, scan_id: str) -> List[Evidence]:
        try:
            source = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            logger.debug("تعذر قراءة %s: %s", file_path, exc)
            return []

        evidences = self._detect_secrets(source, file_path, scan_id)

        if file_path.suffix == ".py":
            evidences.extend(self._analyze_python_ast(source, file_path, scan_id))

        return evidences

    def _iter_files(self, root: Path):
        for path in root.rglob("*"):
            if (
                path.is_file()
                and path.suffix.lower() in CODE_EXTENSIONS
                and not any(part in EXCLUDED_DIRS for part in path.parts)
            ):
                yield path

    # ─── المحرك 1: الأسرار ────────────────────────────────────

    def _detect_secrets(
        self, source: str, file_path: Path, scan_id: str
    ) -> List[Evidence]:
        evidences: List[Evidence] = []
        for pattern, label in SECRET_PATTERNS:
            for match in re.finditer(pattern, source):
                line_no = source[: match.start()].count("\n") + 1
                evidences.append(
                    Evidence(
                        scan_id=scan_id,
                        source_tool="AegisScan.Secrets",
                        evidence_type=EvidenceType.SECRET,
                        category=EvidenceCategory.SECRETS,
                        description=f"{label} في السطر {line_no} "
                                    f"(طول المطابقة {len(match.group())})",
                        location=f"{file_path}:{line_no}",
                        confidence_weight=entropy_confidence(match.group()),
                        context={"secret_type": label, "line": line_no},
                    )
                )
        return evidences

    # ─── المحرك 2: AST ────────────────────────────────────────

    def _analyze_python_ast(
        self, source: str, file_path: Path, scan_id: str
    ) -> List[Evidence]:
        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError as exc:
            logger.debug("خطأ نحوي في %s: %s", file_path, exc)
            return []

        visitor = SecurityASTVisitor(file_path, scan_id)
        visitor.visit(tree)
        return visitor.evidences

    # ─── المحرك 3: التبعيات ───────────────────────────────────

    def _analyze_dependencies(self, root: Path, scan_id: str) -> List[Evidence]:
        evidences: List[Evidence] = []
        for filename, language in DEPENDENCY_FILES.items():
            dep_file = root / filename
            if not dep_file.exists():
                continue
            try:
                content = dep_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            for name, version in parse_dependencies(content, language):
                evidences.append(
                    Evidence(
                        scan_id=scan_id,
                        source_tool="AegisScan.Deps",
                        evidence_type=EvidenceType.DEPENDENCY,
                        category=EvidenceCategory.DEPENDENCY,
                        description=f"تبعية: {name} ({version or 'غير محدد'})",
                        location=str(dep_file),
                        confidence_weight=0.4,
                        context={
                            "dependency": name,
                            "version": version,
                            "language": language,
                        },
                    )
                )
        return evidences


class SecurityASTVisitor(ast.NodeVisitor):
    """زائر AST يكتشف الاستدعاءات الخطرة ومؤشرات الحقن."""

    def __init__(self, file_path: Path, scan_id: str) -> None:
        self.file_path = file_path
        self.scan_id = scan_id
        self.evidences: List[Evidence] = []

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._call_name(node)

        is_sink = func_name in DANGEROUS_SINKS or func_name.endswith(
            (".execute", ".executemany")
        )
        if is_sink:
            has_concat = self._has_concat_args(node)
            self.evidences.append(
                Evidence(
                    scan_id=self.scan_id,
                    source_tool="AegisScan.AST",
                    evidence_type=EvidenceType.AST,
                    category=EvidenceCategory.INJECTION,
                    description=(
                        f"استدعاء خطير: {func_name}() في السطر {node.lineno}"
                        + (" مع دمج نصوص (مؤشر حقن)" if has_concat else "")
                    ),
                    location=f"{self.file_path}:{node.lineno}",
                    confidence_weight=0.85 if has_concat else 0.55,
                    context={
                        "function": func_name,
                        "line": node.lineno,
                        "has_concat": has_concat,
                    },
                )
            )

        self.generic_visit(node)

    @staticmethod
    def _call_name(node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts: List[str] = []
            current: Any = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

    @staticmethod
    def _has_concat_args(node: ast.Call) -> bool:
        for arg in node.args:
            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                return True
            if isinstance(arg, ast.JoinedStr):
                return True
        return False


def parse_dependencies(content: str, language: str) -> List[Tuple[str, Optional[str]]]:
    """استخراج (اسم، إصدار) من ملف تبعيات."""
    deps: List[Tuple[str, Optional[str]]] = []

    if language == "python":
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*[=<>!~]*\s*([\d.]+)?", line)
            if m:
                deps.append((m.group(1), m.group(2)))

    elif language == "javascript":
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return deps
        for section in ("dependencies", "devDependencies"):
            for name, version in (data.get(section) or {}).items():
                deps.append((name, str(version).lstrip("^~")))

    elif language == "go":
        for line in content.splitlines():
            m = re.match(r"^\s*(?:require\s+)?([\w.\-/]+)\s+(v[\d.]+)", line)
            if m:
                deps.append((m.group(1), m.group(2)))

    return deps
