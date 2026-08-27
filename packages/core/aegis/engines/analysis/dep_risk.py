"""Dependency Risk Engine — محرك تحليل مخاطر التبعيات.

يحلل ملفات التبعيات (requirements.txt, pyproject.toml, package.json)
لاكتشاف تبعيات مؤقتة، غير موثوقة، أو تحتوي ثغرات معروفة.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from aiohttp import ClientSession

from aegis.core.event_bus import EventBus
from aegis.models.evidence import Evidence, EvidenceCategory, EvidenceType

logger = logging.getLogger("aegis.analysis.dep_risk")

# تبعيات مؤقتة أو تجريبية
TEMPORARY_DEPS = {
    "debugpy", "pdb", "ipdb", "pytest", "tox", "coverage",
    "black", "flake8", "mypy", "pylint", "isort", "pre-commit",
    "sphinx", "mkdocs", "sphinx-rtd-theme",
}

# تبعيات غير موثوقة (أمثلة)
UNTRUSTED_DEPS = {
    "fabric", "paramiko", "pycrypto", "pycryptodome",
    "httplib2", "xmlrpc",  # historically problematic
}


class DependencyRiskEngine:
    """محرك تحليل مخاطر التبعيات — يفحص الملفات ويتحقق من CVE."""

    name = "DependencyRiskEngine"

    # Mos → GitHub Advisory API
    ADVISORY_API = "https://api.github.com/advisories"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus

    async def analyze_dependencies(
        self,
        project_path: str,
        scan_id: str,
        ecosystem: str = "pip",
    ) -> List[Evidence]:
        """تحليل تبعيات المشروع."""
        path = Path(project_path)
        dep_files = self._find_dep_files(path)
        if not dep_files:
            logger.warning("لم يتم العثور على ملفات تبعيات في %s", project_path)
            return []

        all_deps: List[Tuple[str, str, str]] = []  # (name, version, source_file)
        for dep_file in dep_files:
            deps = self._parse_dep_file(dep_file)
            all_deps.extend(deps)

        evidences: List[Evidence] = []
        evidences.extend(self._check_temporary(all_deps, scan_id))
        evidences.extend(self._check_untrusted(all_deps, scan_id))

        # فحص CVE عبر GitHub Advisory
        async with ClientSession() as session:
            for dep_name, _, source in all_deps:
                try:
                    vulns = await self._check_advisory(session, dep_name, ecosystem)
                    for vuln in vulns:
                        evidences.append(Evidence(
                            scan_id=scan_id,
                            source_tool="DepRisk.advisory",
                            evidence_type=EvidenceType.DEPENDENCY,
                            category=EvidenceCategory.DEPENDENCY,
                            description=(
                                f"ثغرة معروفة في {dep_name}: "
                                f"{vuln.get('cve_id', 'N/A')} — {vuln.get('summary', '')[:100]}"
                            ),
                            location=source,
                            context={
                                "package": dep_name,
                                "source_file": source,
                                "vuln": vuln,
                            },
                        ))
                except Exception:
                    continue

        for ev in evidences:
            await self.event_bus.publish(
                topic="evidence.new", payload=ev.to_dict(), source=self.name
            )

        logger.info("تحليل التبعيات: %d تبعية → %d أدلة", len(all_deps), len(evidences))
        return evidences

    @staticmethod
    def _find_dep_files(path: Path) -> List[Path]:
        """البحث عن ملفات التبعيات."""
        files: List[Path] = []
        names = [
            "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
            "pyproject.toml", "setup.py", "setup.cfg",
            "package.json", "Pipfile", "poetry.lock",
        ]
        for name in names:
            f = path / name
            if f.exists():
                files.append(f)
        # also check subdirectories (1 level)
        for f in path.glob("*/requirements*.txt"):
            if f not in files:
                files.append(f)
        return files

    @staticmethod
    def _parse_dep_file(file_path: Path) -> List[Tuple[str, str, str]]:
        """تحليل ملف تبعيات وإرجاع [(اسم, إصدار, ملف مصدري)]."""
        deps: List[Tuple[str, str, str]] = []
        name = file_path.name

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            if name.endswith(".txt") or name == "Pipfile":
                # requirements.txt format: package>=1.0
                match = re.match(r"^([a-zA-Z0-9_-]+)\s*([><=!~]+.+)?", line)
                if match:
                    deps.append((
                        match.group(1).lower(),
                        (match.group(2) or "any").strip(),
                        str(file_path),
                    ))

            elif name == "pyproject.toml":
                #简易解析 [project.dependencies]
                match = re.match(r'^"?([a-zA-Z0-9_-]+)"?\s*[><=!]', line)
                if match:
                    deps.append((match.group(1).lower(), "any", str(file_path)))

        return deps

    def _check_temporary(
        self, deps: List[Tuple[str, str, str]], scan_id: str
    ) -> List[Evidence]:
        """الكشف عن تبعيات مؤقتة."""
        evidences: List[Evidence] = []
        for dep_name, version, source in deps:
            if dep_name in TEMPORARY_DEPS:
                evidences.append(Evidence(
                    scan_id=scan_id,
                    source_tool="DepRisk.temporary",
                    evidence_type=EvidenceType.DEPENDENCY,
                    category=EvidenceCategory.DEPENDENCY,
                    description=f"تبعية مؤقتة/تجريبية في الإنتاج: {dep_name} ({version})",
                    location=source,
                    context={"package": dep_name, "version": version, "source_file": source},
                ))
        return evidences

    def _check_untrusted(
        self, deps: List[Tuple[str, str, str]], scan_id: str
    ) -> List[Evidence]:
        """الكشف عن تبعيات غير موثوقة."""
        evidences: List[Evidence] = []
        for dep_name, version, source in deps:
            if dep_name in UNTRUSTED_DEPS:
                evidences.append(Evidence(
                    scan_id=scan_id,
                    source_tool="DepRisk.untrusted",
                    evidence_type=EvidenceType.DEPENDENCY,
                    category=EvidenceCategory.CRYPTOGRAPHY,
                    description=f"تبعية غير موثوقة/قديمة: {dep_name} ({version})",
                    location=source,
                    context={"package": dep_name, "version": version, "source_file": source},
                ))
        return evidences

    async def _check_advisory(
        self, session: ClientSession, package: str, ecosystem: str
    ) -> List[Dict[str, Any]]:
        """التحقق من ثغرات معروفة عبر GitHub Advisory."""
        params = {"affects": package, "ecosystem": ecosystem, "per_page": 5}
        try:
            async with session.get(
                self.ADVISORY_API, params=params, timeout=15
            ) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
                results = []
                for adv in data:
                    results.append({
                        "cve_id": adv.get("cve_id", ""),
                        "summary": adv.get("summary", ""),
                        "severity": adv.get("severity", "unknown"),
                    })
                return results
        except Exception:
            return []
