import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from uuid import uuid4

from .websocket_manager import WebSocketManager
from ..core.config import settings

logger = logging.getLogger(__name__)

# Define the 15 engines with their categories and order
ENGINES = [
    {"name": "recon", "display_name": "Recon & Asset Discovery", "category": "recon", "order": 1, "timeout": 60},
    {"name": "evidence_collection", "display_name": "Evidence Collection", "category": "analysis", "order": 2, "timeout": 60},
    {"name": "code_quality", "display_name": "Code Quality Analysis", "category": "analysis", "order": 3, "timeout": 120},
    {"name": "runtime_analysis", "display_name": "Runtime Log Analysis", "category": "analysis", "order": 4, "timeout": 60},
    {"name": "performance", "display_name": "Performance Analysis", "category": "analysis", "order": 5, "timeout": 60},
    {"name": "dependency_risk", "display_name": "Dependency Risk", "category": "analysis", "order": 6, "timeout": 120},
    {"name": "config_check", "display_name": "Configuration Check", "category": "analysis", "order": 7, "timeout": 60},
    {"name": "vuln_intelligence", "display_name": "Vulnerability Intelligence", "category": "intelligence", "order": 8, "timeout": 120},
    {"name": "correlation", "display_name": "Correlation Engine", "category": "validation", "order": 9, "timeout": 60},
    {"name": "validation", "display_name": "Security Validation", "category": "validation", "order": 10, "timeout": 180},
    {"name": "control_validation", "display_name": "Control Validation (WAF/EDR/IDS)", "category": "control", "order": 11, "timeout": 180},
    {"name": "coverage_gap", "display_name": "Coverage Gap Analyzer", "category": "coverage", "order": 12, "timeout": 60},
    {"name": "attack_path", "display_name": "Attack Path Analyzer", "category": "attack_path", "order": 13, "timeout": 120},
    {"name": "evidence_graph", "display_name": "Evidence Graph", "category": "evidence_graph", "order": 14, "timeout": 60},
    {"name": "knowledge", "display_name": "Knowledge Management", "category": "knowledge", "order": 15, "timeout": 60},
    {"name": "ai_explain", "display_name": "AI Explanation Engine", "category": "ai_explain", "order": 16, "timeout": 60},
    {"name": "posture", "display_name": "Security Posture", "category": "posture", "order": 17, "timeout": 60},
    {"name": "compliance", "display_name": "Compliance Checker", "category": "compliance", "order": 18, "timeout": 60},
    {"name": "digital_twin", "display_name": "Digital Twin Simulation", "category": "digital_twin", "order": 19, "timeout": 180},
    {"name": "reporting", "display_name": "Report Generation", "category": "reporting", "order": 20, "timeout": 60},
]

class ScanOrchestrator:
    def __init__(self, websocket_manager: WebSocketManager):
        self.websocket_manager = websocket_manager
        self.active_scans: Dict[str, Dict] = {}
        self.engine_status: Dict[str, str] = {e["name"]: "active" for e in ENGINES}
        self.scan_queues: Dict[str, asyncio.Queue] = {}
        self.max_concurrent = settings.MAX_CONCURRENT_SCANS
        self.running = False

    async def start(self):
        self.running = True
        logger.info("Scan Orchestrator started")

    async def stop(self):
        self.running = False
        # Cancel all running scans
        for scan_id, scan_data in self.active_scans.items():
            if scan_data.get("task"):
                scan_data["task"].cancel()
        logger.info("Scan Orchestrator stopped")

    async def list_engines(self) -> List[Dict]:
        return [
            {
                "name": e["name"],
                "display_name": e["display_name"],
                "category": e["category"],
                "order": e["order"],
                "status": self.engine_status.get(e["name"], "active"),
                "timeout": e["timeout"],
            }
            for e in ENGINES
        ]

    async def enable_engine(self, engine_name: str) -> Dict:
        if engine_name in self.engine_status:
            self.engine_status[engine_name] = "active"
            return {"status": "enabled", "engine": engine_name}
        return {"status": "error", "message": "Engine not found"}

    async def disable_engine(self, engine_name: str) -> Dict:
        if engine_name in self.engine_status:
            self.engine_status[engine_name] = "inactive"
            return {"status": "disabled", "engine": engine_name}
        return {"status": "error", "message": "Engine not found"}

    async def start_scan(self, scan_id: str, user: Dict) -> Dict:
        if scan_id in self.active_scans:
            return {"status": "error", "message": "Scan already running"}

        # Check concurrent scan limit
        running_count = sum(1 for s in self.active_scans.values() if s["status"] == "running")
        if running_count >= self.max_concurrent:
            return {"status": "error", "message": "Max concurrent scans reached"}

        # Create scan task
        scan_data = {
            "id": scan_id,
            "user_id": user.get("sub") or user.get("user_id"),
            "status": "queued",
            "progress": 0,
            "current_phase": "initializing",
            "current_engine": "",
            "engines": [],
            "started_at": datetime.utcnow().isoformat(),
            "task": None,
        }
        self.active_scans[scan_id] = scan_data

        # Start scan in background
        task = asyncio.create_task(self._run_scan(scan_id))
        scan_data["task"] = task

        return {"status": "started", "scan_id": scan_id}

    async def _run_scan(self, scan_id: str):
        scan_data = self.active_scans[scan_id]
        scan_data["status"] = "running"

        try:
            # Get engines to run (filter by status)
            engines_to_run = [e for e in ENGINES if self.engine_status.get(e["name"]) == "active"]
            scan_data["engines"] = [e["name"] for e in engines_to_run]

            total_engines = len(engines_to_run)
            for i, engine in enumerate(engines_to_run):
                if scan_data["status"] == "cancelled":
                    break

                engine_name = engine["name"]
                scan_data["current_engine"] = engine_name
                scan_data["current_phase"] = f"Running {engine['display_name']}"

                # Notify progress
                await self.websocket_manager.broadcast_scan_progress(scan_id, {
                    "phase": engine["category"],
                    "progress": int((i / total_engines) * 100),
                    "message": f"Running {engine['display_name']}...",
                    "current_engine": engine_name,
                    "engines_completed": i,
                    "total_engines": total_engines,
                })

                # Simulate engine execution
                await self._run_engine(scan_id, engine)

                # Update progress
                scan_data["progress"] = int(((i + 1) / total_engines) * 100)

            if scan_data["status"] != "cancelled":
                scan_data["status"] = "completed"
                scan_data["completed_at"] = datetime.utcnow().isoformat()
                scan_data["progress"] = 100

                # Final result
                result = {
                    "security_score": 85.5,
                    "risk_level": "medium",
                    "findings_count": 12,
                    "critical_count": 2,
                    "high_count": 4,
                    "medium_count": 4,
                    "low_count": 2,
                }
                await self.websocket_manager.broadcast_scan_completed(scan_id, result)

        except asyncio.CancelledError:
            scan_data["status"] = "cancelled"
            await self.websocket_manager.broadcast_scan_error(scan_id, "Scan cancelled by user")
        except Exception as e:
            logger.exception(f"Scan {scan_id} failed")
            scan_data["status"] = "failed"
            await self.websocket_manager.broadcast_scan_error(scan_id, str(e))

    async def _run_engine(self, scan_id: str, engine: Dict):
        """Simulate engine execution with progress updates"""
        engine_name = engine["name"]
        timeout = engine["timeout"]

        # Simulate work in chunks
        chunks = 5
        for chunk in range(chunks):
            scan_data = self.active_scans.get(scan_id)
            if not scan_data or scan_data["status"] == "cancelled":
                break

            await asyncio.sleep(timeout / chunks / 10)  # Speed up for demo

            # Send engine progress
            await self.websocket_manager.broadcast_scan_progress(scan_id, {
                "phase": engine["category"],
                "progress": scan_data["progress"],
                "message": f"{engine['display_name']} - Step {chunk + 1}/{chunks}",
                "current_engine": engine_name,
            })

    async def pause_scan(self, scan_id: str) -> Dict:
        scan_data = self.active_scans.get(scan_id)
        if not scan_data:
            return {"status": "error", "message": "Scan not found"}

        if scan_data["status"] == "running":
            scan_data["status"] = "paused"
            return {"status": "paused"}
        return {"status": "error", "message": "Scan not running"}

    async def resume_scan(self, scan_id: str) -> Dict:
        scan_data = self.active_scans.get(scan_id)
        if not scan_data:
            return {"status": "error", "message": "Scan not found"}

        if scan_data["status"] == "paused":
            scan_data["status"] = "running"
            return {"status": "resumed"}
        return {"status": "error", "message": "Scan not paused"}

    async def cancel_scan(self, scan_id: str) -> Dict:
        scan_data = self.active_scans.get(scan_id)
        if not scan_data:
            return {"status": "error", "message": "Scan not found"}

        if scan_data["status"] in ["running", "paused", "queued"]:
            scan_data["status"] = "cancelled"
            if scan_data.get("task"):
                scan_data["task"].cancel()
            return {"status": "cancelled"}
        return {"status": "error", "message": "Scan cannot be cancelled"}

    async def get_progress(self, scan_id: str) -> Dict:
        scan_data = self.active_scans.get(scan_id)
        if not scan_data:
            return {"status": "error", "message": "Scan not found"}

        return {
            "scan_id": scan_id,
            "status": scan_data["status"],
            "progress": scan_data["progress"],
            "current_phase": scan_data["current_phase"],
            "current_engine": scan_data["current_engine"],
            "engines": scan_data["engines"],
            "started_at": scan_data["started_at"],
        }