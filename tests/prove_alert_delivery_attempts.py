#!/usr/bin/env python3
"""Prove two active same-release alerts produce independent authenticated CI receipts."""
from __future__ import annotations

import argparse
import json
import re
import secrets
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _exec(container: str, source: str) -> str:
    return subprocess.check_output(
        ["docker", "exec", container, "python3", "-c", source],
        text=True, timeout=15,
    )


def prove(alertmanager: str, receiver: str) -> dict:
    release = "c" * 40
    proofs = []
    for _ in range(2):
        attempt = secrets.token_hex(16)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        alerts = [{
            "labels": {"alertname": "AegisProductionAlertDeliveryAcceptance", "service": "aegisscan",
                       "severity": "critical", "release_sha": release, "acceptance_id": attempt},
            "startsAt": now.isoformat(), "endsAt": (now + timedelta(minutes=10)).isoformat(),
        }]
        source = (
            "import urllib.request; "
            f"data={json.dumps(alerts)!r}.encode(); "
            "req=urllib.request.Request('http://127.0.0.1:9093/api/v2/alerts',data=data,"
            "headers={'Content-Type':'application/json'}); "
            "r=urllib.request.urlopen(req,timeout=5); assert r.status==200"
        )
        _exec(alertmanager, source)
        query = (
            "import json; from pathlib import Path; from collections import deque; "
            "p=Path('/var/lib/aegis-alert-receiver/events.jsonl'); "
            "lines=deque(p.open(),maxlen=256) if p.is_file() else []; "
            f"attempt={attempt!r}; release={release!r}; "
            "items=[x for x in (json.loads(line) for line in lines) if x.get('status')=='firing' "
            "and attempt in x.get('acceptance_ids',[]) and release in x.get('release_shas',[]) "
            "and 'AegisProductionAlertDeliveryAcceptance' in x.get('alertnames',[])]; "
            "print(json.dumps({'digest':items[-1]['payload_sha256']} if items else {}))"
        )
        started = time.monotonic()
        receipt = {}
        for _poll in range(30):
            receipt = json.loads(_exec(receiver, query))
            if receipt:
                break
            time.sleep(1)
        if not re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("digest", ""))):
            raise RuntimeError("same-release acceptance attempt did not receive a fresh firing receipt")
        proofs.append({"acceptance_id": attempt, "payload_sha256": receipt["digest"],
                       "delivery_seconds": round(time.monotonic() - started, 3)})
    assert proofs[0]["acceptance_id"] != proofs[1]["acceptance_id"]
    assert proofs[0]["payload_sha256"] != proofs[1]["payload_sha256"]
    return {"schema": "aegisscan.alert-attempt-grouping-proof.v1", "status": "success",
            "release_sha": release, "attempts": proofs, "first_alert_remained_active": True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alertmanager", default="aegis-alertmanager")
    parser.add_argument("--receiver", default="aegis-alert-receiver")
    parser.add_argument("--output-json", type=Path, required=True)
    args = parser.parse_args()
    proof = prove(args.alertmanager, args.receiver)
    args.output_json.write_text(json.dumps(proof, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(proof, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
