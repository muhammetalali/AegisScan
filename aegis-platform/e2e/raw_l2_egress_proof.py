"""Validate real Masscan output against before/after kernel drop counters."""
from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path


def matching_drop_counters(rules: str, target: str) -> dict[str, int]:
    address = ipaddress.IPv4Address(target)
    counters = {}
    for network, packets in re.findall(
        r"ip daddr ([0-9./]+) counter packets (\d+) bytes \d+ drop", rules
    ):
        if address in ipaddress.IPv4Network(network):
            counters[network] = int(packets)
    if not counters:
        raise ValueError("No kernel drop counter covers the forbidden target")
    return counters


def verify_blocked(raw: str, before: str, after: str, target: str) -> None:
    # Masscan 1.3.2 emits no JSON at all when there are no discoveries.
    # Only that empty-output case is normalized; malformed JSON must fail.
    records = json.loads(raw) if raw.strip() else []
    if records != []:
        raise ValueError("Forbidden scan returned discoveries or an invalid result shape")
    old = matching_drop_counters(before, target)
    new = matching_drop_counters(after, target)
    if old.keys() != new.keys() or any(new[key] < old[key] for key in old):
        raise ValueError("Kernel drop rules changed or counters reset during the probe")
    if not any(new[key] > old[key] for key in old):
        raise ValueError("Empty scan output without a kernel drop is not proof of isolation")


if __name__ == "__main__":
    output, before, after, target = sys.argv[1:]
    verify_blocked(
        Path(output).read_text(encoding="utf-8"),
        Path(before).read_text(encoding="utf-8"),
        Path(after).read_text(encoding="utf-8"),
        target,
    )
    print("FORBIDDEN_RAW_PACKET_SCAN_BLOCKED=PASS")
