"""سلسلة تدقيق هاشية قابلة للتحقق، لا تدّعي أنها بديلًا عن التخزين الخارجي."""

from __future__ import annotations

import hashlib
import json
from typing import Any


class ImmutableAuditChain:
    """سجل append-only داخل الذاكرة مع تحقق من ترتيب السجلات."""

    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []

    @staticmethod
    def _hash(entry: dict[str, Any]) -> str:
        payload = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
        return hashlib.sha256(payload).hexdigest()

    def append(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        previous = self._entries[-1]['hash'] if self._entries else '0' * 64
        entry = {'sequence': len(self._entries) + 1, 'previous_hash': previous, 'action': action, 'payload': payload}
        entry['hash'] = self._hash(entry)
        self._entries.append(entry)
        return dict(entry)

    def verify(self) -> bool:
        previous = '0' * 64
        for index, entry in enumerate(self._entries, start=1):
            if entry.get('sequence') != index or entry.get('previous_hash') != previous:
                return False
            if entry.get('hash') != self._hash({k: v for k, v in entry.items() if k != 'hash'}):
                return False
            previous = entry['hash']
        return True

    def entries(self) -> tuple[dict[str, Any], ...]:
        return tuple(dict(item) for item in self._entries)
