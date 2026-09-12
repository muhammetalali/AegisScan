from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / 'aegis-platform/backend/fastapi_app/services/credential_execution.py'

OLD = """_PROTOCOL_SECURITY_CAPABILITIES = {\n    'websocket.security-validation',\n    'graphql.security-validation',\n    'cross-protocol.security-validation',\n}\n"""
NEW = """_PROTOCOL_SECURITY_CAPABILITIES = {\n    'websocket.security-validation',\n    'graphql.security-validation',\n    'cross-protocol.security-validation',\n    'identity-protocol.security-validation',\n}\n"""


def main() -> None:
    text = TARGET.read_text(encoding='utf-8')
    if NEW in text:
        return
    if OLD not in text:
        raise RuntimeError('protocol security capability allowlist anchor changed')
    TARGET.write_text(text.replace(OLD, NEW, 1), encoding='utf-8')


if __name__ == '__main__':
    main()
