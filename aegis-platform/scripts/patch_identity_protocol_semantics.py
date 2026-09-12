from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / 'aegis-platform/backend/fastapi_app/services/identity_protocol_security.py'


def replace_once(text: str, old: str, new: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise RuntimeError(f'identity protocol semantic anchor changed: {old[:80]!r}')
    return text.replace(old, new, 1)


def main() -> None:
    text = TARGET.read_text(encoding='utf-8')
    text = replace_once(
        text,
        "    allowed = {str(value) for value in (case.get('allowed_algorithms') or [])}\n    if accepted and algorithm and allowed and algorithm not in allowed:\n",
        "    allowed = {str(value) for value in (case.get('allowed_algorithms') or [])}\n    if accepted and algorithm.lower() == 'none':\n        failures.append('unsigned JWT alg=none token was accepted')\n    if accepted and algorithm and allowed and algorithm not in allowed:\n",
    )
    old_saml = """def _validate_saml(case: dict[str, Any], accepted: bool, failures: list[str]) -> None:\n    if not accepted:\n        return\n    signature_required = bool(case.get('saml_signature_required', True))\n    if signature_required and not bool(case.get('saml_response_signature_valid', True)):\n        failures.append('SAML response with invalid signature was accepted')\n    if signature_required and not bool(case.get('saml_assertion_signature_valid', True)):\n        failures.append('SAML assertion with invalid signature was accepted')\n"""
    new_saml = """def _validate_saml(case: dict[str, Any], accepted: bool, failures: list[str]) -> None:\n    if not accepted:\n        return\n    response_valid = bool(case.get('saml_response_signature_valid', True))\n    assertion_valid = bool(case.get('saml_assertion_signature_valid', True))\n    signature_policy = str(case.get('saml_signature_policy') or 'either')\n    signature_ok = {\n        'response': response_valid,\n        'assertion': assertion_valid,\n        'either': response_valid or assertion_valid,\n        'both': response_valid and assertion_valid,\n        'none': True,\n    }.get(signature_policy, False)\n    if not signature_ok:\n        if not response_valid:\n            failures.append('SAML response with invalid signature was accepted')\n        if not assertion_valid:\n            failures.append('SAML assertion with invalid signature was accepted')\n        if response_valid and assertion_valid:\n            failures.append('invalid SAML signature policy was evaluated')\n"""
    text = replace_once(text, old_saml, new_saml)
    text = replace_once(
        text,
        "        'saml_assertion_signature_valid': bool(case.get('saml_assertion_signature_valid', True)),\n        'saml_destination_valid':",
        "        'saml_assertion_signature_valid': bool(case.get('saml_assertion_signature_valid', True)),\n        'saml_signature_policy': str(case.get('saml_signature_policy') or 'either'),\n        'saml_destination_valid':",
    )
    TARGET.write_text(text, encoding='utf-8')


if __name__ == '__main__':
    main()
