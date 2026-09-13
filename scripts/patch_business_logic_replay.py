from pathlib import Path

path = Path("aegis-platform/backend/fastapi_app/services/decision_action_orchestration.py")
text = path.read_text()

old = """    event_type: str,\n    idempotency_sha256: str,\n"""
new = """    event_type: str | None,\n    idempotency_sha256: str,\n"""
assert text.count(old) == 1, "unexpected _find_replay signature"
text = text.replace(old, new, 1)

old = """            if event.event_type != event_type:\n                continue\n"""
new = """            if event_type is not None and event.event_type != event_type:\n                continue\n"""
assert text.count(old) == 1, "unexpected replay event filter"
text = text.replace(old, new, 1)

old = """                event_type=f\"action.{state}\",\n                idempotency_sha256=key_sha,\n"""
new = """                event_type=None,\n                idempotency_sha256=key_sha,\n"""
assert text.count(old) == 1, "unexpected transition replay call"
text = text.replace(old, new, 1)

path.write_text(text)
Path(__file__).unlink()
