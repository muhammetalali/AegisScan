from __future__ import annotations

import asyncio
import os
from contextlib import contextmanager
from typing import Any, Iterator

import httpx

from . import itsm_remediation_v2 as core


class ProviderReconciliationError(RuntimeError):
    pass


@contextmanager
def provider_lock(provider: str, idempotency_key: str) -> Iterator[None]:
    """Serialize create/reconcile for one provider+idempotency key across workers."""
    pool = core._db()
    conn = pool.getconn()
    lock_name = f"aegisscan:itsm:{provider}:{idempotency_key}"
    locked = False
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(hashtext(%s))", (lock_name,))
            locked = True
        yield
    finally:
        if locked:
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT pg_advisory_unlock(hashtext(%s))", (lock_name,))
            finally:
                pool.putconn(conn)
        else:
            pool.putconn(conn)


async def reconcile_jira(idempotency_key: str) -> dict[str, Any] | None:
    base = os.getenv("JIRA_BASE_URL", "").rstrip("/")
    token = os.getenv("JIRA_API_TOKEN")
    email = os.getenv("JIRA_USER_EMAIL")
    project = os.getenv("JIRA_PROJECT_KEY")
    if not all((base, token, email, project)):
        return None

    label = "aegis-idem-" + idempotency_key[:16]
    jql = f'project = "{project}" AND labels = "{label}" ORDER BY created DESC'
    async with httpx.AsyncClient(
        timeout=20,
        follow_redirects=True,
        auth=(email, token),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    ) as client:
        response = await client.post(
            f"{base}/rest/api/3/search/jql",
            json={"jql": jql, "maxResults": 2, "fields": ["key", "summary", "status", "labels"]},
        )
        response.raise_for_status()
        issues = response.json().get("issues", [])

    if not issues:
        return None
    issue = issues[0]
    key = issue.get("key")
    if not key:
        return None
    return {
        "status": "reconciled",
        "provider": "jira",
        "external_id": key,
        "external_url": f"{base}/browse/{key}",
        "response": issue,
    }


async def reconcile_servicenow(idempotency_key: str) -> dict[str, Any] | None:
    base = os.getenv("SERVICENOW_BASE_URL", "").rstrip("/")
    token = os.getenv("SERVICENOW_API_TOKEN")
    username = os.getenv("SERVICENOW_USERNAME")
    password = os.getenv("SERVICENOW_PASSWORD")
    if not base or not (token or (username and password)):
        return None

    table = os.getenv("SERVICENOW_TABLE", "incident")
    field = os.getenv("SERVICENOW_IDEMPOTENCY_FIELD", "correlation_id")
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    auth = None if token else (username, password)
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(timeout=20, follow_redirects=True, headers=headers, auth=auth) as client:
        response = await client.get(
            f"{base}/api/now/table/{table}",
            params={
                "sysparm_query": f"{field}={idempotency_key}",
                "sysparm_limit": "2",
                "sysparm_fields": "sys_id,number,short_description,state",
            },
        )
        response.raise_for_status()
        rows = response.json().get("result", [])

    if not rows:
        return None
    row = rows[0]
    sys_id = row.get("sys_id")
    if not sys_id:
        return None
    return {
        "status": "reconciled",
        "provider": "servicenow",
        "external_id": sys_id,
        "external_url": f"{base}/nav_to.do?uri={table}.do?sys_id={sys_id}",
        "response": row,
    }


async def reconcile(provider: str, idempotency_key: str) -> dict[str, Any] | None:
    if provider == "jira":
        return await reconcile_jira(idempotency_key)
    if provider == "servicenow":
        return await reconcile_servicenow(idempotency_key)
    raise ValueError(f"Unsupported provider: {provider}")


async def create_or_reconcile(
    *,
    provider: str,
    decision: dict[str, Any],
    action: dict[str, Any],
    evidence: list[dict[str, Any]],
    idempotency_key: str,
) -> dict[str, Any]:
    """Retry-safe provider operation: reconcile before and between create attempts."""
    request_hash = core._request_hash(decision, evidence)
    record = core._get_or_create_record(action["actionId"], provider, idempotency_key, request_hash)

    if record.get("request_hash") != request_hash:
        raise ProviderReconciliationError("Idempotency key already used with a different request payload")
    if record.get("external_id"):
        return {
            "status": "existing",
            "provider": provider,
            "external_id": record["external_id"],
            "external_url": record.get("external_url"),
            "response": record.get("response") or {},
        }

    lock = provider_lock(provider, idempotency_key)
    with lock:
        fresh = core._get_record(record["record_id"])
        if fresh.get("external_id"):
            return {"status": "existing", "provider": provider, "external_id": fresh["external_id"], "external_url": fresh.get("external_url"), "response": fresh.get("response") or {}}

        found = await reconcile(provider, idempotency_key)
        if found:
            core._update_record(
                record["record_id"],
                integration_state="synced",
                external_state="created",
                external_id=found["external_id"],
                external_url=found.get("external_url"),
                response=found.get("response") or {},
                last_error=None,
            )
            core._audit(action["actionId"], "itsm.reconciled", action.get("requestedBy", "system"), f"Reconciled existing {provider} ticket before create", {"provider": provider, "external_id": found["external_id"]})
            return found

        last_error: Exception | None = None
        for attempt in range(1, 4):
            core._update_record(record["record_id"], integration_state="creating", attempt_count=attempt, last_error=None)
            try:
                result = await core._create_provider(provider, decision, action, evidence, idempotency_key)
                if result.get("external_id"):
                    core._update_record(record["record_id"], integration_state="created", external_state="created", external_id=result["external_id"], external_url=result.get("external_url"), response=result.get("response") or {}, last_error=None)
                    core._audit(action["actionId"], "itsm.created", action.get("requestedBy", "system"), f"Created {provider} remediation ticket", {"provider": provider, "external_id": result["external_id"], "attempt": attempt})
                    return result
                last_error = ProviderReconciliationError(f"{provider} returned no external_id")
            except Exception as exc:
                last_error = exc

            # The provider may have created the ticket while the response was lost.
            try:
                found = await reconcile(provider, idempotency_key)
            except Exception as reconcile_exc:
                last_error = reconcile_exc
                found = None
            if found:
                core._update_record(record["record_id"], integration_state="synced", external_state="created", external_id=found["external_id"], external_url=found.get("external_url"), response=found.get("response") or {}, last_error=None)
                core._audit(action["actionId"], "itsm.reconciled_after_retry", action.get("requestedBy", "system"), f"Reconciled {provider} ticket after create attempt", {"provider": provider, "external_id": found["external_id"], "attempt": attempt})
                return found
            if attempt < 3:
                await asyncio.sleep(2 ** (attempt - 1))

        core._update_record(record["record_id"], integration_state="sync_error", last_error=f"{type(last_error).__name__}: {last_error}" if last_error else "Unknown provider error")
        raise ProviderReconciliationError(f"Unable to create or reconcile {provider} ticket") from last_error
