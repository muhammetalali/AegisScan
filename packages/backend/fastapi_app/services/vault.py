from __future__ import annotations

import os
from typing import Any

import httpx


class VaultUnavailable(RuntimeError):
    pass


async def read_secret(path: str) -> dict[str, Any]:
    """Read a secret from HashiCorp Vault when VAULT_ADDR/TOKEN are configured.

    CI/local development may continue using ephemeral environment injection; Vault
    becomes the production source without hard-coding credentials in the repo.
    """
    addr = os.getenv("VAULT_ADDR")
    token = os.getenv("VAULT_TOKEN")
    if not addr or not token:
        raise VaultUnavailable("Vault is not configured")
    url = f"{addr.rstrip('/')}/v1/{path.lstrip('/')}"
    async with httpx.AsyncClient(timeout=8.0, verify=os.getenv("VAULT_TLS_VERIFY", "1") != "0") as client:
        response = await client.get(url, headers={"X-Vault-Token": token})
        response.raise_for_status()
        data = response.json()
    return data.get("data", {}).get("data", data.get("data", {}))
