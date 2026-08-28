from __future__ import annotations

import asyncio
import json

from fastapi_app.services.itsm_provider_health import check_all_providers


async def main() -> int:
    result = await check_all_providers()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "healthy" else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
