"""Real Docker proof that deployment cache reclaim preserves release objects."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "production_host_deploy", ROOT / "aegis-platform/scripts/production_host_deploy.py"
)
assert SPEC and SPEC.loader
deploy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(deploy)


def docker(*args: str) -> str:
    return subprocess.run(
        ["docker", *args], check=True, text=True, capture_output=True, timeout=180
    ).stdout.strip()


def main() -> None:
    name = f"aegis-storage-proof-{uuid.uuid4().hex[:12]}"
    tags = [f"{name}:rollback", f"{name}:candidate"]
    try:
        docker("volume", "create", name)
        with tempfile.TemporaryDirectory(prefix="aegis-storage-proof-") as temporary:
            context = Path(temporary)
            (context / "Dockerfile").write_text("FROM scratch\nCOPY marker /marker\n", encoding="utf-8")
            for tag in tags:
                (context / "marker").write_text(tag, encoding="utf-8")
                docker("build", "--tag", tag, str(context))
        ids = {tag: docker("image", "inspect", tag, "--format", "{{.Id}}") for tag in tags}
        # The candidate has no container yet, just like the production build
        # boundary. A stopped rollback container and a data volume must survive.
        container = docker(
            "create", "--name", name, "--mount", f"type=volume,src={name},dst=/data",
            tags[0], "unused-command",
        )
        evidence = deploy._storage_stage(
            "all-build-cache", ["docker", "builder", "prune", "--all", "--force"]
        )
        for tag, expected_id in ids.items():
            assert docker("image", "inspect", tag, "--format", "{{.Id}}") == expected_id
        assert docker("container", "inspect", name, "--format", "{{.Id}}") == container
        assert docker("volume", "inspect", name, "--format", "{{.Name}}") == name
        print(json.dumps({
            "schema": "aegisscan.production-build-cache-reality.v1",
            "status": "success",
            "candidate_image_preserved": True,
            "rollback_image_preserved": True,
            "rollback_container_preserved": True,
            "data_volume_preserved": True,
            "storage_reclaim": evidence,
        }, sort_keys=True))
    finally:
        for args in [("container", "rm", name), ("image", "rm", *tags), ("volume", "rm", name)]:
            subprocess.run(["docker", *args], text=True, capture_output=True, timeout=60)


if __name__ == "__main__":
    main()
