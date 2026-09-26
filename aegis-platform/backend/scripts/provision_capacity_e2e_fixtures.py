#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import secrets
import uuid

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_project.settings")

import django
django.setup()

from django.contrib.auth import get_user_model
from django_project.users.models import UserRole

SCHEMA = "aegisscan.capacity-e2e-fixtures.v1"


def _provision_user(email: str, password: str, first_name: str, last_name: str):
    User = get_user_model()
    user, _ = User.objects.get_or_create(
        email=email,
        defaults={
            "first_name": first_name,
            "last_name": last_name,
            "role": UserRole.SECURITY_MANAGER,
            "is_active": True,
            "is_verified": True,
        },
    )
    user.first_name = first_name
    user.last_name = last_name
    user.role = UserRole.SECURITY_MANAGER
    user.is_active = True
    user.is_verified = True
    user.set_password(password)
    user.save()
    if not user.has_permission("project.create") or not user.has_permission("scan.create"):
        raise SystemExit(f"capacity actor lacks required governed permissions: {email}")


def build_fixtures(count: int) -> dict[str, object]:
    if not 1 <= count <= 16:
        raise ValueError("count must be between 1 and 16")
    token = uuid.uuid4().hex[:12]
    fixtures = []
    for index in range(count):
        actor_email = f"capacity-{token}-{index}@aegisscan.local"
        approver_email = f"capacity-approver-{token}-{index}@aegisscan.local"
        actor_password = f"Aegis-Capacity-{index}-!9-{secrets.token_urlsafe(24)}"
        approver_password = f"Aegis-Capacity-Approver-{index}-!7-{secrets.token_urlsafe(24)}"
        _provision_user(actor_email, actor_password, "Capacity", f"Actor {index}")
        _provision_user(approver_email, approver_password, "Capacity", f"Approver {index}")
        fixtures.append({
            "actor_email": actor_email,
            "actor_password": actor_password,
            "approver_email": approver_email,
            "approver_password": approver_password,
        })
    return {"schema": SCHEMA, "run_token": token, "fixtures": fixtures}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, required=True)
    args = parser.parse_args()
    print(json.dumps(build_fixtures(args.count), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
