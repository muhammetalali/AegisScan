"""Regression for role labels consumed by the existing Users / Roles UI.

Django TextChoices labels are lazy translation proxy objects. FastAPI's
jsonable_encoder turns an uncoerced proxy into {'_args': ..., '_kw': ...},
which React cannot render as a child (React error #31).
"""

import asyncio

from fastapi.encoders import jsonable_encoder

from django_project.users.models import UserRole
from fastapi_app.routers.audit import list_roles


def test_audit_roles_renderable_as_json_strings():
    # This calls the existing view's serialization result only; it does not
    # skip or modify the route's real authentication dependency in production.
    response = asyncio.run(list_roles(current_user={"user_id": "serialization-only"}))
    encoded = jsonable_encoder(response)

    assert len(encoded["items"]) == len(UserRole.choices) == 7
    assert {role["id"] for role in encoded["items"]} == set(UserRole.values)
    assert all(
        set(role) == {"id", "name"}
        and isinstance(role["name"], str)
        and bool(role["name"].strip())
        for role in encoded["items"]
    )
