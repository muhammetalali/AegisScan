from __future__ import annotations

from projects.authorization import get_project_authorization
from projects.models import Project
from users.models import Permission


def user_can_read_asset_project(project: Project, user) -> bool:
    return user.has_permission(Permission.ASSET_READ) and get_project_authorization(project.pk, user).can_read


def user_can_create_asset(project: Project, user) -> bool:
    return user.has_permission(Permission.ASSET_CREATE) and get_project_authorization(project.pk, user).can_update


def user_can_update_asset(project: Project, user) -> bool:
    return user.has_permission(Permission.ASSET_UPDATE) and get_project_authorization(project.pk, user).can_update


def user_can_delete_asset(project: Project, user) -> bool:
    return user.has_permission(Permission.ASSET_DELETE) and get_project_authorization(project.pk, user).can_update
