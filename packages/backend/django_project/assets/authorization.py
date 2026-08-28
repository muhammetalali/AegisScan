from __future__ import annotations

from dataclasses import dataclass

from projects.authorization import get_project_authorization
from projects.models import Project
from users.models import Permission


@dataclass(frozen=True)
class AssetAuthorization:
    """Asset-scoped authorization built on project membership and user permissions."""

    project_id: object
    user: object

    @property
    def project(self):
        return self.project_id

    def _project_auth(self):
        return get_project_authorization(self.project_id, self.user)

    def can_read(self) -> bool:
        return self.user.has_permission(Permission.ASSET_READ) and self._project_auth().can_read

    def can_create(self) -> bool:
        return self.user.has_permission(Permission.ASSET_CREATE) and self._project_auth().can_update

    def can_update(self) -> bool:
        return self.user.has_permission(Permission.ASSET_UPDATE) and self._project_auth().can_update

    def can_delete(self) -> bool:
        return self.user.has_permission(Permission.ASSET_DELETE) and self._project_auth().can_update


def get_asset_authorization(project_id, user) -> AssetAuthorization:
    return AssetAuthorization(project_id=project_id, user=user)


def user_can_read_asset_project(project: Project, user) -> bool:
    return get_asset_authorization(project.pk, user).can_read()


def user_can_create_asset(project: Project, user) -> bool:
    return get_asset_authorization(project.pk, user).can_create()


def user_can_update_asset(project: Project, user) -> bool:
    return get_asset_authorization(project.pk, user).can_update()


def user_can_delete_asset(project: Project, user) -> bool:
    return get_asset_authorization(project.pk, user).can_delete()
