from __future__ import annotations

from dataclasses import dataclass

from .models import ProjectMembership


READ_ROLES = frozenset(
    {
        ProjectMembership.Role.OWNER,
        ProjectMembership.Role.ADMIN,
        ProjectMembership.Role.MEMBER,
        ProjectMembership.Role.VIEWER,
    }
)
WRITE_ROLES = frozenset(
    {
        ProjectMembership.Role.OWNER,
        ProjectMembership.Role.ADMIN,
    }
)
OWNER_ONLY_ROLES = frozenset({ProjectMembership.Role.OWNER})


@dataclass(frozen=True)
class ProjectAuthorization:
    """Project-scoped authorization decisions shared by APIs and services."""

    membership: ProjectMembership | None
    is_superuser: bool = False

    @property
    def role(self) -> str | None:
        if self.is_superuser:
            return ProjectMembership.Role.OWNER
        return self.membership.role if self.membership else None

    @property
    def is_member(self) -> bool:
        return self.is_superuser or self.role in READ_ROLES

    @property
    def can_read(self) -> bool:
        return self.is_superuser or self.role in READ_ROLES

    @property
    def can_update(self) -> bool:
        return self.is_superuser or self.role in WRITE_ROLES

    @property
    def can_delete(self) -> bool:
        return self.is_superuser or self.role in OWNER_ONLY_ROLES

    @property
    def can_archive(self) -> bool:
        return self.is_superuser or self.role in WRITE_ROLES

    @property
    def can_manage_members(self) -> bool:
        return self.is_superuser or self.role in WRITE_ROLES

    def can_manage_membership(self, target: ProjectMembership, *, new_role: str | None = None) -> bool:
        """Return whether this actor may change/remove a target membership."""
        if not self.can_manage_members:
            return False
        if self.is_superuser or self.role == ProjectMembership.Role.OWNER:
            return True
        if target.role == ProjectMembership.Role.OWNER:
            return False
        return new_role != ProjectMembership.Role.OWNER

    def can_change_role_to(self, new_role: str) -> bool:
        if not self.can_manage_members:
            return False
        if self.is_superuser or self.role == ProjectMembership.Role.OWNER:
            return new_role in {role.value for role in ProjectMembership.Role}
        return new_role in {
            ProjectMembership.Role.ADMIN,
            ProjectMembership.Role.MEMBER,
            ProjectMembership.Role.VIEWER,
        }


def get_project_authorization(project_id, user) -> ProjectAuthorization:
    if not getattr(user, "is_authenticated", False):
        return ProjectAuthorization(None)
    if getattr(user, "is_superuser", False):
        return ProjectAuthorization(None, is_superuser=True)
    membership = (
        ProjectMembership.objects.select_related("project", "user")
        .filter(project_id=project_id, user=user)
        .first()
    )
    return ProjectAuthorization(membership)
