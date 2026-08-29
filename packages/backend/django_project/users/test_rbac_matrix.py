from django.test import SimpleTestCase

from .models import Permission, UserRole, ROLE_PERMISSIONS


class RBACMatrixTests(SimpleTestCase):
    """Freeze the role/permission contract and protect least-privilege invariants."""

    def test_every_declared_role_has_a_permission_set(self):
        declared_roles = {role.value for role in UserRole}
        self.assertEqual(set(ROLE_PERMISSIONS), declared_roles)

    def test_matrix_contains_only_declared_permissions(self):
        declared_permissions = {permission.value for permission in Permission}
        for role, permissions in ROLE_PERMISSIONS.items():
            with self.subTest(role=role):
                self.assertEqual(len(permissions), len(set(permissions)))
                self.assertTrue(set(permissions) <= declared_permissions)

    def test_super_admin_has_every_permission(self):
        self.assertEqual(
            set(ROLE_PERMISSIONS[UserRole.SUPER_ADMIN]),
            {permission.value for permission in Permission},
        )

    def test_viewer_is_read_only_for_protected_domains(self):
        viewer = set(ROLE_PERMISSIONS[UserRole.VIEWER])
        self.assertEqual(
            viewer,
            {
                Permission.PROJECT_READ,
                Permission.ASSET_READ,
                Permission.SCAN_READ,
                Permission.VULN_READ,
                Permission.REPORT_READ,
                Permission.COMPLIANCE_READ,
                Permission.KNOWLEDGE_READ,
                Permission.TWIN_READ,
            },
        )

    def test_security_analyst_has_no_administrative_user_or_system_permissions(self):
        analyst = set(ROLE_PERMISSIONS[UserRole.SECURITY_ANALYST])
        forbidden = {
            Permission.USER_CREATE,
            Permission.USER_READ,
            Permission.USER_UPDATE,
            Permission.USER_DELETE,
            Permission.USER_MANAGE_ROLES,
            Permission.USER_MANAGE_PERMISSIONS,
            Permission.SYSTEM_SETTINGS,
            Permission.SYSTEM_MONITOR,
            Permission.SYSTEM_BACKUP,
            Permission.API_KEY_MANAGE,
        }
        self.assertTrue(forbidden.isdisjoint(analyst))

    def test_admin_does_not_get_the_two_reserved_privileges(self):
        admin = set(ROLE_PERMISSIONS[UserRole.ADMIN])
        self.assertNotIn(Permission.USER_DELETE, admin)
        self.assertNotIn(Permission.USER_MANAGE_PERMISSIONS, admin)
        self.assertNotIn(Permission.SYSTEM_BACKUP, admin)

    def test_auditor_cannot_modify_security_state(self):
        auditor = set(ROLE_PERMISSIONS[UserRole.AUDITOR])
        forbidden = {
            Permission.PROJECT_CREATE,
            Permission.PROJECT_UPDATE,
            Permission.PROJECT_DELETE,
            Permission.ASSET_CREATE,
            Permission.ASSET_UPDATE,
            Permission.ASSET_DELETE,
            Permission.SCAN_CREATE,
            Permission.SCAN_CANCEL,
            Permission.SCAN_RESTART,
            Permission.SCAN_SCHEDULE,
            Permission.VULN_UPDATE,
            Permission.VULN_ASSIGN,
            Permission.VULN_CHANGE_STATUS,
            Permission.VULN_ADD_NOTE,
            Permission.REPORT_CREATE,
            Permission.COMPLIANCE_UPDATE,
            Permission.KNOWLEDGE_CREATE,
            Permission.KNOWLEDGE_UPDATE,
            Permission.TWIN_SIMULATE,
        }
        self.assertTrue(forbidden.isdisjoint(auditor))
