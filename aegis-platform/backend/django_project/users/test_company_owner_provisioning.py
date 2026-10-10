"""Owner-only company employee lifecycle; no public signup, mail or MFA required."""
import pytest
from django.test import override_settings
from rest_framework.test import APIClient
from django_project.users.models import User, UserRole


@pytest.fixture
def company_owner(settings, db):
    owner = User.objects.create_superuser(
        email=settings.AEGIS_PRIMARY_OWNER_EMAIL,
        password='Strong-Test-Owner-Pass-2026!',
        first_name='Company', last_name='Owner',
    )
    return owner


@pytest.fixture
def other_admin(db):
    return User.objects.create_user(
        email='delegate-admin@example.invalid',
        password='Strong-Test-Admin-Pass-2026!',
        role=UserRole.ADMIN,
    )


@pytest.mark.django_db
def test_public_signup_is_disabled_and_creates_no_account():
    client = APIClient()
    response = client.post('/api/v1/auth/register/', {
        'email': 'public-outsider@example.invalid',
        'password': 'Strong-Test-Password!2026',
        'password_confirm': 'Strong-Test-Password!2026',
    }, format='json')
    assert response.status_code == 403
    assert not User.objects.filter(email='public-outsider@example.invalid').exists()


@pytest.mark.django_db
def test_primary_owner_scan_types_are_not_filtered_by_employee_settings(company_owner, other_admin):
    # Owner access must remain available while managing the company remotely.
    company_owner.enabled_scan_types = []
    company_owner.granted_permissions = []
    company_owner.save(update_fields=['enabled_scan_types', 'granted_permissions'])
    assert company_owner.is_company_owner
    assert all(company_owner.can_scan_type(scan_type) for scan_type in (
        'code', 'url', 'ip', 'api', 'file', 'docker', 'network', 'full_validation',
    ))

    # Employee settings still apply independently of the owner's privileges.
    other_admin.enabled_scan_types = ['url']
    other_admin.save(update_fields=['enabled_scan_types'])
    assert other_admin.can_scan_type('url')
    assert not other_admin.can_scan_type('ip')


@pytest.mark.django_db
def test_only_primary_owner_can_create_activate_and_assign_employee(company_owner, other_admin):
    admin = APIClient()
    admin.force_authenticate(user=other_admin)
    payload = {
        'email': 'employee@example.invalid', 'first_name': 'Company',
        'last_name': 'Employee', 'password': 'Strong-Test-Employee!2026',
        'password_confirm': 'Strong-Test-Employee!2026',
        'role': UserRole.SECURITY_ANALYST,
        'granted_permissions': ['project.read', 'scan.create'],
        'enabled_scan_types': ['url', 'file'],
    }
    assert admin.post('/api/v1/auth/users/', payload, format='json').status_code == 403

    owner = APIClient()
    owner.force_authenticate(user=company_owner)
    created = owner.post('/api/v1/auth/users/', payload, format='json')
    assert created.status_code == 201, created.data
    employee = User.objects.get(email=payload['email'])
    assert employee.is_active is False
    assert employee.is_superuser is False
    assert employee.role == UserRole.SECURITY_ANALYST
    assert employee.get_effective_permissions() == ['project.read', 'scan.create']
    assert employee.can_scan_type('url') is True
    assert employee.can_scan_type('file') is True
    assert employee.can_scan_type('ip') is False
    assert employee.has_permission('user.update') is False

    detail = f'/api/v1/auth/users/{employee.pk}/'
    assert admin.patch(detail, {'role':'admin'}, format='json').status_code == 403
    assert admin.post(detail + 'activate/', {}, format='json').status_code == 403

    activated = owner.post(detail + 'activate/', {}, format='json')
    assert activated.status_code == 200
    employee.refresh_from_db()
    assert employee.is_active

    grant = owner.patch(detail, {
        'role':UserRole.ADMIN,
        'granted_permissions':['project.read','scan.create','system.monitor'],
        'enabled_scan_types':['ip'],
    },format='json')
    assert grant.status_code == 200, grant.data
    employee.refresh_from_db()
    assert employee.role == UserRole.ADMIN
    assert employee.can_scan_type('url') is False
    assert employee.can_scan_type('ip') is True
    assert employee.has_permission('system.monitor') is True
    assert employee.has_permission('user.update') is False

    assert owner.post(detail + 'set_password/', {'password':'Replacement-Password!2026'}, format='json').status_code == 200
    employee.refresh_from_db()
    assert employee.check_password('Replacement-Password!2026')

    assert owner.post(detail + 'deactivate/', {}, format='json').status_code == 200
    employee.refresh_from_db()
    assert not employee.is_active


@pytest.mark.django_db
def test_owner_credential_and_identity_are_not_delegable(company_owner, other_admin):
    owner = APIClient()
    owner.force_authenticate(user=company_owner)
    owner_detail = f'/api/v1/auth/users/{company_owner.pk}/'
    assert owner.post(owner_detail+'deactivate/',{},format='json').status_code == 400
    assert owner.post(owner_detail+'set_password/',{'password':'NewSecret!2026'},format='json').status_code == 403
    assert owner.delete(owner_detail).status_code == 403
    assert owner.patch(owner_detail, {'role':UserRole.VIEWER}, format='json').status_code == 403
    assert owner.post('/api/v1/auth/deactivate-self/', {'password':'Strong-Test-Owner-Pass-2026!'},format='json').status_code == 403
    assert company_owner.is_company_owner is True
    assert other_admin.is_company_owner is False


@pytest.mark.django_db
def test_owner_delegates_scoped_super_admin_without_delegating_company_ownership(company_owner):
    owner = APIClient()
    owner.force_authenticate(user=company_owner)
    response = owner.get('/api/v1/auth/users/access_options/')
    assert response.status_code == 200
    assert UserRole.SUPER_ADMIN in response.data['roles']
    assert 'user.update' in response.data['roles'][UserRole.SUPER_ADMIN]

    email = 'operational-delegate@example.invalid'
    created = owner.post('/api/v1/auth/users/', {
        'email': email, 'first_name': 'Operational', 'last_name': 'Delegate',
        'password': 'Strong-Delegate-Pass!2026',
        'password_confirm': 'Strong-Delegate-Pass!2026',
        'role': UserRole.SUPER_ADMIN,
        'granted_permissions': ['project.read', 'scan.create', 'system.monitor', 'user.update'],
        'enabled_scan_types': ['url'],
        'enabled_pages': ['/projects', '/system'],
    }, format='json')
    assert created.status_code == 201, created.data

    delegate = User.objects.get(email=email)
    assert delegate.role == UserRole.SUPER_ADMIN
    assert delegate.is_active is False
    assert delegate.is_superuser is False
    assert delegate.is_staff is False
    assert delegate.is_company_owner is False
    assert delegate.get_effective_permissions() == ['project.read', 'scan.create', 'system.monitor', 'user.update']
    assert delegate.can_scan_type('url') is True
    assert delegate.can_scan_type('ip') is False

    delegate_detail = f'/api/v1/auth/users/{delegate.pk}/'
    assert owner.post(delegate_detail + 'activate/', {}, format='json').status_code == 200
    delegate.refresh_from_db()
    assert delegate.is_active
    assert delegate.is_company_owner is False
    secondary = APIClient()
    secondary.force_authenticate(user=delegate)
    assert secondary.post('/api/v1/auth/users/', {
        'email': 'not-delegated@example.invalid',
        'first_name': 'Cannot', 'last_name': 'Provision',
        'password': 'Strong-Password-Test!2026',
        'password_confirm': 'Strong-Password-Test!2026',
    }, format='json').status_code == 403
    assert secondary.patch(
        f'/api/v1/auth/users/{company_owner.pk}/',
        {'role': UserRole.VIEWER}, format='json',
    ).status_code == 403
    assert secondary.post(
        delegate_detail + 'deactivate/', {}, format='json',
    ).status_code == 403
    assert company_owner.is_company_owner is True


@pytest.mark.django_db
def test_promoting_legacy_admin_with_null_grants_cannot_implicitly_grant_everything(company_owner):
    legacy = User.objects.create_user(
        email='legacy-delegate@example.invalid',
        password='Strong-Legacy-Test-Password!2026',
        role=UserRole.ADMIN,
    )
    assert legacy.granted_permissions is None
    owner = APIClient()
    owner.force_authenticate(user=company_owner)
    response = owner.patch(
        f'/api/v1/auth/users/{legacy.pk}/',
        {'role': UserRole.SUPER_ADMIN},
        format='json',
    )
    assert response.status_code == 200, response.data
    legacy.refresh_from_db()
    assert legacy.role == UserRole.SUPER_ADMIN
    assert legacy.granted_permissions == []
    assert legacy.get_effective_permissions() == []
    assert not legacy.is_superuser
    assert not legacy.is_company_owner



@pytest.mark.django_db
def test_owner_grants_must_stay_within_role_and_scan_types_are_validated(company_owner):
    owner = APIClient()
    owner.force_authenticate(user=company_owner)
    base = {
        'email':'restricted@example.invalid','first_name':'Restricted','last_name':'Staff',
        'password':'Strong-Test-Password!2026',
        'password_confirm':'Strong-Test-Password!2026',
        'role':UserRole.VIEWER,
    }
    response = owner.post('/api/v1/auth/users/', {
        **base,'granted_permissions':['scan.create'],'enabled_scan_types':['url'],
    },format='json')
    assert response.status_code == 400
    response = owner.post('/api/v1/auth/users/',{
        **base,'granted_permissions':[], 'enabled_scan_types':['not-a-scan'],
    },format='json')
    assert response.status_code == 400
    assert not User.objects.filter(email=base['email']).exists()


@pytest.mark.django_db
@override_settings(CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}})
def test_cookie_owner_provisions_and_revokes_staff_through_real_auth(company_owner):
    """Exercise real CSRF + JWT cookies, not just force_authenticated mocks."""
    owner = APIClient(enforce_csrf_checks=True)
    owner_csrf = owner.get('/api/v1/auth/csrf/').json()['csrfToken']
    login = owner.post('/api/v1/auth/login/', {
        'email': company_owner.email, 'password': 'Strong-Test-Owner-Pass-2026!',
    }, format='json', HTTP_X_CSRFTOKEN=owner_csrf)
    assert login.status_code == 200, login.data
    assert 'aegis_access' in login.cookies

    staff_email = 'staff-cookie-lifecycle@example.invalid'
    staff_password = 'Strong-Test-Employee!2026'
    created = owner.post('/api/v1/auth/users/', {
        'email': staff_email, 'first_name': 'Scoped', 'last_name': 'Employee',
        'password': staff_password, 'password_confirm': staff_password,
        'role': UserRole.SECURITY_ANALYST,
        'granted_permissions': ['project.read', 'scan.create'],
        'enabled_scan_types': ['url'],
        'enabled_pages': ['/projects', '/assess'],
    }, format='json', HTTP_X_CSRFTOKEN=owner_csrf)
    assert created.status_code == 201, created.data
    employee = User.objects.get(email=staff_email)
    assert not employee.is_active

    staff = APIClient(enforce_csrf_checks=True)
    staff_csrf = staff.get('/api/v1/auth/csrf/').json()['csrfToken']
    inactive_login = staff.post('/api/v1/auth/login/', {
        'email': staff_email, 'password': staff_password,
    }, format='json', HTTP_X_CSRFTOKEN=staff_csrf)
    assert inactive_login.status_code == 401

    detail = f'/api/v1/auth/users/{employee.pk}/'
    assert owner.post(detail + 'activate/', {}, format='json',
                      HTTP_X_CSRFTOKEN=owner_csrf).status_code == 200
    live_login = staff.post('/api/v1/auth/login/', {
        'email': staff_email, 'password': staff_password,
    }, format='json', HTTP_X_CSRFTOKEN=staff_csrf)
    assert live_login.status_code == 200, live_login.data
    assert staff.get('/api/v1/auth/users/me/').status_code == 200
    assert staff.post('/api/v1/auth/users/', {
        'email': 'unauthorized@example.invalid',
    }, format='json', HTTP_X_CSRFTOKEN=staff_csrf).status_code == 403

    assert owner.post(detail + 'deactivate/', {}, format='json',
                      HTTP_X_CSRFTOKEN=owner_csrf).status_code == 200
    assert staff.get('/api/v1/auth/users/me/').status_code == 401
    assert staff.post('/api/v1/auth/refresh/', {}, format='json',
                      HTTP_X_CSRFTOKEN=staff_csrf).status_code == 401
    assert not User.objects.filter(email='unauthorized@example.invalid').exists()
    assert owner.get('/api/v1/auth/users/me/').status_code == 200
