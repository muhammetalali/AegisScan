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
    assert owner.post('/api/v1/auth/users/', {
        'email':'fake-owner@example.invalid','password':'Strong-Test-Password!2026',
        'password_confirm':'Strong-Test-Password!2026',
        'role':UserRole.SUPER_ADMIN,
    },format='json').status_code == 400
    assert company_owner.is_company_owner is True
    assert other_admin.is_company_owner is False


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
