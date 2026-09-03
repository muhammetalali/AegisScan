import pytest
from fastapi.testclient import TestClient

from django_project.audit.models import AuditLog
from django_project.users.models import APIKey, LoginAttempt, Team, TeamMembership, User, UserRole
from fastapi_app.core.dependencies import get_current_user
from fastapi_app.main import app

pytestmark = pytest.mark.django_db(transaction=True)


def _context():
    user = User.objects.create_user(email='audit-e2e@example.invalid', password='Strong-Test-Password-123!', role=UserRole.ADMIN)
    team = Team.objects.create(name='Real Audit Team', owner=user)
    TeamMembership.objects.create(team=team, user=user, role=TeamMembership.Role.OWNER)
    APIKey.objects.create(name='Real Key', key_hash='hash', key_prefix='aegis_test', user=user, team=team, permissions=['audit.read'])
    LoginAttempt.objects.create(email=user.email, ip_address='127.0.0.1', user_agent='pytest', success=True)
    AuditLog.objects.create(user=user, action=AuditLog.Action.LOGIN, result=AuditLog.Result.SUCCESS, resource_type='user', resource_id=str(user.id), resource_repr=user.email, ip_address='127.0.0.1')
    app.dependency_overrides[get_current_user] = lambda: {'user_id': str(user.id)}
    return user


def teardown_function(_function):
    app.dependency_overrides.clear()


def test_audit_logs_are_persisted_not_seeded():
    user = _context()
    client = TestClient(app)
    response = client.get('/audit/logs')
    assert response.status_code == 200
    payload = response.json()
    assert payload['total'] == 1
    assert payload['items'][0]['user'] == user.email
    assert payload['items'][0]['request_id']


def test_users_teams_keys_and_login_attempts_are_database_backed():
    user = _context()
    client = TestClient(app)
    users = client.get('/audit/users').json()
    teams = client.get('/audit/teams').json()
    keys = client.get('/audit/api-keys').json()
    attempts = client.get('/audit/login-attempts').json()
    assert users['total'] == 1
    assert teams['total'] == 1
    assert keys['total'] == 1
    assert attempts['total'] == 1
    assert users['items'][0]['email'] == user.email
    assert teams['items'][0]['name'] == 'Real Audit Team'
    assert keys['items'][0]['name'] == 'Real Key'
    assert attempts['items'][0]['success'] is True


def test_audit_roles_are_declarative_and_no_fake_users_exist():
    _context()
    client = TestClient(app)
    roles = client.get('/audit/roles').json()
    assert roles['total'] == len([*UserRole])
    assert all(row['id'] in {r.value for r in UserRole} for row in roles['items'])
