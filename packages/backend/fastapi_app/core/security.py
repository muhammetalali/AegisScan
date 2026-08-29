from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from asgiref.sync import sync_to_async
from jose import jwt, JWTError
from passlib.context import CryptContext

from .config import settings


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "token_type": "access"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "token_type": "refresh"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def _token_type(payload: Dict[str, Any]) -> Optional[str]:
    return payload.get("token_type") or payload.get("type")


@sync_to_async
def _load_active_user(user_id: Any) -> Optional[Dict[str, Any]]:
    from django.contrib.auth import get_user_model
    from django_project.users.models import ROLE_PERMISSIONS

    User = get_user_model()
    try:
        user = User.objects.get(pk=user_id)
    except (User.DoesNotExist, ValueError, TypeError):
        return None
    if not user.is_active:
        return None
    return {
        "id": str(user.pk),
        "email": user.email,
        "role": user.role,
        "is_staff": user.is_staff,
        "is_superuser": user.is_superuser,
        "permissions": [p.value if hasattr(p, "value") else p for p in ROLE_PERMISSIONS.get(user.role, [])],
    }


async def verify_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if _token_type(payload) != "access":
            return None
        user_id = payload.get("user_id") or payload.get("sub")
        if user_id is None:
            return None
        user = await _load_active_user(user_id)
        if not user:
            return None
        return {**payload, **user}
    except JWTError:
        return None


async def verify_refresh_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if _token_type(payload) != "refresh":
            return None
        user_id = payload.get("user_id") or payload.get("sub")
        if user_id is None:
            return None
        user = await _load_active_user(user_id)
        if not user:
            return None
        return {**payload, **user}
    except JWTError:
        return None
