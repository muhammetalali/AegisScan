from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from .config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
TOKEN_ISSUER = "aegisscan"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def _expires_in(minutes: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=minutes)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "token_type": "access", "iss": TOKEN_ISSUER})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    to_encode.update({"exp": _expires_in(settings.REFRESH_TOKEN_EXPIRE_MINUTES), "token_type": "refresh", "iss": TOKEN_ISSUER})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)


async def verify_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM], issuer=TOKEN_ISSUER)
        if payload.get("token_type") != "access" or not payload.get("user_id"):
            return None
        return payload
    except JWTError:
        return None


async def verify_refresh_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM], issuer=TOKEN_ISSUER)
        if payload.get("token_type") != "refresh" or not payload.get("user_id"):
            return None
        return payload
    except JWTError:
        return None
