from os import getenv
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


def _origins() -> List[str]:
    return [
        value.strip()
        for value in getenv(
            "CORS_ALLOWED_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173",
        ).split(",")
        if value.strip()
    ]


def _is_debug() -> bool:
    return getenv("DEBUG", "False").strip().lower() in {"1", "true", "yes", "on"}


class Settings(BaseSettings):
    PROJECT_NAME: str = "AegisScan Platform"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = getenv("SECRET_KEY", "change-me")
    JWT_SECRET_KEY: str = getenv("JWT_SECRET_KEY", "")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 1440
    DATABASE_URL: str = getenv(
        "DATABASE_URL", "postgresql://aegis:aegis@localhost:5432/aegisdb"
    )
    REDIS_URL: str = getenv("REDIS_URL", "redis://localhost:6379/0")
    CORS_ORIGINS: List[str] = _origins()
    DJANGO_API_URL: str = getenv("DJANGO_API_URL", "http://localhost:8000/api/v1")
    CELERY_BROKER_URL: str = getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
    CELERY_RESULT_BACKEND: str = getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")
    MAX_CONCURRENT_SCANS: int = 5
    DEFAULT_SCAN_TIMEOUT: int = 3600
    ENGINE_TIMEOUT: int = 300
    MAX_FILE_SIZE: int = 100 * 1024 * 1024
    UPLOAD_DIR: str = "/tmp/aegis_uploads"
    PROMETHEUS_ENABLED: bool = True
    METRICS_PORT: int = 9090

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()

if not _is_debug():
    if settings.SECRET_KEY.strip().lower() in {
        "",
        "change-me",
        "changeme",
        "secret",
        "secret-key",
    }:
        raise RuntimeError(
            "Production FastAPI startup requires a real SECRET_KEY; "
            "refusing to run with a placeholder value."
        )
    if settings.JWT_SECRET_KEY.strip().lower() in {
        "",
        "change-me",
        "changeme",
        "secret",
        "secret-key",
    }:
        raise RuntimeError(
            "Production FastAPI startup requires a real JWT_SECRET_KEY; "
            "refusing to run with a placeholder value."
        )
