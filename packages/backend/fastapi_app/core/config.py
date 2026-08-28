from typing import List
import os
import tempfile

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "AegisScan Platform"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"

    SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", os.getenv("SECRET_KEY", ""))
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 1440

    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://aegis:aegis@localhost:5432/aegisdb")

    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    REDIS_SSL_CERT_REQS: str = os.getenv("REDIS_SSL_CERT_REQS", "required")

    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    DJANGO_API_URL: str = os.getenv("DJANGO_API_URL", "http://localhost:8000/api/v1")

    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
    CELERY_RESULT_BACKEND: str = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")

    MAX_CONCURRENT_SCANS: int = 5
    DEFAULT_SCAN_TIMEOUT: int = 3600
    ENGINE_TIMEOUT: int = 300
    MAX_FILE_SIZE: int = 100 * 1024 * 1024
    UPLOAD_DIR: str = os.path.join(tempfile.gettempdir(), "aegis_uploads")
    HOST: str = os.getenv("AEGIS_HOST") or "0.0.0.0"  # nosec B104
    PORT: int = 8001

    PROMETHEUS_ENABLED: bool = True
    METRICS_PORT: int = 9090
    OTEL_ENABLED: bool = True
    OTEL_SERVICE_NAME: str = "aegisscan-fastapi"

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True, extra="ignore")

    @model_validator(mode="after")
    def validate_production_security(self):
        production = os.getenv("AEGIS_ENV", "development").lower() == "production"
        if production:
            if len(self.SECRET_KEY) < 32 or self.SECRET_KEY in {"your-secret-key-change-in-production", "change-me"}:
                raise ValueError("A strong SECRET_KEY/JWT_SECRET_KEY is required in production")
            if not self.REDIS_URL.startswith("rediss://"):
                raise ValueError("Production Redis must use rediss:// TLS")
            if self.REDIS_SSL_CERT_REQS != "required":
                raise ValueError("Production Redis certificate verification must be required")
            if "localhost" in self.DATABASE_URL or "127.0.0.1" in self.DATABASE_URL:
                raise ValueError("Production DATABASE_URL must not point to localhost")
        return self


settings = Settings()
