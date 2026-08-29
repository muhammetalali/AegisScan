from pydantic_settings import BaseSettings
from typing import List
import os

class Settings(BaseSettings):
    PROJECT_NAME: str = 'AegisScan Platform'
    VERSION: str = '1.0.0'
    API_V1_STR: str = '/api/v1'

    SECRET_KEY: str = os.getenv('JWT_SECRET_KEY', os.getenv('SECRET_KEY', 'change-me'))
    ALGORITHM: str = 'HS256'
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 1440
    DATABASE_URL: str = os.getenv('DATABASE_URL', 'postgresql://aegis:aegis@localhost:5432/aegisdb')
    REDIS_URL: str = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    DJANGO_API_URL: str = os.getenv('DJANGO_API_URL', 'http://localhost:8000/api/v1')
    CELERY_BROKER_URL: str = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    CELERY_RESULT_BACKEND: str = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
    MAX_CONCURRENT_SCANS: int = 5
    DEFAULT_SCAN_TIMEOUT: int = 3600
    ENGINE_TIMEOUT: int = 300
    MAX_FILE_SIZE: int = 100 * 1024 * 1024
    UPLOAD_DIR: str = '/tmp/aegis_uploads'
    PROMETHEUS_ENABLED: bool = True
    METRICS_PORT: int = 9090

    class Config:
        env_file = '.env'
        case_sensitive = True

settings = Settings()
