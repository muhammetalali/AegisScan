import sys
from datetime import timedelta
from pathlib import Path

import environ

BASE_DIR = Path(__file__).resolve().parent.parent
DJANGO_APPS_DIR = BASE_DIR / "django_project"
if str(DJANGO_APPS_DIR) not in sys.path:
    sys.path.insert(0, str(DJANGO_APPS_DIR))

LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

env = environ.Env(
    DEBUG=(bool, False),
    SECRET_KEY=(str, None),
    ALLOWED_HOSTS=(list, ["*"]),
    CORS_ALLOWED_ORIGINS=(list, ["http://localhost:5173", "http://127.0.0.1:5173"]),
    DATABASE_URL=(str, None),
    REDIS_URL=(str, None),
    CELERY_BROKER_URL=(str, None),
    CELERY_RESULT_BACKEND=(str, None),
    JWT_SECRET_KEY=(str, None),
    JWT_ACCESS_TOKEN_LIFETIME=(int, 60),
    JWT_REFRESH_TOKEN_LIFETIME=(int, 1440),
    AUTH_ACCESS_COOKIE=(str, "aegis_access"),
    AUTH_REFRESH_COOKIE=(str, "aegis_refresh"),
    EMAIL_HOST=(str, None),
    EMAIL_PORT=(int, 587),
    EMAIL_HOST_USER=(str, ""),
    EMAIL_HOST_PASSWORD=(str, ""),
    EMAIL_USE_TLS=(bool, True),
    DEFAULT_FROM_EMAIL=(str, ""),
    FRONTEND_URL=(str, "http://localhost:5173"),
    SENTRY_DSN=(str, ""),
    LOG_LEVEL=(str, "INFO"),
    LOG_TO_FILE=(bool, True),
    WS_ALLOW_QUERY_TOKEN=(bool, False),
    SECURE_SSL_REDIRECT=(bool, False),
)
environ.Env.read_env(BASE_DIR / ".env")

SECRET_KEY = env("SECRET_KEY")
DEBUG = env("DEBUG")
ALLOWED_HOSTS = env("ALLOWED_HOSTS")
DATABASE_URL = env("DATABASE_URL")
REDIS_URL = env("REDIS_URL")
CELERY_BROKER_URL = env("CELERY_BROKER_URL")
CELERY_RESULT_BACKEND = env("CELERY_RESULT_BACKEND")
JWT_SECRET_KEY = env("JWT_SECRET_KEY")
JWT_ACCESS_TOKEN_LIFETIME = timedelta(minutes=env("JWT_ACCESS_TOKEN_LIFETIME"))
JWT_REFRESH_TOKEN_LIFETIME = timedelta(minutes=env("JWT_REFRESH_TOKEN_LIFETIME"))
AUTH_ACCESS_COOKIE = env("AUTH_ACCESS_COOKIE")
AUTH_REFRESH_COOKIE = env("AUTH_REFRESH_COOKIE")
WS_ALLOW_QUERY_TOKEN = env("WS_ALLOW_QUERY_TOKEN")
LOG_TO_FILE = env("LOG_TO_FILE")

required_runtime_settings = {
    "SECRET_KEY": SECRET_KEY,
    "DATABASE_URL": DATABASE_URL,
    "REDIS_URL": REDIS_URL,
    "CELERY_BROKER_URL": CELERY_BROKER_URL,
    "CELERY_RESULT_BACKEND": CELERY_RESULT_BACKEND,
    "JWT_SECRET_KEY": JWT_SECRET_KEY,
}
missing_runtime_settings = [name for name, value in required_runtime_settings.items() if not value]
if missing_runtime_settings:
    raise RuntimeError("Required runtime settings are missing: " + ", ".join(missing_runtime_settings))

if len(SECRET_KEY) < 32:
    raise RuntimeError("SECRET_KEY must be at least 32 characters")
if len(JWT_SECRET_KEY) < 32:
    raise RuntimeError("JWT_SECRET_KEY must be at least 32 characters")
if not DEBUG:
    if not ALLOWED_HOSTS or "*" in ALLOWED_HOSTS:
        raise RuntimeError("Explicit ALLOWED_HOSTS are required when DEBUG=0")
    WS_ALLOW_QUERY_TOKEN = False

INSTALLED_APPS = [
    "django.contrib.admin", "django.contrib.auth", "django.contrib.contenttypes",
    "django.contrib.sessions", "django.contrib.messages", "django.contrib.staticfiles",
    "rest_framework", "rest_framework_simplejwt", "rest_framework_simplejwt.token_blacklist", "corsheaders", "django_filters",
    "django_celery_beat", "django_celery_results", "channels", "drf_spectacular",
    "health_check", "core", "users", "projects", "scans", "vulnerabilities", "reports",
    "assets", "compliance", "knowledge", "notifications", "audit", "system", "security_sessions",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "core.middleware.SecurityHeadersMiddleware",
]

ROOT_URLCONF = "django_project.urls"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [BASE_DIR / "templates"],
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.debug", "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth", "django.contrib.messages.context_processors.messages",
    ]},
}]
WSGI_APPLICATION = "django_project.wsgi.application"
ASGI_APPLICATION = "django_project.asgi.application"

DATABASES = {"default": env.db("DATABASE_URL")}
DATABASES["default"]["CONN_MAX_AGE"] = 60
DATABASES["default"]["CONN_HEALTH_CHECKS"] = True
if DATABASES["default"]["ENGINE"].endswith("postgresql"):
    DATABASES["default"]["OPTIONS"] = {"connect_timeout": 10}

CACHES = {"default": {"BACKEND": "django.core.cache.backends.redis.RedisCache", "LOCATION": REDIS_URL, "KEY_PREFIX": "aegis"}}
SESSION_ENGINE = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS = "default"
CORS_ALLOWED_ORIGINS = env("CORS_ALLOWED_ORIGINS")
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_ALL_ORIGINS = DEBUG
CSRF_TRUSTED_ORIGINS = env("CORS_ALLOWED_ORIGINS")

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "users.authentication.CookieJWTAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_FILTER_BACKENDS": (
        "django_filters.rest_framework.DjangoFilterBackend", "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 20,
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "EXCEPTION_HANDLER": "core.exceptions.custom_exception_handler",
    "DATETIME_FORMAT": "%Y-%m-%dT%H:%M:%S.%fZ",
}
SPECTACULAR_SETTINGS = {
    "TITLE": "AegisScan Platform API", "DESCRIPTION": "Security Validation Platform API Documentation",
    "VERSION": "1.0.0", "SERVE_INCLUDE_SCHEMA": False, "COMPONENT_SPLIT_REQUEST": True,
    "SCHEMA_PATH_PREFIX": "/api/v1",
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": JWT_ACCESS_TOKEN_LIFETIME,
    "REFRESH_TOKEN_LIFETIME": JWT_REFRESH_TOKEN_LIFETIME,
    "ROTATE_REFRESH_TOKENS": True, "BLACKLIST_AFTER_ROTATION": True, "UPDATE_LAST_LOGIN": True,
    "ALGORITHM": "HS256", "SIGNING_KEY": JWT_SECRET_KEY, "AUTH_HEADER_TYPES": ("Bearer",),
    "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION", "USER_ID_FIELD": "id", "USER_ID_CLAIM": "user_id",
    "TOKEN_TYPE_CLAIM": "token_type", "JTI_CLAIM": "jti",
}

CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = "UTC"
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 3600
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_BEAT_SCHEDULER = "django_celery_beat.schedulers:DatabaseScheduler"

CHANNEL_LAYERS = {"default": {"BACKEND": "channels_redis.core.RedisChannelLayer", "CONFIG": {"hosts": [REDIS_URL]}}}
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
AUTH_USER_MODEL = "users.User"

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = env("SECURE_SSL_REDIRECT")
SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_HSTS_PRELOAD = not DEBUG
SECURE_CONTENT_TYPE_NOSNIFF = True
SESSION_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_SAMESITE = "Lax"
USE_TZ = True
TIME_ZONE = "UTC"

DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL")
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = env("EMAIL_HOST")
EMAIL_PORT = env("EMAIL_PORT")
EMAIL_HOST_USER = env("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD")
EMAIL_USE_TLS = env("EMAIL_USE_TLS")
FRONTEND_URL = env("FRONTEND_URL")

_handlers = {
    "console": {"class": "logging.StreamHandler", "formatter": "verbose"},
}
if LOG_TO_FILE:
    _handlers["file"] = {
        "class": "logging.FileHandler",
        "filename": str(LOG_DIR / "django.log"),
        "formatter": "verbose",
    }

LOGGING = {
    "version": 1, "disable_existing_loggers": False,
    "formatters": {"verbose": {"format": "{levelname} {asctime} {name} {message}", "style": "{"}},
    "handlers": _handlers,
    "root": {"handlers": list(_handlers), "level": env("LOG_LEVEL")},
}
