import os
from pathlib import Path
from datetime import timedelta
import environ

BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env(
    DEBUG=(bool, False),
    SECRET_KEY=(str, 'django-insecure-change-me-in-production'),
    ALLOWED_HOSTS=(list, ['localhost', '127.0.0.1']),
    CORS_ALLOWED_ORIGINS=(list, ['http://localhost:5173', 'http://127.0.0.1:5173']),
    DATABASE_URL=(str, 'postgresql://aegis:aegis@localhost:5432/aegisdb'),
    REDIS_URL=(str, 'redis://localhost:6379/0'),
    CELERY_BROKER_URL=(str, 'redis://localhost:6379/0'),
    CELERY_RESULT_BACKEND=(str, 'redis://localhost:6379/0'),
    JWT_SECRET_KEY=(str, 'jwt-secret-change-me'),
    JWT_ACCESS_TOKEN_LIFETIME=(int, 60),
    JWT_REFRESH_TOKEN_LIFETIME=(int, 1440),
    AUTH_COOKIE_SECURE=(bool, False),
    EMAIL_HOST=(str, 'smtp.gmail.com'),
    EMAIL_PORT=(int, 587),
    EMAIL_HOST_USER=(str, ''),
    EMAIL_HOST_PASSWORD=(str, ''),
    EMAIL_USE_TLS=(bool, True),
    DEFAULT_FROM_EMAIL=(str, 'AegisScan <noreply@aegisscan.local>'),
    FRONTEND_URL=(str, 'http://localhost:5173'),
    SENTRY_DSN=(str, ''),
    LOG_LEVEL=(str, 'INFO'),
)
environ.Env.read_env(BASE_DIR / '.env')

SECRET_KEY = env('SECRET_KEY')
DEBUG = env('DEBUG')
ALLOWED_HOSTS = env('ALLOWED_HOSTS')

INSTALLED_APPS = [
    'django.contrib.admin', 'django.contrib.auth', 'django.contrib.contenttypes', 'django.contrib.sessions', 'django.contrib.messages', 'django.contrib.staticfiles',
    'rest_framework', 'rest_framework_simplejwt', 'rest_framework_simplejwt.token_blacklist', 'corsheaders', 'django_filters', 'django_celery_beat', 'django_celery_results', 'channels', 'drf_spectacular',
    'health_check', 'health_check.db', 'health_check.cache', 'health_check.storage',
    'core', 'users', 'projects', 'scans', 'vulnerabilities', 'assets', 'compliance', 'knowledge', 'notifications', 'audit', 'system', 'evidence',
]

MIDDLEWARE = ['corsheaders.middleware.CorsMiddleware', 'django.middleware.security.SecurityMiddleware', 'django.contrib.sessions.middleware.SessionMiddleware', 'django.middleware.common.CommonMiddleware', 'django.middleware.csrf.CsrfViewMiddleware', 'django.contrib.auth.middleware.AuthenticationMiddleware', 'django.contrib.messages.middleware.MessageMiddleware', 'django.middleware.clickjacking.XFrameOptionsMiddleware']
ROOT_URLCONF = 'django_project.urls'
TEMPLATES = [{'BACKEND': 'django.template.backends.django.DjangoTemplates', 'DIRS': [BASE_DIR / 'templates'], 'APP_DIRS': True, 'OPTIONS': {'context_processors': ['django.template.context_processors.debug', 'django.template.context_processors.request', 'django.contrib.auth.context_processors.auth', 'django.contrib.messages.context_processors.messages']}}]
WSGI_APPLICATION = 'django_project.wsgi.application'
ASGI_APPLICATION = 'django_project.asgi.application'
DATABASES = {'default': env.db('DATABASE_URL')}
DATABASES['default']['CONN_MAX_AGE'] = 60
DATABASES['default']['OPTIONS'] = {'connect_timeout': 10}
CACHES = {'default': {'BACKEND': 'django_redis.cache.RedisCache', 'LOCATION': env('REDIS_URL'), 'OPTIONS': {'CLIENT_CLASS': 'django_redis.client.DefaultClient', 'COMPRESSOR': 'django_redis.compressors.zlib.ZlibCompressor'}, 'KEY_PREFIX': 'aegis'}}
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'

# Explicit origin allow-list. Never enable wildcard CORS for this platform.
CORS_ALLOWED_ORIGINS = env('CORS_ALLOWED_ORIGINS')
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_ALL_ORIGINS = False
CSRF_TRUSTED_ORIGINS = env('CORS_ALLOWED_ORIGINS')

# JWT remains the authentication mechanism; cookies only change where the tokens live.
AUTH_COOKIE_SECURE = env('AUTH_COOKIE_SECURE') or not DEBUG
AUTH_COOKIE_SAMESITE = 'Lax'
AUTH_COOKIE_HTTPONLY = True
AUTH_ACCESS_COOKIE = 'aegis_access'
AUTH_REFRESH_COOKIE = 'aegis_refresh'
SESSION_COOKIE_SECURE = AUTH_COOKIE_SECURE
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SECURE = AUTH_COOKIE_SECURE
CSRF_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_HTTPONLY = False
if not DEBUG:
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SECURE_SSL_REDIRECT = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = 'DENY'

REST_FRAMEWORK = {'DEFAULT_AUTHENTICATION_CLASSES': ('users.authentication.CookieJWTAuthentication', 'rest_framework_simplejwt.authentication.JWTAuthentication', 'rest_framework.authentication.SessionAuthentication'), 'DEFAULT_PERMISSION_CLASSES': ('rest_framework.permissions.IsAuthenticated',), 'DEFAULT_FILTER_BACKENDS': ('django_filters.rest_framework.DjangoFilterBackend', 'rest_framework.filters.SearchFilter', 'rest_framework.filters.OrderingFilter'), 'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination', 'PAGE_SIZE': 20, 'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema', 'EXCEPTION_HANDLER': 'core.exceptions.custom_exception_handler', 'DATETIME_FORMAT': '%Y-%m-%dT%H:%M:%S.%fZ'}
SPECTACULAR_SETTINGS = {'TITLE': 'AegisScan Platform API', 'DESCRIPTION': 'Security Validation Platform API Documentation', 'VERSION': '1.0.0', 'SERVE_INCLUDE_SCHEMA': False, 'COMPONENT_SPLIT_REQUEST': True, 'SCHEMA_PATH_PREFIX': '/api/v1', 'TAGS': [{'name': 'Authentication', 'description': 'User authentication and authorization'}, {'name': 'Projects', 'description': 'Project management'}, {'name': 'Scans', 'description': 'Security scan operations'}, {'name': 'Vulnerabilities', 'description': 'Vulnerability management'}, {'name': 'Reports', 'description': 'Report generation and management'}, {'name': 'Assets', 'description': 'Asset discovery and management'}, {'name': 'Compliance', 'description': 'Compliance and policy checking'}, {'name': 'Knowledge', 'description': 'Knowledge base and lessons learned'}, {'name': 'Notifications', 'description': 'Real-time notifications'}, {'name': 'Audit', 'description': 'Audit trail and logging'}, {'name': 'System', 'description': 'System monitoring and health'}, {'name': 'Users', 'description': 'User and role management'}]}
SIMPLE_JWT = {'ACCESS_TOKEN_LIFETIME': timedelta(minutes=env('JWT_ACCESS_TOKEN_LIFETIME')), 'REFRESH_TOKEN_LIFETIME': timedelta(minutes=env('JWT_REFRESH_TOKEN_LIFETIME')), 'ROTATE_REFRESH_TOKENS': True, 'BLACKLIST_AFTER_ROTATION': True, 'UPDATE_LAST_LOGIN': True, 'ALGORITHM': 'HS256', 'SIGNING_KEY': env('JWT_SECRET_KEY'), 'VERIFYING_KEY': None, 'AUDIENCE': None, 'ISSUER': 'aegisscan', 'JWK_URL': None, 'LEEWAY': 0, 'AUTH_HEADER_TYPES': ('Bearer',), 'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION', 'USER_ID_FIELD': 'id', 'USER_ID_CLAIM': 'user_id', 'USER_AUTHENTICATION_RULE': 'rest_framework_simplejwt.authentication.default_user_authentication_rule', 'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',), 'TOKEN_TYPE_CLAIM': 'token_type', 'TOKEN_USER_CLASS': 'rest_framework_simplejwt.models.TokenUser', 'JTI_CLAIM': 'jti', 'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp', 'SLIDING_TOKEN_LIFETIME': timedelta(minutes=env('JWT_ACCESS_TOKEN_LIFETIME')), 'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(minutes=env('JWT_REFRESH_TOKEN_LIFETIME'))}
CELERY_BROKER_URL = env('CELERY_BROKER_URL')
CELERY_RESULT_BACKEND = env('CELERY_RESULT_BACKEND')
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'UTC'
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 3600
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'
CHANNEL_LAYERS = {'default': {'BACKEND': 'channels_redis.RedisChannelLayer', 'CONFIG': {'hosts': [env('REDIS_URL')]}}}
AUTH_PASSWORD_VALIDATORS = [{'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'}, {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'}, {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'}, {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'}]
AUTH_USER_MODEL = 'users.User'
LANGUAGE_CODE = 'ar'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True
STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
MEDIA_URL = 'media/'
MEDIA_ROOT = BASE_DIR / 'media'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
LOGGING = {'version': 1, 'disable_existing_loggers': False, 'formatters': {'verbose': {'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}', 'style': '{'}, 'json': {'format': '{"level": "%(levelname)s", "time": "%(asctime)s", "module": "%(module)s", "message": "%(message)s"}'}}, 'handlers': {'console': {'class': 'logging.StreamHandler', 'formatter': 'verbose'}, 'file': {'class': 'logging.handlers.RotatingFileHandler', 'filename': BASE_DIR / 'logs' / 'aegis.log', 'maxBytes': 1024 * 1024 * 10, 'backupCount': 5, 'formatter': 'json'}}, 'root': {'handlers': ['console', 'file'], 'level': env('LOG_LEVEL')}, 'loggers': {'django': {'handlers': ['console', 'file'], 'level': 'INFO', 'propagate': False}, 'celery': {'handlers': ['console', 'file'], 'level': 'INFO', 'propagate': False}, 'channels': {'handlers': ['console', 'file'], 'level': 'INFO', 'propagate': False}, 'aegis': {'handlers': ['console', 'file'], 'level': 'DEBUG', 'propagate': False}}}
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = env('EMAIL_HOST')
EMAIL_PORT = env('EMAIL_PORT')
EMAIL_USE_TLS = env('EMAIL_USE_TLS')
EMAIL_HOST_USER = env('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_EMAIL')
FRONTEND_URL = env('FRONTEND_URL')
if env('SENTRY_DSN'):
    import sentry_sdk
    from sentry_sdk.integrations.django import DjangoIntegration
    from sentry_sdk.integrations.celery import CeleryIntegration
    from sentry_sdk.integrations.redis import RedisIntegration
    sentry_sdk.init(dsn=env('SENTRY_DSN'), integrations=[DjangoIntegration(), CeleryIntegration(), RedisIntegration()], traces_sample_rate=0.1, profiles_sample_rate=0.1, environment='production' if not DEBUG else 'development')
