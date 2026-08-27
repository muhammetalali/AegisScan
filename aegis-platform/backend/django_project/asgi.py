"""
ASGI config for AegisScan Platform.
"""
import os
import sys
from pathlib import Path

# Allow Django apps stored under django_project/ to keep their existing
# top-level app imports (core, users, scans, ...).
PROJECT_DIR = Path(__file__).resolve().parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')

from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack

django_asgi_app = get_asgi_application()

# Consumers call get_user_model() during module import, so Django's app
# registry must be initialized before importing websocket routing.
from core.routing import websocket_urlpatterns

application = ProtocolTypeRouter({
    'http': django_asgi_app,
    'websocket': AuthMiddlewareStack(
        URLRouter(websocket_urlpatterns)
    ),
})
