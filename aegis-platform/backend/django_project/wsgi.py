"""
WSGI config for AegisScan Platform.
"""
import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aegis_core.settings')

application = get_wsgi_application()