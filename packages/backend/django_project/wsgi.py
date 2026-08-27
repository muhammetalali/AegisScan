"""
WSGI config for AegisScan Platform.
"""
import os
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')

from django.core.wsgi import get_wsgi_application

application = get_wsgi_application()
