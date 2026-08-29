from __future__ import annotations

import os
from datetime import datetime, timezone
from django.db import transaction

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
import django

django.setup()

from celery import shared_task
from evidence.models import Evidence
from scans.models import Scan
from .security_scan import *
