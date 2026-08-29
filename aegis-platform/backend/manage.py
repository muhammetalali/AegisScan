#!/usr/bin/env python
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DJANGO_PROJECT_DIR = BASE_DIR / 'django_project'
if str(DJANGO_PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(DJANGO_PROJECT_DIR))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')

from django.core.management import execute_from_command_line

if __name__ == '__main__':
    execute_from_command_line(sys.argv)
