#!/usr/bin/env python
"""Repository-root entrypoint for the Django backend."""
from pathlib import Path
import runpy
import sys

ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "packages" / "backend"
BACKEND_MANAGE = BACKEND_DIR / "manage.py"

if not BACKEND_MANAGE.is_file():
    raise SystemExit(f"Django manage.py not found: {BACKEND_MANAGE}")

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

runpy.run_path(str(BACKEND_MANAGE), run_name="__main__")
