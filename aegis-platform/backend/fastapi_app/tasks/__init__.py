"""Celery task package.

Task modules are discovered by Celery; this package intentionally avoids eager
imports so one task module cannot break imports of another task or test module.
"""
