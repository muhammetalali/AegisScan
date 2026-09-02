# Enterprise Migration Gate

This directory is governed by Django's migration graph and CI migration checks.

The initial enterprise migration is a dependency bootstrap. Django CI is responsible for generating and validating subsequent model-state migrations from `enterprise/models.py` before PostgreSQL application.
