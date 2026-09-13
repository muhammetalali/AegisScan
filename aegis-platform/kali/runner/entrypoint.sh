#!/bin/sh
set -eu

umask 077
exec python3 /opt/aegis-runner/runner.py
