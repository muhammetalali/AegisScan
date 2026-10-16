@echo off
setlocal EnableExtensions
pushd "%~dp0" || exit /b 1
echo === AegisScan - Portable Windows Starter ===
set "PYTHONIOENCODING=utf-8"
set "AEGIS_PYTHON="
if exist ".venv\Scripts\python.exe" set "AEGIS_PYTHON=%CD%\.venv\Scripts\python.exe"
if not defined AEGIS_PYTHON (
    where python >nul 2>&1
    if not errorlevel 1 set "AEGIS_PYTHON=python"
)
if not defined AEGIS_PYTHON (
    echo Python is required to launch this development workspace.
    popd
    exit /b 1
)
echo Detected Windows host network:
"%AEGIS_PYTHON%" "aegis-platform\scripts\production_network_identity.py" --windows-host
if errorlevel 1 echo Active physical Windows LAN is unavailable; do not infer target access from VMware NAT.
echo.
echo Core tests:
"%AEGIS_PYTHON%" -m pytest tests -q
if errorlevel 1 echo Tests did not pass; check the developer environment before release.
echo.
echo CLI:
if exist ".venv\Scripts\aegis.exe" (
    ".venv\Scripts\aegis.exe" version
) else (
    where aegis >nul 2>&1
    if not errorlevel 1 aegis version
)
echo.
echo Frontend: cd aegis-platform\frontend ^&^& npm run dev
echo This starter uses the current project directory, not a user-specific drive, MAC or IP.
popd
endlocal
