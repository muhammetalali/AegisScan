@echo off
echo === AegisScan Platform - Windows 11 Starter ===
powershell -ExecutionPolicy Bypass -Command ".\.venv\Scripts\Activate.ps1; $env:PYTHONIOENCODING='utf-8'; $env:PATH += ';C:\Users\muham\AppData\Roaming\Python\Python314\Scripts'; Write-Host 'Core tests:'; python -m pytest tests/ -q; Write-Host ''; Write-Host 'CLI:'; aegis version"
echo.
echo Frontend: cd packages\web ^&^& npm install ^&^& npm run dev
echo Open VS Code: code C:\Users\muham\Desktop\AegisScan-1
pause
