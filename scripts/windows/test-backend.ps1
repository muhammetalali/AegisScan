[CmdletBinding()]
param(
    [string]$TestPath = "packages/backend/django_project/users/test_cookie_auth.py"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $RepoRoot

$ComposeFile = "packages/platform/docker-compose.yml"
$EnvFile = "packages/platform/.env"
$EnvExample = "packages/platform/.env.example"

if (-not (Test-Path $EnvFile)) {
    throw "Missing $EnvFile. Copy $EnvExample to $EnvFile and provide real local development secrets before starting the stack."
}

Write-Host "==> Validating Docker Compose configuration"
docker compose --env-file $EnvFile -f $ComposeFile config | Out-Null

Write-Host "==> Starting PostgreSQL and Redis"
docker compose --env-file $EnvFile -f $ComposeFile up -d --build postgres redis

Write-Host "==> Waiting for PostgreSQL and Redis health"
$deadline = (Get-Date).AddMinutes(3)
while ((Get-Date) -lt $deadline) {
    $rows = docker compose --env-file $EnvFile -f $ComposeFile ps --format json postgres redis | ConvertFrom-Json
    if ($rows -isnot [array]) { $rows = @($rows) }
    $healthy = $rows.Count -ge 2 -and ($rows | Where-Object { $_.Name -match 'postgres' -and $_.Health -eq 'healthy' }) -and ($rows | Where-Object { $_.Name -match 'redis' -and $_.Health -eq 'healthy' })
    if ($healthy) { break }
    Start-Sleep -Seconds 3
}

if ((Get-Date) -ge $deadline) {
    docker compose --env-file $EnvFile -f $ComposeFile ps
    throw "PostgreSQL/Redis did not become healthy within the expected window."
}

Write-Host "==> Building the Django test image"
docker compose --env-file $EnvFile -f $ComposeFile build django

Write-Host "==> Running Django migrations in an isolated test container"
docker compose --env-file $EnvFile -f $ComposeFile run --rm --no-deps django python manage.py migrate --noinput

Write-Host "==> Running: $TestPath"
docker compose --env-file $EnvFile -f $ComposeFile run --rm --no-deps django python -m pytest $TestPath -q

Write-Host "==> Backend test completed successfully."
