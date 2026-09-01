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

function Get-HealthStatus([string]$Service) {
    $containerId = docker compose --env-file $EnvFile -f $ComposeFile ps -q $Service
    if (-not $containerId) { return "missing" }
    $status = docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' $containerId
    return ($status | Out-String).Trim()
}

Write-Host "==> Waiting for PostgreSQL and Redis health"
$deadline = (Get-Date).AddMinutes(3)
while ((Get-Date) -lt $deadline) {
    $postgresHealth = Get-HealthStatus "postgres"
    $redisHealth = Get-HealthStatus "redis"
    Write-Host "    postgres=$postgresHealth redis=$redisHealth"
    if ($postgresHealth -eq "healthy" -and $redisHealth -eq "healthy") { break }
    Start-Sleep -Seconds 3
}

if ((Get-HealthStatus "postgres") -ne "healthy" -or (Get-HealthStatus "redis") -ne "healthy") {
    docker compose --env-file $EnvFile -f $ComposeFile ps
    throw "PostgreSQL/Redis did not become healthy within the expected window."
}

Write-Host "==> Building the Django test image"
docker compose --env-file $EnvFile -f $ComposeFile build django

Write-Host "==> Running Django tests in an isolated pytest database"
# pytest-django creates and tears down a test database from DATABASE_URL.
# We deliberately do not run migrate against the developer database here.
docker compose --env-file $EnvFile -f $ComposeFile run --rm --no-deps django python -m pytest $TestPath -q

Write-Host "==> Backend test completed successfully."
