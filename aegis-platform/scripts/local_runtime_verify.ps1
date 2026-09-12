$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host '=== AegisScan Local Runtime Verification ===' -ForegroundColor Cyan

docker compose config --quiet
if ($LASTEXITCODE -ne 0) { throw 'docker compose configuration is invalid' }

$services = @('postgres','redis','scan_target','django','fastapi','celery_worker','celery_beat','frontend','nginx')
foreach ($service in $services) {
    $state = docker compose ps --status running --services | Select-String -SimpleMatch $service
    if (-not $state) { throw "Required service is not running: $service" }
}

$checks = @(
    @{ Name = 'Frontend/Nginx'; Url = 'http://localhost/' },
    @{ Name = 'Django health'; Url = 'http://localhost/health/' },
    @{ Name = 'Django readiness'; Url = 'http://localhost/ready/' },
    @{ Name = 'FastAPI health'; Url = 'http://localhost/health' },
    @{ Name = 'FastAPI readiness'; Url = 'http://localhost/ready' }
)

foreach ($check in $checks) {
    try {
        $response = Invoke-WebRequest -Uri $check.Url -UseBasicParsing -TimeoutSec 15
        if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
            throw "HTTP $($response.StatusCode)"
        }
        Write-Host ("PASS  {0}: HTTP {1}" -f $check.Name, $response.StatusCode) -ForegroundColor Green
    } catch {
        throw ("FAIL  {0}: {1}" -f $check.Name, $_.Exception.Message)
    }
}

$djangoCheck = docker compose exec -T django python manage.py check 2>&1
if ($LASTEXITCODE -ne 0) { throw "Django check failed: $djangoCheck" }
Write-Host 'PASS  Django system check' -ForegroundColor Green

$migrationCheck = docker compose exec -T django python manage.py makemigrations --check --dry-run 2>&1
if ($LASTEXITCODE -ne 0) { throw "Django migration consistency failed: $migrationCheck" }
Write-Host 'PASS  Django migration consistency' -ForegroundColor Green

$nmapVersion = docker compose exec -T celery_worker nmap --version 2>&1 | Select-String -Pattern 'Nmap version'
if (-not $nmapVersion) { throw 'Nmap is not available inside the real Celery worker runtime' }
Write-Host ("PASS  Real scanner runtime: {0}" -f $nmapVersion.Line) -ForegroundColor Green

Write-Host ''
Write-Host 'LOCAL_RUNTIME=PASS' -ForegroundColor Green
Write-Host 'Next: run the external HTTP black-box harness:'
Write-Host 'python .\e2e\external_black_box_e2e.py'
