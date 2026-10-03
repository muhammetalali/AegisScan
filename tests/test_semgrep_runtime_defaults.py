from pathlib import Path


CODE_SERVICE = Path("aegis-platform/kali/runner/code_service.py")
SCANNER_ADAPTERS = Path("aegis-platform/backend/fastapi_app/services/scanner_adapters.py")
PROD_COMPOSE = Path("aegis-platform/docker-compose.prod.yml")
DEV_COMPOSE = Path("aegis-platform/docker-compose.yml")
CANARY_COMPOSE = Path("aegis-platform/docker-compose.semgrep-canary.yml")
DEFAULT_KALI_COMPOSE = Path("aegis-platform/docker-compose.semgrep-default-kali.yml")
TRUST_BOOTSTRAP = Path("aegis-platform/scripts/production_execution_trust_bootstrap.py")
ADVANCED_SCANS = Path("aegis-platform/backend/fastapi_app/tasks/advanced_scans.py")


def test_semgrep_runtime_defaults_use_explicit_registry_config():
    code_service = CODE_SERVICE.read_text(encoding="utf-8")
    scanner_adapters = SCANNER_ADAPTERS.read_text(encoding="utf-8")
    prod_compose = PROD_COMPOSE.read_text(encoding="utf-8")
    dev_compose = DEV_COMPOSE.read_text(encoding="utf-8")
    canary_compose = CANARY_COMPOSE.read_text(encoding="utf-8")
    default_kali_compose = DEFAULT_KALI_COMPOSE.read_text(encoding="utf-8")
    trust_bootstrap = TRUST_BOOTSTRAP.read_text(encoding="utf-8")

    assert "os.environ.get('AEGIS_CODE_SEMGREP_CONFIG', 'p/default')" in code_service
    assert "os.getenv('SEMGREP_CONFIG', 'p/default')" in scanner_adapters
    assert "${SEMGREP_CONFIG:-auto}" not in prod_compose
    assert prod_compose.count("${SEMGREP_CONFIG:-p/default}") == 3
    assert dev_compose.count("${SEMGREP_CONFIG:-p/default}") == 2
    assert "${SEMGREP_CONFIG:-p/default}" in canary_compose
    assert "${SEMGREP_CONFIG:-p/default}" in default_kali_compose
    assert '"SEMGREP_CONFIG": "p/default"' in trust_bootstrap


def test_semgrep_partial_execution_persists_stderr():
    source = ADVANCED_SCANS.read_text(encoding="utf-8")
    semgrep = source.split(
        "def run_semgrep_scan(self,scan_id:str)->dict[str,Any]:", 1
    )[1]
    assert "execution.error_message=result.stderr if result.exit_code!=0 else ''" in semgrep
    assert "'evidences_collected','error_message','result_data','updated_at'" in semgrep
