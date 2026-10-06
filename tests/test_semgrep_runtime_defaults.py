from pathlib import Path


CODE_SERVICE = Path("aegis-platform/kali/runner/code_service.py")
SCANNER_ADAPTERS = Path("aegis-platform/backend/fastapi_app/services/scanner_adapters.py")
PROD_COMPOSE = Path("aegis-platform/docker-compose.prod.yml")
DEV_COMPOSE = Path("aegis-platform/docker-compose.yml")
CANARY_COMPOSE = Path("aegis-platform/docker-compose.semgrep-canary.yml")
DEFAULT_KALI_COMPOSE = Path("aegis-platform/docker-compose.semgrep-default-kali.yml")
TRUST_BOOTSTRAP = Path("aegis-platform/scripts/production_execution_trust_bootstrap.py")
CODE_PROVIDER_DOCKERFILE = Path("aegis-platform/kali/Dockerfile.code-provider")
PRODUCTION_BASELINE = Path("aegis-platform/kali/semgrep-rules/aegis-production-baseline-v1.yml")
CANARY_REALITY = Path("aegis-platform/e2e/semgrep_canary_reality.py")
CANARY_WORKFLOW = Path(".github/workflows/code-semgrep-canary-reality.yml")
ADVANCED_SCANS = Path("aegis-platform/backend/fastapi_app/tasks/advanced_scans.py")


def test_semgrep_runtime_defaults_use_explicit_registry_config():
    code_service = CODE_SERVICE.read_text(encoding="utf-8")
    scanner_adapters = SCANNER_ADAPTERS.read_text(encoding="utf-8")
    prod_compose = PROD_COMPOSE.read_text(encoding="utf-8")
    dev_compose = DEV_COMPOSE.read_text(encoding="utf-8")
    canary_compose = CANARY_COMPOSE.read_text(encoding="utf-8")
    default_kali_compose = DEFAULT_KALI_COMPOSE.read_text(encoding="utf-8")
    trust_bootstrap = TRUST_BOOTSTRAP.read_text(encoding="utf-8")
    code_provider_dockerfile = CODE_PROVIDER_DOCKERFILE.read_text(encoding="utf-8")
    production_baseline = PRODUCTION_BASELINE.read_text(encoding="utf-8")

    assert "os.environ.get('AEGIS_CODE_SEMGREP_CONFIG', 'p/default')" in code_service
    assert "os.getenv('SEMGREP_CONFIG', 'p/default')" in scanner_adapters
    assert "${SEMGREP_CONFIG:-auto}" not in prod_compose
    assert prod_compose.count("${SEMGREP_CONFIG:-p/default}") == 2
    assert "AEGIS_CODE_SEMGREP_CONFIG: ${AEGIS_CODE_SEMGREP_CONFIG:-/opt/aegis-semgrep-rules/aegis-production-baseline-v1.yml}" in prod_compose
    assert dev_compose.count("${SEMGREP_CONFIG:-p/default}") == 2
    assert "${SEMGREP_CONFIG:-p/default}" in canary_compose
    assert "${SEMGREP_CONFIG:-p/default}" in default_kali_compose
    assert '"SEMGREP_CONFIG": "p/default"' in trust_bootstrap
    assert '"AEGIS_CODE_SEMGREP_CONFIG": "/opt/aegis-semgrep-rules/aegis-production-baseline-v1.yml"' in trust_bootstrap
    assert "ENV AEGIS_CODE_SEMGREP_CONFIG=/opt/aegis-semgrep-rules/aegis-production-baseline-v1.yml" in code_provider_dockerfile
    assert "--config /opt/aegis-semgrep-rules/aegis-production-baseline-v1.yml" in code_provider_dockerfile
    assert "/opt/aegis-runner/code_service.py >/tmp/aegis-semgrep-baseline-build-proof.json" in code_provider_dockerfile
    assert production_baseline.count("  - id: aegis.") >= 6
    assert "p/default" not in production_baseline


def test_semgrep_partial_execution_persists_stderr():
    source = ADVANCED_SCANS.read_text(encoding="utf-8")
    semgrep = source.split(
        "def run_semgrep_scan(self,scan_id:str)->dict[str,Any]:", 1
    )[1]
    assert "execution.error_message=result.stderr if result.exit_code!=0 else ''" in semgrep
    assert "'evidences_collected','error_message','result_data','updated_at'" in semgrep


def test_semgrep_canary_normalizes_successful_finding_exit_codes():
    reality = CANARY_REALITY.read_text(encoding="utf-8")
    workflow = CANARY_WORKFLOW.read_text(encoding="utf-8")

    assert "assert legacy.exit_code in {0, 1}" in reality
    assert "assert candidate.exit_code == 0" in reality
    assert "legacy.exit_code == candidate.exit_code" not in reality
    assert '"candidate_success": 0' in reality
    assert '"legacy_accepted": [0, 1]' in reality
    assert "'candidate_finding_exit_code':0" in workflow
    assert "'legacy_finding_exit_codes':[0,1]" in workflow
