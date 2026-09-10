from pathlib import Path


def test_orchestration_gate_executes_policy_inventory_and_yaml_tests():
    text = (Path(__file__).parents[1] / '.github' / 'workflows' / 'ci-orchestration-reality.yml').read_text(encoding='utf-8')
    assert 'test_ci_workflow_yaml.py' in text
    assert 'test_ci_concurrency_policy.py' in text
    assert 'test_ci_concurrency_inventory.py' in text
