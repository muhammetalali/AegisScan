#!/usr/bin/env python3
from __future__ import annotations
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi_app.services.wstg_completion_policy import build_wstg_completion_policy

def verify() -> dict:
    payload = build_wstg_completion_policy()
    if payload['total_tests'] != 97:
        raise ValueError('WSTG completion policy must cover exactly 97 tests')
    if payload['completion_claim_supported_tests'] != 97:
        raise ValueError('Not all WSTG tests have a governed completion-claim path')
    if payload['gap_native_small_tests'] != 5:
        raise ValueError('Historical native-gap identity count changed')
    if payload['gap_native_small_completion_supported'] != 5:
        raise ValueError('One or more reviewed native gaps lacks a completion-claim path')
    if payload['observation_alone_is_completion'] is not False:
        raise ValueError('Observation was incorrectly promoted to completion authority')
    if payload['completion_is_pass_or_fail'] is not False:
        raise ValueError('Methodology completion was incorrectly promoted to a verdict')
    return payload

if __name__ == '__main__':
    print(json.dumps(verify(), indent=2, sort_keys=True))
