import signal
import subprocess
from unittest.mock import patch

import pytest

from fastapi_app.services.scanner_adapters import ScannerExecutionCancelled, _run_controlled


class FakeProcess:
    def __init__(self):
        self.pid=1234
        self.returncode=None
        self.calls=0

    def poll(self):
        return self.returncode

    def communicate(self, timeout=None):
        self.calls += 1
        if self.calls < 3:
            raise subprocess.TimeoutExpired(['tool'], timeout)
        self.returncode=0
        return ('ok','')

    def wait(self, timeout=None):
        self.returncode=-15
        return self.returncode


def test_controlled_scanner_pause_resume_signals_process_group():
    proc=FakeProcess()
    states=iter(['paused','running','running','running'])
    with patch('fastapi_app.services.scanner_adapters.subprocess.Popen',return_value=proc), patch('fastapi_app.services.scanner_adapters.os.killpg') as killpg:
        result=_run_controlled(['tool'],tool='tool',target='127.0.0.1',timeout=10,state_getter=lambda:next(states),poll_interval=0.01)
    assert result.stdout=='ok'
    killpg.assert_any_call(1234,signal.SIGSTOP)
    killpg.assert_any_call(1234,signal.SIGCONT)


def test_controlled_scanner_cancel_terminates_process_group():
    proc=FakeProcess()
    with patch('fastapi_app.services.scanner_adapters.subprocess.Popen',return_value=proc), patch('fastapi_app.services.scanner_adapters.os.killpg') as killpg:
        with pytest.raises(ScannerExecutionCancelled):
            _run_controlled(['tool'],tool='tool',target='127.0.0.1',timeout=10,state_getter=lambda:'cancelled',poll_interval=0.01)
    assert killpg.called
