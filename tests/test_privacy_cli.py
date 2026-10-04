"""C3 CLI flags: --keep-location and --keep-crypto reveal their category in reports, never in logs."""

import json
import logging

import pytest
from typer.testing import CliRunner

from secure_osint.cli import app
from secure_osint.core import privacy
from secure_osint.core.workflow import StepResult, StepStatus

TRON = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'
IP = '93.184.216.34'
DATA = {'note': f'wallet {TRON} from {IP}', 'gps': {'latitude': 45.4642, 'longitude': 9.19}}


@pytest.fixture(autouse=True)
def restore_logging():
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    yield
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)
    privacy.clear_sensitive_values()


def _run(monkeypatch, tmp_path, *flags):
    def fake_execute(self, wf, target):
        logging.getLogger('secure_osint.sources.fake').warning('found %s at %s', TRON, DATA['gps'])
        return {'lookup': StepResult(status=StepStatus.SUCCESS, data=DATA)}

    monkeypatch.setattr('secure_osint.core.engine.WorkflowEngine.execute', fake_execute)
    result = CliRunner().invoke(
        app, ['run', 'someone', '--workflow', 'generic', '--no-cache', '-q', '--output-dir', str(tmp_path), *flags]
    )
    assert result.exit_code == 0, result.output
    report = json.loads((tmp_path / 'latest.json').read_text(encoding='utf-8'))
    return json.dumps(report), result.stderr


def test_default_run_redacts_location_and_crypto(monkeypatch, tmp_path):
    report, _ = _run(monkeypatch, tmp_path)
    assert TRON not in report and '45.4642' not in report and IP not in report


def test_keep_crypto_reveals_wallets_only(monkeypatch, tmp_path):
    report, stderr = _run(monkeypatch, tmp_path, '--keep-crypto')
    assert TRON in report
    assert '45.4642' not in report and IP not in report
    assert TRON not in stderr  # logs are always fully redacted


def test_keep_location_reveals_coordinates_only(monkeypatch, tmp_path):
    report, stderr = _run(monkeypatch, tmp_path, '--keep-location')
    assert '45.4642' in report
    assert TRON not in report and IP not in report
    assert '45.4642' not in stderr


def test_keep_flags_combine(monkeypatch, tmp_path):
    report, _ = _run(monkeypatch, tmp_path, '--keep-location', '--keep-crypto', '--keep-network')
    assert TRON in report and '45.4642' in report and IP in report
