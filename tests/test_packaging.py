"""Regressione: i workflow devono viaggiare dentro il pacchetto, non dipendere dalla directory corrente.

Prima di questa correzione il wheel non conteneva nessun YAML e `secure-osint run` falliva da qualunque
directory diversa dalla root del repository (installazioni pipx e binari PyInstaller inutilizzabili).
"""

import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

import secure_osint
from secure_osint.cli import DEFAULT_WORKFLOW_DIR, app, default_workflow_dir
from secure_osint.core.workflow import load_workflow_from_file

EXPECTED = {'domain', 'email', 'generic', 'github', 'image', 'ip', 'phone', 'username', 'wallet'}
PACKAGED = Path(secure_osint.__file__).resolve().parent / 'workflows'

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - 3.10
    tomllib = None


def test_workflows_live_inside_the_package():
    # Subset, not equality: new workflows (image, wallet...) may be added; none of these may go missing.
    assert EXPECTED <= {p.stem for p in PACKAGED.glob('*.yaml')}


@pytest.mark.parametrize('path', sorted(PACKAGED.glob('*.yaml')), ids=lambda p: p.stem)
def test_every_packaged_workflow_is_valid(path):
    assert load_workflow_from_file(str(path)).steps


def test_default_workflow_dir_is_the_packaged_one(monkeypatch):
    monkeypatch.delenv('SECURE_OSINT_WORKFLOW_DIR', raising=False)
    resolved = Path(default_workflow_dir())
    assert resolved.is_absolute()
    assert resolved == PACKAGED
    assert Path(DEFAULT_WORKFLOW_DIR) == PACKAGED  # the module-level default used by CLI and GUI


def test_env_var_still_overrides_the_default(monkeypatch, tmp_path):
    monkeypatch.setenv('SECURE_OSINT_WORKFLOW_DIR', str(tmp_path))
    assert default_workflow_dir() == str(tmp_path)


def test_cli_works_from_any_directory(monkeypatch, tmp_path):
    # The original bug: from outside the repo root every run failed with "Workflow ... not found".
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ['dry-run', 'example.com'])
    assert result.exit_code == 0, result.output
    assert 'Workflow: domain_recon' in result.output


def test_cli_validate_accepts_packaged_path(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ['validate', str(PACKAGED / 'phone.yaml')])
    assert result.exit_code == 0, result.output


def test_gui_runner_works_from_any_directory(monkeypatch, tmp_path):
    from secure_osint import app as gui_app

    class FakeEngine:
        def __init__(self, **kwargs):
            pass

        def execute(self, wf, input_str):
            return {'s': {'status': 'SUCCESS', 'data': {'wf': wf.name}}}

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('secure_osint.core.engine.WorkflowEngine', FakeEngine)
    monkeypatch.setattr(gui_app, '_open_cache', lambda ttl: None)
    markdown, files, _ = gui_app.run_investigation('example.com', agreed=True, output_dir=str(tmp_path / 'out'))
    assert files is not None, markdown
    assert 'domain_recon' in markdown


def test_python_dash_m_entry_point_works_from_any_directory(tmp_path):
    # __main__.py is also the PyInstaller entry point: it must import cli as a package module.
    import os
    import subprocess

    # The child writes UTF-8 and the parent decodes UTF-8: with the locale default (cp1252 on Windows)
    # any non-ASCII character in the CLI output would raise UnicodeDecodeError in the reader thread.
    env = {**os.environ, 'PYTHONIOENCODING': 'utf-8'}
    result = subprocess.run(
        [sys.executable, '-m', 'secure_osint', 'dry-run', 'example.com'],
        cwd=tmp_path,
        capture_output=True,
        encoding='utf-8',
        errors='replace',
        env=env,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert 'Workflow: domain_recon' in result.stdout


def test_workflow_name_traversal_still_blocked(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ['dry-run', 'example.com', '--workflow', '../../etc/passwd'])
    assert result.exit_code == 1
    assert 'Invalid workflow name' in result.output


@pytest.mark.skipif(tomllib is None, reason='tomllib needs Python 3.11+')
def test_pyproject_declares_workflows_as_package_data():
    assert tomllib is not None  # narrows the Optional module for mypy (configured for 3.10)
    root = Path(__file__).resolve().parents[1]
    config = tomllib.loads((root / 'pyproject.toml').read_text(encoding='utf-8'))
    assert 'workflows/*.yaml' in config['tool']['setuptools']['package-data']['secure_osint']
