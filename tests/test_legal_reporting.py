import hashlib
import json

from typer.testing import CliRunner

from secure_osint.core.reporter import (
    INTEGRITY_MARKER,
    LEGAL_DISCLAIMER,
    ReportGenerator,
    canonical_json,
)

RESULTS = {'step1': {'status': 'SUCCESS', 'data': {'k': 'v'}}}


def _json(tmp_path, **kw):
    out = tmp_path / 'r.json'
    ReportGenerator(**kw).generate_json(RESULTS, 'example.com', 'domain', str(out))
    return json.loads(out.read_text(encoding='utf-8'))


def _md(tmp_path, **kw):
    out = tmp_path / 'r.md'
    ReportGenerator(**kw).generate_markdown(RESULTS, 'example.com', 'domain', str(out))
    return out.read_text(encoding='utf-8')


# --- case id ---


def test_case_id_absent_by_default(tmp_path):
    assert 'case_id' not in _json(tmp_path)
    assert 'Case ID' not in _md(tmp_path)


def test_case_id_stamped_on_json_and_markdown(tmp_path):
    report = _json(tmp_path, case_id='ACME-2026-014')
    assert report['case_id'] == 'ACME-2026-014'
    assert '**Case ID:** ACME-2026-014' in _md(tmp_path, case_id='ACME-2026-014')


# --- json integrity ---


def test_json_has_verifiable_sha256(tmp_path):
    report = _json(tmp_path, case_id='C1')
    integrity = report.pop('integrity')
    assert integrity['algorithm'] == 'sha256'
    recomputed = hashlib.sha256(canonical_json(report).encode()).hexdigest()
    assert integrity['value'] == recomputed


def test_json_integrity_detects_tampering(tmp_path):
    report = _json(tmp_path)
    stored = report.pop('integrity')['value']
    report['results']['step1']['data']['k'] = 'TAMPERED'
    assert hashlib.sha256(canonical_json(report).encode()).hexdigest() != stored


def test_case_id_changes_the_hash(tmp_path):
    a = _json(tmp_path, case_id='A')['integrity']['value']
    b = _json(tmp_path, case_id='B')['integrity']['value']
    assert a != b


# --- markdown integrity + disclaimer ---


def test_markdown_disclaimer_is_exact(tmp_path):
    assert LEGAL_DISCLAIMER in _md(tmp_path)
    assert 'GDPR' in LEGAL_DISCLAIMER and 'sole responsibility of the end user' in LEGAL_DISCLAIMER


def test_markdown_sha256_covers_body_above_marker(tmp_path):
    text = _md(tmp_path, case_id='C1')
    assert INTEGRITY_MARKER in text
    body, footer = text.split(INTEGRITY_MARKER, 1)
    digest = hashlib.sha256(body.encode()).hexdigest()
    assert digest in footer


def test_json_disclaimer_is_legal_text(tmp_path):
    assert _json(tmp_path)['disclaimer'] == LEGAL_DISCLAIMER


# --- redaction still applies ---


def test_pii_still_redacted_with_case_id(tmp_path):
    out = tmp_path / 'r.json'
    ReportGenerator(case_id='C1').generate_json(
        {'s': {'status': 'SUCCESS', 'data': 'mail me at a@b.co'}}, 'a@b.co', 'wf', str(out)
    )
    text = out.read_text(encoding='utf-8')
    assert 'a@b.co' not in text and '[REDACTED]' in text


# --- CLI ---


def _cli_run(tmp_path, monkeypatch, extra):
    from unittest.mock import Mock

    from secure_osint.cli import app

    src = Mock()
    src.fetch.return_value = {'ok': 1}
    monkeypatch.setattr('secure_osint.sources.tool_catalog.tool_catalog', {'dns': src})
    wf_dir = tmp_path / 'wf'
    wf_dir.mkdir()
    (wf_dir / 'generic.yaml').write_text(
        'name: g\ndescription: d\ninput_type: generic\nrisk: low\nsteps:\n  - id: only\n    type: dns\n'
    )
    out = tmp_path / 'out'
    result = CliRunner().invoke(
        app,
        [
            'run',
            'example.com',
            '--workflow',
            'generic',
            '--workflow-dir',
            str(wf_dir),
            '--output-dir',
            str(out),
            '-q',
            *extra,
        ],
    )
    return result, out


def test_cli_case_id_stamps_reports(tmp_path, monkeypatch):
    result, out = _cli_run(tmp_path, monkeypatch, ['--case-id', 'PI-99'])
    assert result.exit_code == 0, result.output
    assert json.loads((out / 'latest.json').read_text(encoding='utf-8'))['case_id'] == 'PI-99'
    assert 'PI-99' in (out / 'latest.md').read_text(encoding='utf-8')


def test_cli_without_case_id(tmp_path, monkeypatch):
    result, out = _cli_run(tmp_path, monkeypatch, [])
    assert result.exit_code == 0, result.output
    assert 'case_id' not in json.loads((out / 'latest.json').read_text(encoding='utf-8'))
