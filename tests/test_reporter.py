import tempfile
import os
from secure_osint.core.reporter import ReportGenerator


def test_generate_json_structure():
    reporter = ReportGenerator()
    with tempfile.NamedTemporaryFile(mode='w+t', suffix='.json', delete=False) as f:
        temp_path = f.name
    try:
        results = {'step1': {'status': 'SUCCESS', 'data': 'test'}}
        reporter.generate_json(results, 'test_input', 'test_workflow', temp_path)
        assert os.path.exists(temp_path)
        with open(temp_path, 'r', encoding='utf-8') as f:
            import json

            data = json.load(f)
        assert 'timestamp' in data
        assert 'input' in data
        assert 'results' in data
    finally:
        os.unlink(temp_path)


def test_generate_markdown_contains_headers():
    reporter = ReportGenerator()
    with tempfile.NamedTemporaryFile(mode='w+t', suffix='.md', delete=False) as f:
        temp_path = f.name
    try:
        results = {'step1': {'status': 'SUCCESS', 'data': 'test'}}
        reporter.generate_markdown(results, 'test_input', 'test_workflow', temp_path)
        assert os.path.exists(temp_path)
        with open(temp_path, 'r', encoding='utf-8') as f:
            content = f.read()
        assert '# OSINT Report' in content
        assert '## Results' in content
    finally:
        os.unlink(temp_path)


def test_report_applies_redaction():
    reporter = ReportGenerator()
    with tempfile.NamedTemporaryFile(mode='w+t', suffix='.json', delete=False) as f:
        temp_path = f.name
    try:
        results = {'step1': {'status': 'SUCCESS', 'data': 'email: test@example.com'}}
        reporter.generate_json(results, 'test@example.com', 'test', temp_path)
        with open(temp_path, 'r', encoding='utf-8') as f:
            content = f.read()
        assert 'test@example.com' not in content
        assert '[REDACTED]' in content
    finally:
        os.unlink(temp_path)


def test_markdown_uses_real_code_fence(tmp_path):
    out = tmp_path / 'r.md'
    ReportGenerator().generate_markdown({'s': {'status': 'SUCCESS', 'data': {'k': 'v'}}}, 'in', 'wf', str(out))
    content = out.read_text(encoding='utf-8')
    assert '```json\n' in content
    assert '\n```\n' in content


def test_reports_are_owner_only(tmp_path):
    from tests.owner_only import assert_owner_only

    out = tmp_path / 'r.json'
    ReportGenerator().generate_json({}, 'in', 'wf', str(out))
    assert_owner_only(out)
    md = tmp_path / 'r.md'
    ReportGenerator().generate_markdown({}, 'in', 'wf', str(md))
    assert_owner_only(md)


def test_overwritten_permissive_report_becomes_owner_only(tmp_path):
    from tests.owner_only import assert_owner_only, make_permissive

    out = tmp_path / 'r.json'
    out.write_text('stale', encoding='utf-8')
    make_permissive(out)
    ReportGenerator().generate_json({}, 'in', 'wf', str(out))
    assert_owner_only(out)
    assert 'stale' not in out.read_text(encoding='utf-8')


def test_report_directories_created_for_output_are_owner_only(tmp_path):
    from tests.owner_only import assert_owner_only

    out = tmp_path / 'reports' / 'run-1' / 'latest.json'
    ReportGenerator().generate_json({}, 'in', 'wf', str(out))
    assert_owner_only(tmp_path / 'reports')
    assert_owner_only(out.parent)
    assert_owner_only(out)


def test_report_on_filesystem_without_acls_is_written_with_a_warning(tmp_path, monkeypatch, caplog):
    import logging

    from secure_osint.utils import secure_fs

    # e.g. a FAT32/exFAT evidence drive: the deliverable is still produced, but the user is told.
    monkeypatch.setattr(secure_fs, '_apply_owner_only', lambda path, is_dir: None)
    monkeypatch.setattr(secure_fs, 'is_owner_only', lambda path: False)
    out = tmp_path / 'r.json'
    with caplog.at_level(logging.WARNING):
        ReportGenerator().generate_json({}, 'in', 'wf', str(out))
    assert out.is_file()
    assert 'owner-only' in caplog.text
