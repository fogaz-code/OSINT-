"""GUI restyling: presentation helpers (they run in CI without gradio) and the stylesheet."""

import json
import re
from pathlib import Path

import pytest

from secure_osint import app as gui_app
from secure_osint.app import (
    _display_report,
    _footer_html,
    _header_html,
    _load_css,
    _pivot_targets,
    _pivots_markdown,
    _report_json,
    _report_pivots,
)

PIVOTS = [
    'Name: Jroe Dev (from GitHub, Keybase)',
    'Username: jroe_work',
    'Username: alice-work',  # hyphen: not a valid username for the username source
    'Username: jroe_work',  # duplicate
    'Email: [REDACTED] (DNS SOA contact)',
]


def test_only_valid_usernames_can_prefill_a_new_investigation():
    assert _pivot_targets(PIVOTS) == ['jroe_work']


def test_names_and_redacted_emails_are_never_runnable():
    assert _pivot_targets(['Name: Jane Doe (from GitHub)', 'Email: [REDACTED]', 'Username: [REDACTED]']) == []


def test_pivot_list_shows_every_suggestion():
    text = _pivots_markdown(PIVOTS)
    assert text.count('\n') == len(PIVOTS) - 1 and '`Name: Jroe Dev (from GitHub, Keybase)`' in text
    assert _pivots_markdown([]) == '_No pivots suggested for this investigation._'


def test_report_json_reads_the_written_report(tmp_path):
    path = tmp_path / 'latest.json'
    path.write_text(json.dumps({'correlations': {'suggested_pivots': ['Username: bob']}}), encoding='utf-8')
    data = _report_json([str(path), 'latest.md'])
    assert _report_pivots(data) == ['Username: bob']


@pytest.mark.parametrize('files', [None, [], ['/nonexistent/latest.json']])
def test_report_json_missing_is_none(files):
    assert _report_json(files) is None and _report_pivots(None) == []


def test_report_json_rejects_non_object(tmp_path):
    path = tmp_path / 'latest.json'
    path.write_text('[1, 2]', encoding='utf-8')
    assert _report_json([str(path)]) is None


def test_header_and_footer_escape_the_version():
    assert '&lt;script&gt;' in _header_html('<script>') and '<script>' not in _header_html('<script>')
    assert 'ACCEPTABLE_USE_POLICY.md' in _footer_html('1.0.0') and 'v1.0.0' in _footer_html('1.0.0')


def test_stylesheet_is_packaged_and_styles_the_key_elements():
    css = _load_css()
    for selector in ('#so-run', '#so-gate', '#so-aup', '.so-filter', '#so-tabs', '#so-report', '@media'):
        assert selector in css, selector
    root = Path(__file__).resolve().parents[1]
    assert 'assets/*.css' in (root / 'pyproject.toml').read_text(encoding='utf-8')  # ships in the wheel


def test_stylesheet_loads_nothing_from_the_network():
    css = _load_css()
    assert not re.search(r'@import|url\(\s*["\']?https?:', css, re.IGNORECASE)  # no web fonts, no remote images


def test_missing_stylesheet_does_not_break_the_ui(monkeypatch, tmp_path):
    monkeypatch.setattr(gui_app, '_ASSETS', tmp_path)
    assert _load_css() == ''


REPORT = (
    '# OSINT Report: domain\n\n**Generated:** 2026-09-26\n**Input:** example.com\n\n'
    '### Step: dns\n**Status:** SUCCESS\n**Data:**\n```json\n{"A": ["[REDACTED]"]}\n```\n\n'
    '### Step: s\n**Status:** SUCCESS\n**Data:**\n````json\n{"k": "```"}\n````\n'
)


def test_display_report_collapses_each_step_json():
    shown = _display_report(REPORT)
    assert shown.count('<details>') == 2 and shown.count('</details>') == 2
    assert '**Data:**' not in shown
    assert '```json\n{"A": ["[REDACTED]"]}\n```' in shown  # content kept, just folded
    assert '````json\n{"k": "```"}\n````' in shown  # longer fences (backticks in the data) survive intact


def test_display_report_puts_header_fields_on_their_own_lines():
    shown = _display_report(REPORT)
    assert '**Generated:** 2026-09-26  \n' in shown and '**Status:** SUCCESS  \n' in shown


def test_display_report_leaves_other_text_alone():
    plain = '# OSINT Report\n\nNo steps.\n'
    assert _display_report(plain) == plain
