"""Remote text in Markdown reports must stay inert: no images, links or HTML (tracking beacons)."""

import re

from secure_osint.core.dorks import format_dork_lines
from secure_osint.core.reporter import ReportGenerator
from secure_osint.core.timeline import format_timeline_lines
from secure_osint.core.workflow import StepResult, StepStatus
from secure_osint.utils.markdown import md_code, md_text

BEACON = '![p](https://evil.example/beacon.png)'
HTML = '<img src=https://evil.example/b.png>'
# Live Markdown image/link syntax (unescaped '![' or '](') or a raw HTML tag.
LIVE = re.compile(r'(?<!\\)!(?<!\\)\[|(?<!\\)\]\(https://evil|<img')


def test_md_text_neutralises_images_links_and_html():
    for payload in (BEACON, HTML, '[x](https://evil.example/)', 'https://x/)![](https://evil.example/b.png'):
        assert not LIVE.search(md_text(payload)), md_text(payload)


def test_md_text_keeps_plain_text_readable():
    assert md_text('Alice Example (from GitHub)') == 'Alice Example (from GitHub)'


def test_md_code_cannot_close_its_span_or_a_table_cell():
    assert md_code('a`b|c') == r'`ab\|c`'


def test_markdown_report_does_not_render_a_remote_display_name_as_an_image(tmp_path):
    data = {
        'email': 'x@example.com',
        'gravatar': {'display_name': BEACON, 'profile_url': 'https://gravatar.com/x', 'verified_accounts': []},
    }
    results = {'email_check': StepResult(step_id='email_check', status=StepStatus.SUCCESS, data=data)}
    out = tmp_path / 'r.md'
    ReportGenerator().generate_markdown(results, 'x@example.com', 'email', str(out))
    text = out.read_text(encoding='utf-8')
    # Raw data sits in ```json fences, which are never rendered (json.dumps keeps it on one line, so it
    # cannot close the fence); everything outside them is rendered Markdown.
    rendered = re.sub(r'```json\n.*?\n```', '', text, flags=re.DOTALL)
    assert 'evil.example' in rendered  # the pivot is reported...
    assert not LIVE.search(rendered)  # ...but as text, never as a live image


def test_dork_and_timeline_cells_are_inert():
    dorks = [
        {
            'entity': BEACON,
            'engine': 'duckduckgo',
            'query': 'q`|x',
            'url': 'https://duckduckgo.com/?q=q',
            'purpose': HTML,
        }
    ]
    timeline = {'timeline': [{'date': '2020-01-01', 'platform': BEACON, 'event': HTML, 'source': 'github'}]}
    lines = format_dork_lines(dorks) + format_timeline_lines(timeline)
    assert any('evil.example' in line for line in lines)
    for line in lines:
        if 'evil.example' in line:
            assert not LIVE.search(line), line
