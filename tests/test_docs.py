import re
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urlparse

import pytest

from secure_osint.cli import DEFAULT_WORKFLOW_DIR
from secure_osint.core.reporter import LEGAL_DISCLAIMER
from secure_osint.core.workflow import load_workflow_from_file
from secure_osint.sources.username_source import PLATFORM_LABELS, PLATFORMS

README = Path(__file__).resolve().parent.parent / 'README.md'

AUTOMATED = [key for key, p in PLATFORMS.items() if p.kind != 'auth_required']
MANUAL_ONLY = [key for key, p in PLATFORMS.items() if p.kind == 'auth_required']


def _section(text: str, heading: str) -> str:
    """The body of a Markdown section, up to the next heading of the same or a higher level."""
    level = len(heading) - len(heading.lstrip('#'))
    start = text.index(heading + '\n') + len(heading) + 1
    following = re.search(rf'^#{{1,{level}}} ', text[start:], re.M)
    return text[start : start + following.start()] if following else text[start:]


def _table(section: str) -> List[List[str]]:
    """Body rows of the first Markdown table in ``section``, cells stripped of spaces and backticks."""
    lines = [line for line in section.splitlines() if line.startswith('|')]
    return [[cell.strip().strip('`') for cell in line.strip('|').split('|')] for line in lines[2:]]


def _expected_platform_row(key: str) -> Tuple[str, ...]:
    platform = PLATFORMS[key]
    if platform.check_url is None:
        return (PLATFORM_LABELS[key], key, 'no, login required', platform.confidence, 'not queried')
    host = (urlparse(platform.check_url).hostname or '').replace('{u}', '*')
    return (PLATFORM_LABELS[key], key, 'yes', platform.confidence, host)


@pytest.fixture(scope='module')
def readme() -> str:
    return README.read_text(encoding='utf-8')


@pytest.mark.parametrize(
    'heading',
    [
        '## Professional use cases',
        '## Legal & ethical guidelines',
        '## Capabilities',
        '## Sources',
    ],
)
def test_required_sections_present(readme, heading):
    assert heading in readme


@pytest.mark.parametrize(
    'phrase',
    [
        'Public data only',  # boundary: only public data
        'leak databases',  # boundary: no illegal/leak DBs
        'ToS-violating probing',  # boundary: no intrusive probing
        'GDPR',  # user responsibility / lawful basis
        '--keep-network',  # phone/IP shown only behind the flag
        '--case-id',  # chain-of-custody
    ],
)
def test_ethical_and_feature_notes_documented(readme, phrase):
    assert phrase in readme


@pytest.mark.parametrize('source', ['phone', 'username', 'dns', 'rdap'])
def test_feature_list_mentions_sources(readme, source):
    assert f'`{source}`' in readme


def test_merge_commit_house_rule_retained(readme):
    # The autopilot workflow must not drop the stacked-PR / merge-commit house rule.
    assert 'house rule' in readme.lower()
    assert 'Merge commits only' in readme or 'merge commit' in readme.lower()


def test_disclaimer_constant_referenced_in_docs(readme):
    # The report disclaimer's core promise is echoed in the guidelines.
    assert 'sole responsibility of the end user' in LEGAL_DISCLAIMER
    assert 'responsibility of the end user' in readme


# --- drift guards: the README must describe what the code actually does ---


def test_readme_platform_table_matches_username_source(readme):
    rows = _table(_section(readme, '### Username platforms'))
    documented: Dict[str, Tuple[str, ...]] = {row[1]: tuple(row) for row in rows}
    assert set(documented) == set(PLATFORMS), 'README platform table and username_source.PLATFORMS differ'
    for key in PLATFORMS:
        assert documented[key] == _expected_platform_row(key)


def test_readme_platform_counts_match_username_source(readme):
    match = re.search(
        r'\*\*(\d+) platforms\*\*: (\d+) checked automatically, (\d+) flagged for manual verification', readme
    )
    assert match, 'README must state the username platform counts'
    assert tuple(int(n) for n in match.groups()) == (len(PLATFORMS), len(AUTOMATED), len(MANUAL_ONLY))
    # No stale count anywhere else ("18 platforms", "across 23 platforms"...).
    allowed = {len(PLATFORMS), len(AUTOMATED), len(MANUAL_ONLY)}
    for number in re.findall(r'(\d+) (?:username )?platforms\b', readme):
        assert int(number) in allowed, f'stale platform count in README: {number}'


def test_sources_table_username_row_names_every_platform(readme):
    row = next(r for r in _table(_section(readme, '## Sources')) if r[0] == 'username')
    for key in PLATFORMS:
        assert PLATFORM_LABELS[key] in row[1], f'{PLATFORM_LABELS[key]} missing from the Sources table'


@pytest.mark.parametrize('confidence', ['HIGH', 'MEDIUM'])
def test_confidence_table_examples_match_the_code(readme, confidence):
    row = next(r for r in _table(_section(readme, '### Username confidence and soft 404s')) if r[0] == confidence)
    documented = {name.strip() for name in row[2].split(',')}
    expected = {PLATFORM_LABELS[key] for key, p in PLATFORMS.items() if p.confidence == confidence}
    assert documented == expected


def test_every_shipped_workflow_is_documented(readme):
    for path in sorted(Path(DEFAULT_WORKFLOW_DIR).glob('*.yaml')):
        name = load_workflow_from_file(str(path)).name
        assert f'`{name}`' in readme, f'workflow {name} ({path.name}) is not documented in the README'


def test_generic_workflow_documented_as_free_text_github_search(readme):
    workflows = _section(readme, '### Built-in workflows')
    assert '`generic`' in workflows and 'GitHub user search' in workflows


def test_security_policy_uses_private_vulnerability_reporting():
    policy = (README.parent / 'SECURITY.md').read_text(encoding='utf-8')
    # A real private channel, not a placeholder mailbox nobody reads.
    assert '/security/advisories/new' in policy
    assert '.local' not in policy and 'placeholder' not in policy.lower()
    for heading in ('## Supported versions', '## Reporting a vulnerability', '## Scope'):
        assert heading in policy
