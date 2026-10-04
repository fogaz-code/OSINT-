"""C8 manual search queries (dorks): generated from the redacted correlations, never executed."""

import json
import socket
from urllib.parse import parse_qs, urlparse

import pytest

from secure_osint.core import dorks
from secure_osint.core.dorks import build_dorks, format_dork_lines
from secure_osint.core.reporter import ReportGenerator

ENGINE_HOSTS = {'google': 'www.google.com', 'bing': 'www.bing.com', 'duckduckgo': 'duckduckgo.com'}


def _account(platform, label, url, status='found', name=None):
    account = {'platform': platform, 'label': label, 'username': 'jroe', 'status': status, 'url': url}
    if name:
        account['profile'] = {'display_name': name}
    return account


CORR = {
    'primary_target': 'jroe',
    'usernames': ['jroe'],
    'emails': ['[REDACTED]'],
    'domains': ['example.com'],
    'infrastructure': ['[REDACTED]', 'mail.example.com'],
    'phones': [],
    'accounts': [
        _account('github', 'GitHub', 'https://github.com/jroe', name='Alice Example'),
        _account('keybase', 'Keybase', 'https://keybase.io/jroe', name='Alice Example'),
        _account('reddit', 'Reddit', 'https://www.reddit.com/user/jroe', status='not_found'),
        _account('instagram', 'Instagram', 'https://www.instagram.com/jroe/', status='manual'),
    ],
}


def _queries(corr=CORR, engine='google'):
    return [d['query'] for d in build_dorks(corr) if d['engine'] == engine]


def test_every_dork_has_the_contract_shape_and_a_properly_encoded_url():
    result = build_dorks(CORR)
    assert result
    for dork in result:
        assert set(dork) == {'entity', 'engine', 'query', 'url', 'purpose'}
        parsed = urlparse(dork['url'])
        assert parsed.scheme == 'https' and parsed.hostname == ENGINE_HOSTS[dork['engine']]
        assert parse_qs(parsed.query)['q'] == [dork['query']]  # round-trips: nothing lost or injected
        assert ' ' not in dork['url'] and '"' not in dork['url']
        assert dork['purpose']


def test_each_query_is_offered_on_all_three_engines():
    by_engine = {engine: _queries(engine=engine) for engine in ENGINE_HOSTS}
    assert by_engine['google'] == by_engine['bing'] == by_engine['duckduckgo']


def test_username_dorks_scope_to_found_platforms_only():
    queries = _queries()
    assert '"jroe"' in queries
    assert '"jroe" site:github.com' in queries and '"jroe" site:keybase.io' in queries
    assert '"jroe" -site:github.com -site:keybase.io' in queries
    assert not any('reddit' in q or 'instagram' in q for q in queries)  # not found / manual: no scoping


def test_domain_dorks():
    queries = _queries()
    assert 'site:example.com' in queries
    assert 'site:example.com -site:www.example.com' in queries
    assert '"example.com" -site:example.com' in queries
    assert not any('mail.example.com' in q for q in queries)  # infrastructure hosts are not dorked


def test_display_names_from_found_profiles():
    queries = _queries()
    assert '"Alice Example"' in queries and '"Alice Example" "jroe"' in queries
    assert queries.count('"Alice Example"') == 1  # de-duplicated across platforms


def test_redacted_selectors_never_reach_a_query():
    text = json.dumps(build_dorks(CORR))
    assert 'REDACTED' not in text
    assert build_dorks({'primary_target': '[REDACTED]', 'emails': ['[REDACTED]'], 'phones': ['[REDACTED]']}) == []


def test_visible_email_dorks():
    corr = {'primary_target': 'jane@example.org', 'emails': ['jane@example.org'], 'domains': ['example.org']}
    queries = _queries(corr)
    assert '"jane@example.org"' in queries
    assert '"jane@example.org" -site:example.org' in queries


def test_phone_dork_searches_every_known_format_at_once():
    corr = {'primary_target': '+390612345678', 'phones': ['+39 06 1234 5678', '+390612345678', '06 1234 5678']}
    assert _queries(corr) == ['"+39 06 1234 5678" OR "+390612345678" OR "06 1234 5678"']


def test_quotes_and_backticks_in_values_cannot_break_the_query():
    corr = {
        'primary_target': 'x',
        'accounts': [_account('github', 'GitHub', 'https://github.com/x', name='Bob "the" `B`')],
    }
    assert '"Bob the B"' in _queries(corr)


def test_special_characters_are_percent_encoded():
    corr = {
        'primary_target': 'x',
        'accounts': [_account('github', 'GitHub', 'https://github.com/x', name='Tom & Jerry #1')],
    }
    dork = next(d for d in build_dorks(corr) if d['query'] == '"Tom & Jerry #1"' and d['engine'] == 'google')
    query_string = dork['url'].split('?', 1)[1]
    assert '%26' in query_string and '%23' in query_string
    assert '&' not in query_string and '#' not in query_string  # cannot add a parameter or a fragment


@pytest.mark.parametrize('term', dorks.FORBIDDEN_TERMS)
def test_no_template_targets_leaks_or_credentials(term):
    for template in dorks.TEMPLATE_TEXT:
        assert term not in template.lower()


def test_generated_queries_contain_no_leak_or_credential_terms():
    corr = {
        **CORR,
        'phones': ['+39 06 1234 5678'],
        'emails': ['jane@example.org'],
    }
    for dork in build_dorks(corr):
        operators = dork['query'].lower().replace(dork['entity'].lower(), '')
        for term in dorks.FORBIDDEN_TERMS + dorks.FORBIDDEN_SITES:
            assert term not in operators, (term, dork['query'])


def test_paste_or_leak_sites_are_never_used_for_scoping():
    corr = {
        'primary_target': 'jroe',
        'usernames': ['jroe'],
        'accounts': [_account('paste', 'Pastebin', 'https://pastebin.com/u/jroe')],
    }
    assert not any('pastebin' in q for q in _queries(corr))


def test_scoping_hosts_must_be_real_https_hosts():
    corr = {
        'primary_target': 'jroe',
        'usernames': ['jroe'],
        'accounts': [_account('x', 'X', 'javascript:alert(1)'), _account('y', 'Y', 'https://exa mple.com/')],
    }
    assert _queries(corr) == ['"jroe"']


def test_build_dorks_never_touches_the_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError('dorks must never be executed')

    monkeypatch.setattr(socket, 'socket', refuse)
    monkeypatch.setattr(socket, 'create_connection', refuse)
    assert build_dorks(CORR)


def test_site_scoping_is_capped():
    accounts = [_account(f'p{i}', f'P{i}', f'https://p{i}.example.net/jroe') for i in range(40)]
    queries = _queries({'primary_target': 'jroe', 'usernames': ['jroe'], 'accounts': accounts})
    assert sum(1 for q in queries if ' site:' in q) == dorks.MAX_SITE_SCOPES


# --- report rendering ---


def test_markdown_section_says_it_is_never_run_and_links_each_engine():
    text = '\n'.join(format_dork_lines(build_dorks(CORR)))
    assert text.startswith('## Manual search queries')
    assert 'never runs' in text
    assert '| `"jroe" site:github.com` |' in text
    assert '[Google](https://www.google.com/search?q=' in text and '[DuckDuckGo](https://duckduckgo.com/?q=' in text


def test_markdown_section_when_nothing_to_search():
    assert '_No selectors to search for._' in '\n'.join(format_dork_lines([]))


def test_reports_carry_manual_queries(tmp_path):
    results = {
        'username_check': {
            'status': 'SUCCESS',
            'data': {
                'username': 'jroe',
                'platforms': {'github': {'exists': True, 'url': 'https://github.com/jroe', 'label': 'GitHub'}},
            },
        }
    }
    out = tmp_path / 'r.json'
    ReportGenerator().generate_json(results, 'jroe', 'username', str(out))
    report = json.loads(out.read_text(encoding='utf-8'))
    assert any(d['query'] == '"jroe" site:github.com' for d in report['manual_queries'])
    md = tmp_path / 'r.md'
    ReportGenerator().generate_markdown(results, 'jroe', 'username', str(md))
    text = md.read_text(encoding='utf-8')
    assert '## Manual search queries' in text and text.index('## Manual search queries') < text.index('## Results')


def test_webmail_provider_domains_are_not_dorked():
    corr = {'primary_target': 'jroe', 'domains': ['gmail.com', 'example.org']}
    queries = _queries(corr)
    assert 'site:example.org' in queries
    assert not any('gmail.com' in q for q in queries)


def test_domain_dorks_are_capped():
    corr = {'primary_target': 'x', 'domains': [f'd{i}.example.net' for i in range(20)]}
    dorked = {q.split()[0] for q in _queries(corr) if q.startswith('site:')}
    assert len(dorked) == dorks.MAX_DOMAINS
