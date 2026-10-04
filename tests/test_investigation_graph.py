"""Grafo investigativo: esiti per piattaforma, relazioni dimostrate dai dati, filtri, GUI.

Scenario principale: lo username "jroe" trovato su 9 piattaforme, 4 da verificare a mano (login
richiesto), le altre non trovate. Il grafo deve mostrare 9 nodi piattaforma collegati al target.
"""

import re

import pytest

from secure_osint.core.correlation import build_correlations, format_summary_lines
from secure_osint.core.graph import (
    DEFAULT_FILTERS,
    EXPANDERS,
    FILTERS,
    STYLES,
    expand_node,
    filter_model,
    graph_elements,
    graph_model,
    register_expander,
)
from secure_osint.core.privacy import CATEGORIES, PrivacyGuard
from secure_osint.core.reporter import ReportGenerator
from secure_osint.sources.username_source import AUTH_REQUIRED, AUTH_REQUIRED_MSG, PLATFORM_LABELS, PLATFORMS
from tests.owner_only import assert_owner_only

FOUND = ['github', 'keybase', 'telegram', 'tiktok', 'pinterest', 'dockerhub', 'pypi', 'hackaday', 'sourceforge']


def _username_results(username='jroe', found=FOUND, extra=None):
    platforms = {}
    for name, platform in PLATFORMS.items():
        exists = True if name in found else (None if name in AUTH_REQUIRED else False)
        platforms[name] = {
            'exists': exists,
            'error': AUTH_REQUIRED_MSG if name in AUTH_REQUIRED else None,
            'url': platform.profile_url.format(u=username),
            'exact': name != 'stackoverflow',
            'label': PLATFORM_LABELS[name],
            'confidence': platform.confidence if exists is not None else 'MANUAL',
        }
    platforms.update(extra or {})
    return {'username_check': {'status': 'SUCCESS', 'data': {'username': username, 'platforms': platforms}}}


def _corr(results, target='jroe', guard=None):
    return ReportGenerator(guard).correlations(results, target)


DNS = {
    'dns': {
        'status': 'SUCCESS',
        'data': {
            'A': ['93.184.216.34'],
            'AAAA': [],
            'CNAME': [],
            'NS': ['NS1.Example.com.'],
            'MX': [{'preference': 10, 'exchange': 'Mail.Example.com.'}],
        },
    }
}


# --- correlations: per-platform accounts (pure Python, CI) ---


def test_accounts_have_status_url_and_label():
    accounts = _corr(_username_results())['accounts']
    by = {a['platform']: a for a in accounts}
    assert len(accounts) == len(PLATFORMS)
    assert by['github'] == {
        'platform': 'github',
        'label': 'GitHub',
        'username': 'jroe',
        'status': 'found',
        'confidence': 'HIGH',
        'url': 'https://github.com/jroe',
        'note': '',
    }
    assert by['linkedin']['status'] == 'manual' and by['linkedin']['note'] == AUTH_REQUIRED_MSG
    assert by['gitlab']['status'] == 'not_found'


def test_accounts_sorted_found_then_manual_then_not_found():
    accounts = _corr(_username_results())['accounts']
    statuses = [a['status'] for a in accounts]
    assert statuses == sorted(statuses, key=['found', 'manual', 'not_found'].index)
    found_levels = [a['confidence'] for a in accounts if a['status'] == 'found']
    assert found_levels == sorted(found_levels, key=['HIGH', 'MEDIUM', 'LOW'].index)  # most certain first


def test_stack_overflow_name_search_is_low_confidence():
    accounts = _corr(_username_results(found=FOUND + ['stackoverflow']))['accounts']
    so = next(a for a in accounts if a['platform'] == 'stackoverflow')
    assert so['status'] == 'found' and so['confidence'] == 'LOW'


def test_blocked_platform_counts_as_manual_check():
    extra = {
        'reddit': {'exists': None, 'error': 'Blocked by platform (HTTP 429)', 'url': 'https://r/x', 'label': 'Reddit'}
    }
    accounts = _corr(_username_results(extra=extra))['accounts']
    reddit = next(a for a in accounts if a['platform'] == 'reddit')
    assert reddit['status'] == 'manual' and '429' in reddit['note']


def test_summary_lists_findings_and_ownership_caveat():
    text = '\n'.join(format_summary_lines(_corr(_username_results())))
    assert '**Username found on:**' in text and '`GitHub`' in text and '`SourceForge`' in text
    assert '**Manual verification needed:**' in text and '`LinkedIn`' in text
    assert '**Checked, not found:** 17 platform(s)' in text  # 30 platforms - 9 found - 4 auth-required
    assert 'does not prove the target owns that account' in text


# --- correlations: relations proven by the data (pure Python, CI) ---


def test_dns_relations_for_a_domain_target():
    relations = build_correlations('example.com', DNS)['relations']
    assert {'from': 'example.com', 'to': '93.184.216.34', 'type': 'resolves to'} in relations
    assert {'from': 'example.com', 'to': 'ns1.example.com', 'type': 'nameserver'} in relations
    assert {'from': 'example.com', 'to': 'mail.example.com', 'type': 'mail server'} in relations


def test_email_target_uses_its_domain():
    relations = build_correlations('jane@example.org', {'e': {'data': {'email_domain': 'example.org'}}})['relations']
    assert relations == [{'from': 'jane@example.org', 'to': 'example.org', 'type': 'uses domain'}]


def test_no_dns_relations_invented_for_a_username_target():
    assert build_correlations('jroe', DNS)['relations'] == []


def test_relations_and_accounts_are_redacted_in_the_report():
    relations = _corr(DNS, target='example.com')['relations']
    assert {'from': 'example.com', 'to': '[REDACTED]', 'type': 'resolves to', 'bucket': 'infrastructure'} in relations
    keep = PrivacyGuard(categories=CATEGORIES - {'network'})
    assert any(r['to'] == '93.184.216.34' for r in _corr(DNS, target='example.com', guard=keep)['relations'])


def test_redacted_email_does_not_inherit_a_redacted_ips_relation():
    """Regression test for the [REDACTED] collision bug: an email and an IP can both redact to the
    same placeholder string, but the email must never falsely "resolve to" as if it were the IP.

    Exercises the real pipeline (ReportGenerator, like the CLI/GUI do), not the pure model: the
    original bug only showed up once relations were resolved against the already-redacted display
    string instead of each entity's own raw value.
    """
    results = {
        'dns': {'status': 'SUCCESS', 'data': {'A': ['93.184.216.34'], 'NS': [], 'MX': []}},
        'whois': {'status': 'SUCCESS', 'data': {'contact': 'admin@example.com'}},
    }
    nodes, edges = graph_elements(_corr(results, target='example.com'))
    by_id = {n['id']: n for n in nodes}
    assert by_id['infrastructure:[REDACTED]']['label'] == '[REDACTED]'
    assert by_id['emails:[REDACTED]']['label'] == '[REDACTED]'  # same placeholder, different entity
    edge_by_to = {e['to']: e['label'] for e in edges}
    assert edge_by_to['infrastructure:[REDACTED]'] == 'resolves to'
    assert edge_by_to['emails:[REDACTED]'] == 'observed with'  # no relation proves this for the email


# --- graph: nodes, edges, styling (pure Python, CI) ---


def test_jroe_scenario_shows_nine_platform_nodes_linked_to_target():
    nodes, edges = graph_elements(_corr(_username_results()))
    found = [n for n in nodes if n.get('status') == 'found']
    assert len(found) == 9
    assert {n['label'] for n in found} == {f'{PLATFORM_LABELS[p]}: jroe' for p in FOUND}
    assert all(any(e['from'] == 'target' and e['to'] == n['id'] for e in edges) for n in found)


def test_found_nodes_carry_url_status_and_run_time():
    nodes, _ = graph_elements(_corr(_username_results()), checked_at='2026-09-26 10:00 UTC')
    github = next(n for n in nodes if n['id'] == 'account:github')
    assert github['url'] == 'https://github.com/jroe'
    assert github['color'] == STYLES['found']['color']
    for line in (
        'Status: username exists',
        'URL: https://github.com/jroe',
        'Checked during run: 2026-09-26 10:00 UTC',
    ):
        assert line in github['title']
    assert github['ref'] == {
        'kind': 'account',
        'platform': 'github',
        'username': 'jroe',
        'url': 'https://github.com/jroe',
    }


def test_edges_say_username_found_on_not_ownership():
    _, edges = graph_elements(_corr(_username_results()))
    labels = {e['label'] for e in edges}
    assert 'username found on' in labels
    assert not any('has account' in label or 'owns' in label for label in labels)


def test_edge_style_encodes_confidence():
    _, edges = graph_elements(_corr(_username_results(found=FOUND + ['stackoverflow'])))
    by_to = {e['to']: e for e in edges}
    high, medium, low = by_to['account:github'], by_to['account:tiktok'], by_to['account:stackoverflow']
    assert high['dashes'] is False and high['width'] == 3 and high['color'] == '#3e8ef7'  # solid thick blue
    assert medium['dashes'] and medium['color'] == '#3e8ef7' and medium['width'] < high['width']  # dashed blue
    assert low['dashes'] and low['width'] == 1 and low['color'] != '#3e8ef7'  # thin gray dotted
    assert low['title'] == 'Low confidence: verify manually'
    assert by_to['account:linkedin']['dashes']  # manual check


def test_manual_check_nodes_are_yellow_and_labelled():
    nodes, _ = graph_elements(_corr(_username_results()))
    manual = [n for n in nodes if n.get('status') == 'manual']
    assert {n['label'] for n in manual} == {
        'LinkedIn (manual check required)',
        'Instagram (manual check required)',
        'Facebook (manual check required)',
        'X (manual check required)',
    }
    assert all(n['color'] == STYLES['manual']['color'] for n in manual)


def test_not_found_hidden_by_default_and_shown_by_filter():
    corr = _corr(_username_results())
    assert 'not_found' not in DEFAULT_FILTERS
    default_nodes, _ = graph_elements(corr)
    all_nodes, _ = graph_elements(corr, filters=FILTERS)
    assert not any(n.get('status') == 'not_found' for n in default_nodes)
    not_found = [n for n in all_nodes if n.get('status') == 'not_found']
    assert len(not_found) == 17 and all(n['label'].endswith(': not found') for n in not_found)
    assert all('url' not in n for n in not_found)  # nothing to open


def test_filter_model_drops_nodes_and_their_edges_but_keeps_target():
    model = graph_model(_corr(_username_results()))
    only_manual = filter_model(model, ['manual'])
    assert {n['category'] for n in only_manual['nodes']} == {'target', 'manual'}
    kept = {n['id'] for n in only_manual['nodes']}
    assert all(e['from'] in kept and e['to'] in kept for e in only_manual['edges'])
    assert [n['id'] for n in filter_model(model, [])['nodes']] == ['target']


def test_dns_relations_become_labelled_edges():
    nodes, edges = graph_elements(_corr(DNS, target='example.com'))
    by_label = {n['label']: n['id'] for n in nodes}
    edge_to = {e['to']: e['label'] for e in edges}
    assert edge_to[by_label['[REDACTED]']] == 'resolves to'  # IP redacted, relation kept
    assert edge_to[by_label['ns1.example.com']] == 'nameserver'
    assert edge_to[by_label['mail.example.com']] == 'mail server'


def test_only_https_urls_become_clickable():
    extra = {'github': {'exists': True, 'error': None, 'url': 'javascript:alert(1)', 'label': 'GitHub'}}
    nodes, _ = graph_elements(_corr(_username_results(extra=extra)))
    github = next(n for n in nodes if n['id'] == 'account:github')
    assert 'url' not in github and 'Double-click' not in github['title']


# --- click-to-expand contract (pure Python, CI) ---


def test_expander_registry_marks_and_expands_nodes():
    try:

        @register_expander('github')
        def fake_repos(ref):
            return (
                [{'id': 'repo:x', 'label': f'{ref["username"]}/x', 'category': 'found'}],
                [{'from': 'account:github', 'to': 'repo:x', 'label': 'owns repository'}],
            )

        model = graph_model(_corr(_username_results()))
        github = next(n for n in model['nodes'] if n['id'] == 'account:github')
        assert github.get('expandable') is True
        expanded = expand_node(model, 'account:github')
        assert any(n['id'] == 'repo:x' and n['label'] == 'jroe/x' for n in expanded['nodes'])
        assert len(expanded['nodes']) == len(model['nodes']) + 1
        with pytest.raises(LookupError):
            expand_node(model, 'account:keybase')  # no expander registered
    finally:
        EXPANDERS.pop('github', None)


# --- GUI filters (pure parts run in CI) ---


def test_filter_handler_without_a_run_is_empty():
    from secure_osint.app import _ui_filter

    assert _ui_filter(None, True, True, False, True, True) == ('', None)


def test_filter_handler_without_graph_keeps_report_downloads():
    from secure_osint.app import _ui_filter

    state = {'files': ['a.json', 'a.md'], 'panel': 'notice', 'model': None, 'path': None}
    assert _ui_filter(state, True, True, True, True, True) == ('notice', ['a.json', 'a.md'])


def test_filter_flags_map_to_categories_in_order():
    from secure_osint.app import FILTER_LABELS, _active_filters

    assert len(FILTER_LABELS) == len(FILTERS)
    assert _active_filters([True, False, True, False, True]) == ['found', 'not_found', 'domains']
    assert _active_filters(['true', 1, None, True, False]) == ['infrastructure']  # only real booleans


# --- rendering and GUI end to end (need the 'graph' extra) ---


def _fake_engine(monkeypatch, results):
    from secure_osint import app as gui_app

    class FakeEngine:
        def __init__(self, **kwargs):
            pass

        def execute(self, wf, input_str):
            return results

    monkeypatch.setattr('secure_osint.core.engine.WorkflowEngine', FakeEngine)
    monkeypatch.setattr(gui_app, '_open_cache', lambda ttl: None)
    return gui_app


def test_gui_run_then_filter_rewrites_graph(monkeypatch, tmp_path):
    pytest.importorskip('pyvis')
    gui_app = _fake_engine(monkeypatch, _username_results())
    monkeypatch.chdir(tmp_path)
    flags = [name in DEFAULT_FILTERS for name in FILTERS]
    markdown, files, panel, state = gui_app._ui_run('jroe', 'auto', 'C-9', False, True, True, *flags)
    assert '**Username found on:**' in markdown
    graph_file = files[-1]
    assert graph_file.endswith('C-9_graph.html') and 'GitHub: jroe' in open(graph_file, encoding='utf-8').read()
    assert 'GitLab: not found' not in open(graph_file, encoding='utf-8').read()
    sandbox = panel.split('sandbox="', 1)[1].split('"', 1)[0].split()
    assert 'allow-popups' in sandbox and 'allow-same-origin' not in sandbox

    new_panel, new_files = gui_app._ui_filter(state, True, True, True, True, True)  # show not-found too
    assert new_files == files
    html = open(graph_file, encoding='utf-8').read()
    assert 'GitLab: not found' in html  # the downloadable file matches the screen
    assert_owner_only(graph_file)
    assert new_panel != panel


def test_gate_still_blocks_the_ui_run(monkeypatch, tmp_path):
    gui_app = _fake_engine(monkeypatch, _username_results())
    markdown, files, panel, state = gui_app._ui_run('jroe', 'auto', '', False, False, True, True, True)
    assert markdown == gui_app.GATE_REFUSAL and files is None and state is None


def test_rendered_graph_is_offline_and_has_open_profile_hook(tmp_path):
    pytest.importorskip('pyvis')
    from secure_osint.core.graph import build_correlation_graph, save_graph_html

    html = save_graph_html(build_correlation_graph(_corr(_username_results())), tmp_path / 'g.html').read_text(
        encoding='utf-8'
    )
    assert not re.search(r'(?:src|href)\s*=\s*["\']https?://', html, re.IGNORECASE)
    assert "network.on('doubleClick'" in html and "'noopener,noreferrer'" in html
    assert 'GitHub: jroe' in html and 'X (manual check required)' in html


# --- expander output is validated at the boundary ---


def _with_expander(result):
    @register_expander('github')
    def fake(ref):
        return result

    return graph_model(_corr(_username_results()))


@pytest.mark.parametrize(
    'result',
    [
        None,
        'nodes',
        ([],),
        ({'id': 'x'}, []),
        ([{'label': 'no id'}], []),
        ([{'id': ''}], []),
        ([{'id': 7}], []),
        (['not a dict'], []),
        ([{'id': 'x', 'category': 'target'}], []),  # an expander cannot add a second target
        ([], [{'from': 'account:github'}]),
        ([], ['edge']),
    ],
)
def test_malformed_expander_output_raises_a_clear_error(result):
    try:
        model = _with_expander(result)
        with pytest.raises(ValueError, match='Expander for'):
            expand_node(model, 'account:github')
    finally:
        EXPANDERS.pop('github', None)


def test_expander_nodes_are_normalised_and_filterable():
    try:
        model = _with_expander(
            (
                [
                    {'id': 'repo:x'},  # no category, no label: the GUI filter used to raise KeyError
                    {'id': 'repo:y', 'label': 'y', 'category': 'bogus', 'url': 'javascript:alert(1)', 'onclick': 'x'},
                    {'id': 'repo:z', 'label': 'mail ceo@example.com', 'category': 'domains', 'url': 'https://e.x/z'},
                ],
                [
                    {'from': 'account:github', 'to': 'repo:x', 'label': 'owns repository', 'color': 'red'},
                    {'from': 'account:github', 'to': 'nowhere'},  # dangling: dropped
                ],
            )
        )
        expanded = expand_node(model, 'account:github')
        nodes = {n['id']: n for n in expanded['nodes']}
        x, y, z = nodes['repo:x'], nodes['repo:y'], nodes['repo:z']
        assert x['label'] == 'repo:x' and x['category'] == 'found'
        assert y['category'] == 'found' and 'url' not in y and 'onclick' not in y
        assert z['url'] == 'https://e.x/z' and 'ceo@example.com' not in z['label']  # redacted by default
        assert all('x' in n and 'y' in n for n in expanded['nodes'] if n['category'] != 'target')
        new_edges = [e for e in expanded['edges'] if e['from'] == 'account:github']
        assert new_edges == [
            {'from': 'account:github', 'to': 'repo:x', 'label': 'owns repository', 'title': 'owns repository'}
        ]
        assert filter_model(expanded, FILTERS)  # no KeyError
    finally:
        EXPANDERS.pop('github', None)


def test_filter_model_tolerates_nodes_without_category():
    model = {'nodes': [{'id': 'target', 'category': 'target'}, {'id': 'a'}], 'edges': [{'from': 'target', 'to': 'a'}]}
    assert [n['id'] for n in filter_model(model, FILTERS)['nodes']] == ['target']
