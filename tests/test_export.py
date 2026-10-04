"""C7 export of the (already redacted) correlations: GraphML, GEXF, Maltego CSV, JSON."""

import csv
import io
import json
import xml.etree.ElementTree as ET  # parsing our own output only

import pytest

from secure_osint.core import export
from secure_osint.cli import EXPORT_FILENAMES
from secure_osint.core.export import EXPORT_FORMATS, export_correlations, neutralize_cell
from secure_osint.core.reporter import ReportGenerator

GRAPHML_NS = '{http://graphml.graphdrawing.org/xmlns}'
GEXF_NS = '{http://gexf.net/1.3}'

CORR = {
    'primary_target': 'example.com',
    'usernames': ['=cmd|"/c calc"!A1'],
    'emails': ['[REDACTED]'],
    'domains': ['example.com', 'example.org'],
    'infrastructure': ['[REDACTED]', 'ns1.example.com'],
    'phones': ['+39 06 1234 5678'],
    'locations': ['[REDACTED]'],
    'devices': ['Canon EOS 5D (serial [REDACTED])'],
    'wallets': ['ETH [REDACTED]'],
    'accounts': [
        {
            'platform': 'github',
            'label': 'GitHub',
            'username': 'examplecorp',
            'status': 'found',
            'confidence': 'HIGH',
            'url': 'https://github.com/examplecorp',
        },
        {'platform': 'reddit', 'label': 'Reddit', 'username': 'examplecorp', 'status': 'not_found', 'url': ''},
    ],
    'relations': [
        {'from': 'example.com', 'to': 'ns1.example.com', 'type': 'nameserver', 'bucket': 'infrastructure'},
        {'from': 'example.com', 'to': '[REDACTED]', 'type': 'resolves to', 'bucket': 'infrastructure'},
    ],
    'suggested_pivots': ['Email: [REDACTED] (DNS SOA contact)'],
    'timeline': [],
    'timeline_coverage': {'platforms_with_dates': 0, 'platforms_found': 1},
}


def _write(tmp_path, fmt, corr=CORR):
    path = export_correlations(corr, fmt, tmp_path / EXPORT_FILENAMES[fmt])
    assert path.exists()
    return path, path.read_text(encoding='utf-8')


def test_formats_and_filenames():
    # The names the CLI and GUI actually write (fixed, like latest.json / latest.md next to them).
    assert set(EXPORT_FORMATS) == {'graphml', 'gexf', 'maltego_csv', 'json'}
    assert EXPORT_FILENAMES == {
        'graphml': 'correlations.graphml',
        'gexf': 'correlations.gexf',
        'maltego_csv': 'correlations_maltego.csv',
        'json': 'correlations.json',
    }


def test_unknown_format_is_rejected(tmp_path):
    with pytest.raises(ValueError, match='Unknown export format'):
        export_correlations(CORR, 'xlsx', tmp_path / 'x')
    assert not list(tmp_path.iterdir())


def test_graphml_is_well_formed_with_typed_nodes_and_labelled_edges(tmp_path):
    _, text = _write(tmp_path, 'graphml')
    assert '<!DOCTYPE' not in text and '<!ENTITY' not in text
    root = ET.fromstring(text)
    graph = root.find(f'{GRAPHML_NS}graph')
    assert graph is not None and graph.get('edgedefault') == 'directed'
    keys = {k.get('attr.name'): k.get('id') for k in root.findall(f'{GRAPHML_NS}key')}
    nodes = {}
    for node in graph.findall(f'{GRAPHML_NS}node'):
        data = {d.get('key'): d.text for d in node.findall(f'{GRAPHML_NS}data')}
        nodes[node.get('id')] = data
    assert nodes['target'][keys['type']] == 'target'
    assert nodes['infrastructure:ns1.example.com'][keys['label']] == 'ns1.example.com'
    assert nodes['account:github'][keys['type']] == 'account'
    assert nodes['account:github'][keys['status']] == 'found'
    assert nodes['locations:[REDACTED]'][keys['type']] == 'location'
    edges = {
        e.get('target'): {d.get('key'): d.text for d in e.findall(f'{GRAPHML_NS}data')}
        for e in graph.findall(f'{GRAPHML_NS}edge')
    }
    assert edges['infrastructure:ns1.example.com'][keys['relation']] == 'nameserver'
    assert edges['domains:example.org'][keys['relation']] == 'observed with'
    assert edges['account:github'][keys['relation']] == 'username found on'
    assert all(e.get('source') in nodes and e.get('target') in nodes for e in graph.findall(f'{GRAPHML_NS}edge'))


def test_xml_special_characters_are_escaped_by_the_serializer(tmp_path):
    corr = {'primary_target': 'a&b', 'usernames': ['<script>x</script>', 'x"y\'z', 'ctl\x00\x08\x1bchar']}
    for fmt in ('graphml', 'gexf'):
        _, text = _write(tmp_path, fmt, corr)
        assert '<script>' not in text
        root = ET.fromstring(text)  # well-formed: control characters invalid in XML 1.0 were dropped
        values = [el.text for el in root.iter() if el.text] + [v for el in root.iter() for v in el.attrib.values()]
        assert 'a&b' in values and '<script>x</script>' in values and 'x"y\'z' in values
        assert 'ctlchar' in values


def test_gexf_is_well_formed_and_uses_declared_attributes(tmp_path):
    _, text = _write(tmp_path, 'gexf')
    root = ET.fromstring(text)
    assert root.tag == f'{GEXF_NS}gexf' and root.get('version') == '1.3'
    graph = root.find(f'{GEXF_NS}graph')
    assert graph.get('defaultedgetype') == 'directed'
    declared = {a.get('id') for a in graph.iter(f'{GEXF_NS}attribute')}
    used = {v.get('for') for v in graph.iter(f'{GEXF_NS}attvalue')}
    assert used and used <= declared
    node_ids = {n.get('id') for n in graph.iter(f'{GEXF_NS}node')}
    assert {'target', 'devices:Canon EOS 5D (serial [REDACTED])', 'wallets:ETH [REDACTED]'} <= node_ids
    for edge in graph.iter(f'{GEXF_NS}edge'):
        assert edge.get('source') in node_ids and edge.get('target') in node_ids
    assert len({e.get('id') for e in graph.iter(f'{GEXF_NS}edge')}) == len(list(graph.iter(f'{GEXF_NS}edge')))


@pytest.mark.parametrize(
    'value, expected',
    [
        ('=1+1', "'=1+1"),
        ('+39 06 1234 5678', "'+39 06 1234 5678"),
        ('-2', "'-2"),
        ('@SUM(A1)', "'@SUM(A1)"),
        ('\tx', "'\tx"),
        ('\rx', "'\rx"),
        ('  =1+1', "'  =1+1"),  # leading spaces do not hide the formula
        ('plain', 'plain'),
        ('', ''),
        ('a=b', 'a=b'),
    ],
)
def test_neutralize_cell(value, expected):
    assert neutralize_cell(value) == expected


def test_maltego_csv_has_entity_rows_and_no_formula_cells(tmp_path):
    _, text = _write(tmp_path, 'maltego_csv')
    rows = list(csv.DictReader(io.StringIO(text)))
    assert rows and set(rows[0]) == set(export.MALTEGO_COLUMNS)
    for row in rows:
        for cell in row.values():
            assert not cell or cell[0] not in '=+-@\t\r', row
    by_value = {r['Value']: r for r in rows}
    assert by_value['example.com']['Entity Type'] == 'maltego.Domain'
    assert by_value['ns1.example.com']['Entity Type'] == 'maltego.DNSName'
    assert by_value['ns1.example.com']['Relation'] == 'nameserver'
    assert by_value['\'=cmd|"/c calc"!A1']['Entity Type'] == 'maltego.Alias'
    assert by_value["'+39 06 1234 5678"]['Entity Type'] == 'maltego.PhoneNumber'
    assert by_value['https://github.com/examplecorp']['Entity Type'] == 'maltego.URL'
    assert 'https://reddit' not in text  # not-found platforms are not entities
    assert all(r['Notes'] for r in rows if r['Relation'] == 'observed with')


def test_json_export_keeps_correlations_and_graph(tmp_path):
    _, text = _write(tmp_path, 'json')
    data = json.loads(text)
    assert data['correlations'] == CORR
    assert {n['id'] for n in data['nodes']} >= {'target', 'account:github', 'domains:example.org'}
    assert 'not a verified identity' in data['note']


def test_exports_use_the_private_write_helper(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(export, '_write_private', lambda path, content: calls.append(path))
    for fmt in EXPORT_FORMATS:
        export_correlations(CORR, fmt, tmp_path / EXPORT_FILENAMES[fmt])
    assert len(calls) == len(EXPORT_FORMATS)


def test_redacted_report_correlations_export_without_pii(tmp_path):
    results = {
        'dns': {
            'status': 'SUCCESS',
            'data': {'A': ['93.184.216.34'], 'SOA': {'rname': 'hostmaster.example.com.'}},
        },
        'whois': {'status': 'SUCCESS', 'data': {'email': 'ceo@example.com', 'domain': 'example.com'}},
    }
    corr = ReportGenerator().correlations(results, 'example.com')
    for fmt in EXPORT_FORMATS:
        _, text = _write(tmp_path, fmt, corr)
        for secret in ('93.184.216.34', 'ceo@example.com', 'hostmaster@example.com'):
            assert secret not in text, (fmt, secret)
