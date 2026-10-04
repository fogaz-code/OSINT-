"""Export of a report's correlations to analyst tools (C7): GraphML, GEXF, Maltego entity CSV, JSON.

Input is ``ReportGenerator.correlations()`` output, i.e. ALREADY REDACTED with the run's
PrivacyGuard: an export never shows anything the report hides. Nothing here touches the network.

Model honesty is kept in every format: an edge without a relation the data demonstrates is
labelled "observed with" (co-occurrence in the same investigation, not a verified identity), and a
username found on a platform is "username found on", never "owns". Platforms where the username
was not found and suggested pivots (never run) are not exported as entities.

Output safety:
* XML (GraphML, GEXF) is built with ``xml.etree.ElementTree``, which escapes text and attributes;
  no DOCTYPE and no entities are ever emitted, and characters XML 1.0 forbids are dropped so the
  file is always well-formed.
* CSV cells that a spreadsheet would read as a formula (leading ``= + - @``, tab or CR, also after
  leading spaces) are prefixed with ``'`` (OWASP CSV injection guidance).
* Files are written with the reporter's owner-only private-write helper.
"""

import csv
import io
import ipaddress
import json
import re
import xml.etree.ElementTree as ET  # serialization only: nothing untrusted is ever parsed here
from pathlib import Path
from typing import Any, Dict, List, Tuple

from secure_osint.core.reporter import _write_private
from secure_osint.core.validator import detect_input_type

EXPORT_FORMATS: Tuple[str, ...] = ('graphml', 'gexf', 'maltego_csv', 'json')
MALTEGO_COLUMNS: Tuple[str, ...] = ('Entity Type', 'Value', 'Label', 'Relation', 'Linked To', 'Notes')

GRAPHML_NS = 'http://graphml.graphdrawing.org/xmlns'
GEXF_NS = 'http://gexf.net/1.3'

CO_OCCURRENCE_NOTE = (
    'Edges labelled "observed with" mean co-occurrence in the same investigation, not a verified identity; '
    '"username found on" does not prove the target owns that account.'
)

# (bucket, node type, Maltego entity type)
_BUCKETS: Tuple[Tuple[str, str, str], ...] = (
    ('usernames', 'username', 'maltego.Alias'),
    ('emails', 'email', 'maltego.EmailAddress'),
    ('domains', 'domain', 'maltego.Domain'),
    ('infrastructure', 'infrastructure', 'maltego.DNSName'),
    ('phones', 'phone', 'maltego.PhoneNumber'),
    ('locations', 'location', 'maltego.Location'),
    ('devices', 'device', 'maltego.Device'),
    ('wallets', 'wallet', 'maltego.CryptocurrencyAddress'),
)
_TARGET_TYPES = {
    'domain': 'maltego.Domain',
    'email': 'maltego.EmailAddress',
    'username': 'maltego.Alias',
    'phone': 'maltego.PhoneNumber',
    'ip': 'maltego.IPv4Address',
    'wallet': 'maltego.CryptocurrencyAddress',
}
_ACCOUNT_EDGES = {'found': 'username found on', 'possible': 'possible match on', 'manual': 'needs manual verification'}

_XML_INVALID = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff￾￿]')
_FORMULA_START = frozenset('=+-@\t\r')


def neutralize_cell(value: str) -> str:
    """Prefix ``'`` to a CSV cell a spreadsheet would evaluate as a formula."""
    if value and (value[0] in _FORMULA_START or value.lstrip(' ')[:1] in _FORMULA_START):
        return "'" + value
    return value


def _str(value: Any) -> str:
    return str(value) if value is not None else ''


def _xml_text(value: Any) -> str:
    return _XML_INVALID.sub('', _str(value))


# --- model ---


def _target_type(target: str) -> str:
    try:
        kind = detect_input_type(target, allow_files=False)
    except ValueError:
        return 'maltego.Phrase'
    return _TARGET_TYPES.get(kind, 'maltego.Phrase')


def _entity_type(bucket: str, default: str, value: str) -> str:
    if bucket != 'infrastructure':
        return default
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return 'maltego.Phrase' if '[REDACTED' in value else default  # a redacted IP
    return 'maltego.IPv6Address' if address.version == 6 else 'maltego.IPv4Address'


def build_export_model(correlations: Dict[str, Any]) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    """Nodes ``{id, label, type, maltego_type, status, confidence, url}`` and edges ``{source, target, relation}``.

    Node ids match the interactive graph (``target``, ``<bucket>:<value>``, ``account:<platform>``).
    """
    target = _str(correlations.get('primary_target')).strip() or '(no target)'
    nodes: List[Dict[str, str]] = [
        {
            'id': 'target',
            'label': target,
            'type': 'target',
            'maltego_type': _target_type(target),
            'status': '',
            'confidence': '',
            'url': '',
        }
    ]
    edges: List[Dict[str, str]] = []
    seen = {'target'}
    relations: Dict[Tuple[Any, str], str] = {}
    for relation in correlations.get('relations') or []:
        if isinstance(relation, dict) and _str(relation.get('from')) == target:
            relations.setdefault((relation.get('bucket'), _str(relation.get('to'))), _str(relation.get('type')))

    for account in correlations.get('accounts') or []:
        if not isinstance(account, dict):
            continue
        status = _str(account.get('status'))
        node_id = f'account:{_str(account.get("platform"))}'
        if status not in _ACCOUNT_EDGES or node_id in seen:
            continue
        seen.add(node_id)
        name = _str(account.get('label') or account.get('platform'))
        username = _str(account.get('username'))
        url = _str(account.get('url'))
        nodes.append(
            {
                'id': node_id,
                'label': f'{name}: {username}' if username else name,
                'type': 'account',
                'maltego_type': 'maltego.URL' if url else 'maltego.Alias',
                'status': status,
                'confidence': _str(account.get('confidence')),
                'url': url,
            }
        )
        edges.append({'source': 'target', 'target': node_id, 'relation': _ACCOUNT_EDGES[status]})

    for bucket, kind, maltego_type in _BUCKETS:
        for raw in correlations.get(bucket) or []:
            value = _str(raw).strip()
            node_id = f'{bucket}:{value}'
            if not value or value == target or node_id in seen:
                continue
            seen.add(node_id)
            nodes.append(
                {
                    'id': node_id,
                    'label': value,
                    'type': kind,
                    'maltego_type': _entity_type(bucket, maltego_type, value),
                    'status': '',
                    'confidence': '',
                    'url': '',
                }
            )
            edges.append(
                {'source': 'target', 'target': node_id, 'relation': relations.get((bucket, value)) or 'observed with'}
            )
    return nodes, edges


# --- serializers ---

_NODE_FIELDS = ('label', 'type', 'status', 'confidence', 'url')


def _xml_document(root: ET.Element) -> str:
    body = ET.tostring(root, encoding='unicode')
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + body + '\n'


def _graphml(nodes: List[Dict[str, str]], edges: List[Dict[str, str]]) -> str:
    root = ET.Element('graphml', {'xmlns': GRAPHML_NS})  # unqualified tags in the default namespace
    for field in _NODE_FIELDS:
        ET.SubElement(root, 'key', {'id': field, 'for': 'node', 'attr.name': field, 'attr.type': 'string'})
    ET.SubElement(root, 'key', {'id': 'relation', 'for': 'edge', 'attr.name': 'relation', 'attr.type': 'string'})
    graph = ET.SubElement(root, 'graph', {'id': 'correlations', 'edgedefault': 'directed'})
    for node in nodes:
        element = ET.SubElement(graph, 'node', {'id': _xml_text(node['id'])})
        for field in _NODE_FIELDS:
            if node[field]:
                ET.SubElement(element, 'data', {'key': field}).text = _xml_text(node[field])
    for index, edge in enumerate(edges):
        element = ET.SubElement(
            graph,
            'edge',
            {'id': f'e{index}', 'source': _xml_text(edge['source']), 'target': _xml_text(edge['target'])},
        )
        ET.SubElement(element, 'data', {'key': 'relation'}).text = _xml_text(edge['relation'])
    return _xml_document(root)


def _gexf(nodes: List[Dict[str, str]], edges: List[Dict[str, str]]) -> str:
    root = ET.Element('gexf', {'xmlns': GEXF_NS, 'version': '1.3'})
    meta = ET.SubElement(root, 'meta')
    ET.SubElement(meta, 'creator').text = 'secure-osint'
    ET.SubElement(meta, 'description').text = CO_OCCURRENCE_NOTE
    graph = ET.SubElement(root, 'graph', {'defaultedgetype': 'directed', 'mode': 'static'})
    attributes = ET.SubElement(graph, 'attributes', {'class': 'node'})
    fields = _NODE_FIELDS[1:]  # 'label' is a native GEXF node attribute
    for index, field in enumerate(fields):
        ET.SubElement(attributes, 'attribute', {'id': str(index), 'title': field, 'type': 'string'})
    node_list = ET.SubElement(graph, 'nodes')
    for node in nodes:
        element = ET.SubElement(node_list, 'node', {'id': _xml_text(node['id']), 'label': _xml_text(node['label'])})
        values = ET.SubElement(element, 'attvalues')
        for index, field in enumerate(fields):
            if node[field]:
                ET.SubElement(values, 'attvalue', {'for': str(index), 'value': _xml_text(node[field])})
    edge_list = ET.SubElement(graph, 'edges')
    for index, edge in enumerate(edges):
        ET.SubElement(
            edge_list,
            'edge',
            {
                'id': f'e{index}',
                'source': _xml_text(edge['source']),
                'target': _xml_text(edge['target']),
                'label': _xml_text(edge['relation']),
            },
        )
    return _xml_document(root)


def _maltego_csv(nodes: List[Dict[str, str]], edges: List[Dict[str, str]]) -> str:
    relation_of = {edge['target']: edge['relation'] for edge in edges}
    target_value = nodes[0]['label']
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator='\n')
    writer.writerow(MALTEGO_COLUMNS)
    for node in nodes:
        is_target = node['id'] == 'target'
        relation = '' if is_target else relation_of.get(node['id'], '')
        if is_target:
            notes = 'Primary target of the investigation'
        elif relation == 'observed with':
            notes = 'Co-occurrence in the same investigation, not a verified identity'
        elif node['type'] == 'account':
            notes = f'Platform outcome: {node["status"]}' + (
                f', confidence {node["confidence"]}' if node['confidence'] else ''
            )
            notes += '. A username found on a platform does not prove the target owns the account.'
        else:
            notes = f'Relation shown by the collected data: {relation}'
        value = node['url'] if node['type'] == 'account' and node['url'] else node['label']
        row = (node['maltego_type'], value, node['label'], relation, '' if is_target else target_value, notes)
        writer.writerow([neutralize_cell(cell) for cell in row])
    return buffer.getvalue()


def _json(correlations: Dict[str, Any], nodes: List[Dict[str, str]], edges: List[Dict[str, str]]) -> str:
    payload = {'note': CO_OCCURRENCE_NOTE, 'nodes': nodes, 'edges': edges, 'correlations': correlations}
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str) + '\n'


def export_correlations(correlations: Dict[str, Any], fmt: str, path: Path) -> Path:
    """Write ``correlations`` (already redacted) to ``path`` in ``fmt``, owner-only; return the path.

    Raises:
        ValueError: If ``fmt`` is not one of ``EXPORT_FORMATS``.
    """
    if fmt not in EXPORT_FORMATS:
        raise ValueError(f'Unknown export format {fmt!r}: choose one of {", ".join(EXPORT_FORMATS)}')
    nodes, edges = build_export_model(correlations)
    if fmt == 'graphml':
        content = _graphml(nodes, edges)
    elif fmt == 'gexf':
        content = _gexf(nodes, edges)
    elif fmt == 'maltego_csv':
        content = _maltego_csv(nodes, edges)
    else:
        content = _json(correlations, nodes, edges)
    path = Path(path)
    _write_private(str(path), content)
    return path
