"""Deliverables of a recursive investigation: one report per target plus the pivot record that ties them.

Layout under the output directory (file names never carry a target, only node ids)::

    investigation.json   pivot tree, scope, merged entities, SHA-256 of every per-target report
    investigation.md     the same, for people
    targets/000/latest.json, latest.md   the seed's ordinary report
    targets/001/...                      one folder per pivot that ran

Everything goes through the run's ``ReportGenerator`` (same PrivacyGuard, same case ID), so the
investigation record never shows a value the per-target reports hide.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from secure_osint.core.correlation import ENTITY_BUCKETS
from secure_osint.core.investigation import RUN, Investigation, InvestigationNode
from secure_osint.core.reporter import LEGAL_DISCLAIMER, ReportGenerator, _write_private, canonical_json
from secure_osint.core.workflow import StepStatus
from secure_osint.utils.markdown import md_code, md_text

_BUCKET_BY_KIND = {
    'username': 'usernames',
    'email': 'emails',
    'domain': 'domains',
    'ipv4': 'infrastructure',
    'ipv6': 'infrastructure',
    'phone': 'phones',
    'wallet': 'wallets',
}
_OUTCOME_TEXT = {
    'run': 'investigated',
    'failed': 'run failed',
    'declined': 'declined by the analyst',
    'budget_exhausted': 'not run: target budget exhausted',
    'max_depth': 'not run: beyond the depth limit',
}
INVESTIGATION_NOTE = (
    'Each pivot below was found in the data of its parent target and was run only after the analyst '
    'approved it (or approved pivots in advance with --approve-pivots). A link between two targets means '
    'one selector appeared in the public data collected for the other: co-occurrence, not a verified identity.'
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _status_counts(results: Optional[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for result in (results or {}).values():
        status = getattr(result, 'status', None)
        name = status.value if isinstance(status, StepStatus) else str(status)
        counts[name] = counts.get(name, 0) + 1
    return dict(sorted(counts.items()))


class InvestigationReporter:
    """Writes the per-target reports and the investigation record."""

    def __init__(self, reporter: ReportGenerator):
        """Initialize InvestigationReporter."""
        self.reporter = reporter
        self.guard = reporter.privacy_guard

    def display(self, node: InvestigationNode) -> str:
        """A node's value as every deliverable shows it (redacted like a correlation entity)."""
        bucket = _BUCKET_BY_KIND.get(node.kind)
        return self.reporter._redact_entity(bucket, node.value) if bucket else str(self.guard.redact(node.value))

    def write(self, investigation: Investigation, output_dir: Path) -> Dict[str, Path]:
        """Write every report; returns the paths of ``investigation.json`` and ``investigation.md``."""
        output_dir = Path(output_dir)
        record_nodes: List[Dict[str, Any]] = []
        entities: Dict[str, List[str]] = {bucket: [] for bucket in ENTITY_BUCKETS}
        for node in investigation.nodes:
            item: Dict[str, Any] = {
                'id': node.id,
                'parent': node.parent,
                'depth': node.depth,
                'kind': node.kind,
                'value': self.display(node),
                'workflow': node.workflow,
                'outcome': node.outcome,
                'found_in': list(node.found_in),
            }
            if node.error:
                item['error'] = self.guard.redact(node.error)
            if node.outcome == RUN and node.results is not None:
                folder = output_dir / 'targets' / f'{node.id:03d}'
                json_path = self.reporter.generate_json(
                    node.results, node.value, node.workflow or '', str(folder / 'latest.json')
                )
                md_path = self.reporter.generate_markdown(
                    node.results, node.value, node.workflow or '', str(folder / 'latest.md')
                )
                item['steps'] = _status_counts(node.results)
                item['reports'] = {
                    Path(path).name: {
                        'path': Path(path).relative_to(output_dir).as_posix(),
                        'sha256': _sha256(Path(path)),
                    }
                    for path in (json_path, md_path)
                }
                correlations = self.reporter.correlations(node.results, node.value)
                for bucket in ENTITY_BUCKETS:
                    for value in correlations.get(bucket, []):
                        if value not in entities[bucket]:
                            entities[bucket].append(value)
            record_nodes.append(item)

        record: Dict[str, Any] = {'timestamp': datetime.now(timezone.utc).isoformat()}
        if self.reporter.case_id:
            record['case_id'] = self.reporter.case_id
        record.update(
            {
                'seed': record_nodes[0]['value'] if record_nodes else None,
                'scope': {
                    'follow': list(investigation.follow),
                    'max_depth': investigation.max_depth,
                    'max_targets': investigation.max_targets,
                },
                'targets_run': sum(1 for n in investigation.nodes if n.outcome == RUN),
                'nodes': record_nodes,
                'entities': {bucket: sorted(values) for bucket, values in entities.items()},
                'note': INVESTIGATION_NOTE,
                'disclaimer': LEGAL_DISCLAIMER,
            }
        )
        # Same contract as the per-target JSON report: drop `integrity`, re-serialize canonically, compare.
        # The per-target hashes inside make this one digest cover every file of the investigation.
        record['integrity'] = {
            'algorithm': 'sha256',
            'value': hashlib.sha256(canonical_json(record).encode()).hexdigest(),
            'covers': 'canonical JSON (sorted keys) of this record excluding the integrity field',
        }
        json_out = output_dir / 'investigation.json'
        md_out = output_dir / 'investigation.md'
        _write_private(str(json_out), json.dumps(record, indent=2, default=str))
        _write_private(str(md_out), self._markdown(record))
        return {'json': json_out, 'markdown': md_out}

    @staticmethod
    def _markdown(record: Dict[str, Any]) -> str:
        scope = record['scope']
        lines = ['# OSINT Investigation', f'**Generated:** {record["timestamp"]}']
        if record.get('case_id'):
            lines.append(f'**Case ID:** {md_text(record["case_id"])}')
        lines.extend(
            [
                f'**Seed:** {md_code(record["seed"])}',
                f'**Scope:** follow {", ".join(scope["follow"]) or "nothing"}; depth {scope["max_depth"]}; '
                f'at most {scope["max_targets"]} targets ({record["targets_run"]} run)',
                '',
                f'_{INVESTIGATION_NOTE}_',
                '',
                '## Pivot tree',
                '',
            ]
        )
        children: Dict[Optional[int], List[Dict[str, Any]]] = {}
        for node in record['nodes']:
            children.setdefault(node['parent'], []).append(node)

        def emit(node: Dict[str, Any], indent: int) -> None:
            text = f'{"  " * indent}- [{node["id"]:03d}] {node["kind"]} {md_code(node["value"])}: '
            text += _OUTCOME_TEXT.get(node['outcome'], md_text(node['outcome']))
            if node['found_in']:
                text += ' (found in ' + ', '.join(md_code(step) for step in node['found_in']) + ')'
            if node.get('steps'):
                text += ' · steps ' + ', '.join(f'{k} {v}' for k, v in node['steps'].items())
            if node.get('reports'):
                text += ' · report ' + md_code(node['reports']['latest.md']['path'])
            if node.get('error'):
                text += f' · error: {md_text(node["error"])}'
            lines.append(text)
            for child in children.get(node['id'], []):
                emit(child, indent + 1)

        for root in children.get(None, []):
            emit(root, 0)
        lines.extend(['', '## Entities across all targets', ''])
        for bucket, values in record['entities'].items():
            if values:
                lines.append(f'- **{bucket}:** ' + ', '.join(md_code(v) for v in values))
        lines.extend(['', '## Report integrity', ''])
        for node in record['nodes']:
            for name, info in (node.get('reports') or {}).items():
                lines.append(f'- {md_code(info["path"])}: `{info["sha256"]}`')
        lines.extend(['', '---', LEGAL_DISCLAIMER, ''])
        body = '\n'.join(lines) + '\n'
        digest = hashlib.sha256(body.encode()).hexdigest()
        return body + f'<!-- integrity:sha256 -->\n**Report SHA-256:** `{digest}`\n'
