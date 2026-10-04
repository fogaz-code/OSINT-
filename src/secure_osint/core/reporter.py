import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from secure_osint.core.correlation import (
    DEVICE_SERIAL_RE,
    ENTITY_BUCKETS,
    build_correlations,
    collection_summary,
    format_collection_lines,
    format_pivot_lines,
    format_summary_lines,
    format_timeline_lines,
)
from secure_osint.core.dorks import build_dorks, format_dork_lines
from secure_osint.core.privacy import CATEGORIES, PrivacyGuard
from secure_osint.utils import secure_fs

LEGAL_DISCLAIMER = (
    'DISCLAIMER: This report contains publicly available information gathered via automated OSINT '
    'methods for authorized investigative or self-audit purposes only. Verification of findings and '
    'compliance with local privacy laws (e.g., GDPR) is the sole responsibility of the end user.'
)

# Marca la fine del corpo firmato in Markdown: l'hash copre tutto ciò che precede questo marcatore.
INTEGRITY_MARKER = '<!-- integrity:sha256 -->'


def canonical_json(payload: Dict[str, Any]) -> str:
    """Serializzazione deterministica per il calcolo dell'hash (chiavi ordinate, niente spazi)."""
    return json.dumps(payload, sort_keys=True, separators=(',', ':'), default=str)


def _write_private(output_path: str, content: str) -> None:
    """Atomically write a report (it holds target data) readable by the current user only.

    Delegates to secure_fs (real DACLs on Windows, where chmod is a no-op). Non-strict on purpose: on
    a destination without ACL support (FAT32/exFAT evidence drive) the report is still written, with
    a warning, rather than losing the deliverable.
    """
    secure_fs.write_private(output_path, content, strict=False)


# Behavioural probes: does this guard redact a category? Asked of the guard itself, so the answer
# does not depend on how the privacy module implements the category (rule, structured key, ...).
_CATEGORY_PROBES: Dict[str, tuple] = {
    'location': ({'latitude': 45.4642, 'longitude': 9.19}, 'GPS 45.464200, 9.190000'),
    'crypto': ('0x52908400098527886E0F7030069857D2E4169EE7', 'TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW'),
    'network': ('+39 06 1234 5678', '192.0.2.1'),
    'personal': ('probe@example.com',),
}


def _redacts(guard: PrivacyGuard, category: str) -> bool:
    """True if ``guard`` redacts ``category``; fails closed when the category is unknown here.

    Location and crypto are categories of contract C3: until the privacy module defines them,
    their entities are always redacted, never shown by default.
    """
    if category not in CATEGORIES:
        return True
    declared = getattr(guard, 'categories', None)
    if isinstance(declared, (set, frozenset, list, tuple)):
        return category in declared
    if any(getattr(rule, 'category', None) == category for rule in getattr(guard, 'rules', ())):
        return True
    return any(guard.redact_value(probe) != probe for probe in _CATEGORY_PROBES.get(category, ()))


def _placeholder(guard: PrivacyGuard, category: str) -> str:
    return f'[REDACTED:{category}]' if getattr(guard, 'label', False) else str(guard.placeholder)


class ReportGenerator:
    """Builds redacted JSON and Markdown reports with a case ID and integrity hash."""

    def __init__(self, privacy_guard: Optional[PrivacyGuard] = None, case_id: Optional[str] = None):
        """Initialize ReportGenerator."""
        self.privacy_guard = privacy_guard or PrivacyGuard()
        # ID pratica per la catena di custodia; timbrato su report e log quando presente.
        self.case_id = (case_id or '').strip() or None

    def _to_plain(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Convert step results to plain dicts (model_dump, enum status) WITHOUT redaction."""
        dict_results = {}
        for step_id, step_result in results.items():
            if hasattr(step_result, 'model_dump'):
                d = step_result.model_dump(mode='json')
            else:
                d = dict(step_result)
            if hasattr(d.get('status'), 'value'):
                d['status'] = d['status'].value
            dict_results[step_id] = d
        return dict_results

    def plain_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Step results as plain dicts, NOT redacted: input for correlation and pivot extraction only."""
        return self._to_plain(results)

    def _redact_correlations(self, correlations: Dict[str, Any]) -> Dict[str, Any]:
        """Redact each entity through the same PrivacyGuard, de-duplicating after redaction.

        Emails and IPs collapse to the placeholder unless their category is disabled (e.g.
        ``--keep-network`` reveals IPs); domains and hostnames are not PII and survive.

        Relations are resolved against each entity's RAW (pre-redaction) value, one bucket at a
        time, before that entity's own redaction runs. Two different entities (e.g. an email and an
        IP) can redact to the identical placeholder string; matching them by that shared *display*
        string afterwards would let one falsely inherit the other's relation (a redacted email
        "resolving to" a redacted IP it has nothing to do with). Resolving first, per raw value and
        per bucket, avoids that collision: an email's raw address never matches a relation that was
        only ever recorded for an IP. The bucket is kept on the output relation so the graph, which
        also only ever sees the (already redacted) display strings, can look relations up the same
        way instead of re-introducing the collision by matching on the placeholder alone.
        """
        out: Dict[str, Any] = {'primary_target': self.privacy_guard.redact(correlations['primary_target'])}
        raw_relation_types: Dict[str, str] = {}
        for relation in correlations.get('relations', []):
            raw_relation_types.setdefault(str(relation.get('to', '')), str(relation.get('type', '')))
        relations: list[Dict[str, Any]] = []
        for bucket in ENTITY_BUCKETS:
            redacted: list[str] = []
            bucket_relations: Dict[str, str] = {}
            for value in correlations.get(bucket, []):
                item = self._redact_entity(bucket, value)
                relation_type = raw_relation_types.get(str(value))
                if relation_type and item not in bucket_relations:
                    bucket_relations[item] = relation_type
                if item not in redacted:
                    redacted.append(item)
            out[bucket] = redacted
            for label, relation_type in bucket_relations.items():
                relation_item: Dict[str, Any] = {
                    'from': out['primary_target'],
                    'to': label,
                    'type': self.privacy_guard.redact(relation_type),
                    'bucket': bucket,
                }
                if relation_item not in relations:
                    relations.append(relation_item)
        out['relations'] = relations
        # Esiti per piattaforma: ogni stringa passa per lo stesso PrivacyGuard. redact_value è
        # ricorsivo: copre anche il `profile` annidato (bio, nome, URL avatar).
        out['accounts'] = [self.privacy_guard.redact_value(account) for account in correlations.get('accounts', [])]
        pivots: list[str] = []
        for pivot in correlations.get('suggested_pivots', []):
            item = self.privacy_guard.redact(pivot)
            if item not in pivots:
                pivots.append(item)
        out['suggested_pivots'] = pivots
        out['timeline'] = [self.privacy_guard.redact_value(event) for event in correlations.get('timeline', [])]
        coverage = correlations.get('timeline_coverage') or {}
        out['timeline_coverage'] = {
            'platforms_with_dates': int(coverage.get('platforms_with_dates') or 0),
            'platforms_found': int(coverage.get('platforms_found') or 0),
        }
        return out

    def _redact_entity(self, bucket: str, value: Any) -> str:
        """One entity of ``bucket`` as the report shows it.

        Phones, GPS locations and wallet addresses are replaced as a WHOLE when their category is
        redacted: free-text regexes are not reliable for every spelling (national phone formats,
        decimal coordinates), and these values are identifiers in their own right. A device keeps its
        make/model but not its serial number, which identifies one physical camera.
        """
        guard = self.privacy_guard
        text = str(value)
        if bucket == 'phones' and _redacts(guard, 'network'):
            return _placeholder(guard, 'network')
        if bucket == 'locations' and _redacts(guard, 'location'):
            return _placeholder(guard, 'location')
        if bucket == 'wallets' and _redacts(guard, 'crypto'):
            chain = text.split(' ', 1)[0] if ' ' in text else ''
            return f'{chain} {_placeholder(guard, "crypto")}'.strip()
        if bucket == 'devices':
            match = DEVICE_SERIAL_RE.search(text)
            if match and _redacts(guard, 'device'):
                name = guard.redact(text[: match.start()])
                return f'{name} (serial {_placeholder(guard, "device")})'
        return str(guard.redact(text))

    def correlations(self, results: Dict[str, Any], input_data: str) -> Dict[str, Any]:
        """Return the redacted correlation summary exactly as it appears in the reports.

        Single source of truth for the interactive graph: same data, same PrivacyGuard.
        """
        return self._redact_correlations(build_correlations(input_data, self._to_plain(results)))

    def _build(self, results: Dict[str, Any], input_data: str, workflow_name: str) -> Dict[str, Any]:
        plain_results = self._to_plain(results)
        # Le correlazioni si costruiscono dai dati grezzi, poi si redigono come il resto del report.
        correlations = self._redact_correlations(build_correlations(input_data, plain_results))
        report: Dict[str, Any] = {'timestamp': datetime.now(timezone.utc).isoformat()}
        if self.case_id:
            report['case_id'] = self.case_id
        report.update(
            {
                'input': self.privacy_guard.redact(input_data),
                'workflow': workflow_name,
                'correlations': correlations,
                'collection_summary': self.privacy_guard.redact_value(collection_summary(plain_results)),
                # Built from the REDACTED correlations: a selector the report hides never reaches a query.
                'manual_queries': build_dorks(correlations),
                'results': self.privacy_guard.redact_dict(plain_results),
                'disclaimer': LEGAL_DISCLAIMER,
            }
        )
        return report

    def generate_json(self, results: Dict[str, Any], input_data: str, workflow_name: str, output_path: str) -> str:
        """Write a redacted JSON report with a SHA-256 integrity block.

        Args:
            results: Mapping of step id to result.
            input_data: The (redacted) run input.
            workflow_name: Name of the workflow that ran.
            output_path: Destination path (written 0600).

        Returns:
            The output path.
        """
        report = self._build(results, input_data, workflow_name)
        # L'hash copre il corpo del report SENZA il campo integrity, in forma canonica: un verificatore
        # rimuove `integrity`, riserializza con canonical_json e confronta.
        report['integrity'] = {
            'algorithm': 'sha256',
            'value': hashlib.sha256(canonical_json(report).encode()).hexdigest(),
            'covers': 'canonical JSON (sorted keys) of this report excluding the integrity field',
        }
        _write_private(output_path, json.dumps(report, indent=2, default=str))
        return output_path

    def generate_markdown(self, results: Dict[str, Any], input_data: str, workflow_name: str, output_path: str) -> str:
        """Write a redacted Markdown report with a trailing SHA-256 integrity footer.

        Args:
            results: Mapping of step id to result.
            input_data: The (redacted) run input.
            workflow_name: Name of the workflow that ran.
            output_path: Destination path (written 0600).

        Returns:
            The output path.
        """
        report = self._build(results, input_data, workflow_name)
        lines = [
            f'# OSINT Report: {workflow_name}',
            f'**Generated:** {report["timestamp"]}',
        ]
        if self.case_id:
            lines.append(f'**Case ID:** {self.case_id}')
        lines.append(f'**Input:** {report["input"]}')
        lines.append('')
        lines.extend(format_summary_lines(report['correlations']))
        lines.append('')
        coverage_lines = format_collection_lines(report['collection_summary'])
        if coverage_lines:
            lines.extend(coverage_lines + [''])
        lines.extend(format_timeline_lines(report['correlations']))
        lines.append('')
        lines.extend(format_pivot_lines(report['correlations']))
        lines.append('')
        lines.extend(format_dork_lines(report['manual_queries']))
        lines.extend(['', '## Results', ''])
        for step_id, step_data in report['results'].items():
            lines.append(f'### Step: {step_id}')
            lines.append(f'**Status:** {str(step_data.get("status", "UNKNOWN")).upper()}')
            if step_data.get('error_message'):
                lines.append(f'**Error:** {step_data["error_message"]}')
            if step_data.get('data'):
                body = json.dumps(step_data['data'], indent=2, default=str)
                fence = '```'
                while fence in body:  # il contenuto non deve poter chiudere il blocco
                    fence += '`'
                lines.extend(['**Data:**', f'{fence}json', body, fence])
            lines.append('')
        lines.extend(['---', LEGAL_DISCLAIMER, ''])

        signed_body = '\n'.join(lines) + '\n'
        digest = hashlib.sha256(signed_body.encode()).hexdigest()
        footer = (
            f'{INTEGRITY_MARKER}\n**Report SHA-256:** `{digest}`\n'
            '\n_SHA-256 of all report content above this marker (integrity check)._\n'
        )
        _write_private(output_path, signed_body + footer)
        return output_path
