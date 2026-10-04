import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Tuple, Union

import dns.exception
import dns.resolver

from secure_osint.sources.base import BaseSource, SourceUnavailable, TransientSourceError, require_domain
from secure_osint.sources.registry import register_source

_TEMPORARY_FAILURES = {getattr(socket, 'EAI_AGAIN', None)} - {None}


def _name(value: Any) -> str:
    return value.to_text(omit_final_dot=True)


def _format(rdtype: str, rdata: Any) -> Any:
    if rdtype == 'MX':
        return {'preference': rdata.preference, 'exchange': _name(rdata.exchange)}
    if rdtype in ('NS', 'CNAME'):
        return _name(rdata.target)
    if rdtype == 'TXT':
        # Un record TXT può essere spezzato in più stringhe da 255 byte: vanno concatenate.
        return b''.join(rdata.strings).decode('utf-8', errors='replace')
    if rdtype == 'SOA':
        return {
            'mname': _name(rdata.mname),
            'rname': _name(rdata.rname),
            'serial': rdata.serial,
            'refresh': rdata.refresh,
            'retry': rdata.retry,
            'expire': rdata.expire,
            'minimum': rdata.minimum,
        }
    return rdata.to_text()


@register_source('dns')
class DNSSource(BaseSource):
    """A/AAAA dal resolver di sistema (getaddrinfo), CNAME/MX/NS/TXT/SOA con dnspython.

    Ogni tipo di record fallisce in modo indipendente: un timeout sul TXT (tipico con risposte
    grandi e TCP bloccato) finisce in `errors` senza far fallire lo step.
    """

    RECORD_TYPES = ('CNAME', 'MX', 'NS', 'TXT', 'SOA')

    def __init__(self, lifetime: float = 5.0):
        """Initialize DNSSource."""
        self.lifetime = lifetime

    def _addresses(self, domain: str, results: Dict[str, Any], errors: Dict[str, str]) -> None:
        for family, record in ((socket.AF_INET, 'A'), (socket.AF_INET6, 'AAAA')):
            try:
                infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
            except socket.gaierror as e:
                if e.errno in _TEMPORARY_FAILURES:
                    errors[record] = f'temporary failure: {e}'
                continue
            for info in infos:
                ip = str(info[4][0])
                if ip not in results[record]:
                    results[record].append(ip)

    def _query(self, domain: str, rdtype: str) -> Tuple[str, Union[List[Any], Exception]]:
        try:
            answer = dns.resolver.resolve(domain, rdtype, lifetime=self.lifetime)
        except dns.exception.DNSException as e:
            return rdtype, e
        records = [_format(rdtype, rdata) for rdata in answer]
        if rdtype == 'MX':
            records.sort(key=lambda mx: (mx['preference'], mx['exchange']))
        return rdtype, records

    def fetch(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Query DNS records (A/AAAA via the system resolver, others via dnspython) and return the collected data.

        Args:
            params: Step parameters; always includes ``input`` (the target) and ``upstream``.

        Returns:
            A dict of results specific to this source.

        Raises:
            SourceUnavailable: Permanent failure (invalid input, 404, blocked, missing key).
            TransientSourceError: Temporary failure worth retrying (timeout, 429, 5xx).
        """
        domain = require_domain(params)
        results: Dict[str, Any] = {'A': [], 'AAAA': [], 'CNAME': [], 'MX': [], 'NS': [], 'TXT': [], 'SOA': None}
        errors: Dict[str, str] = {}
        self._addresses(domain, results, errors)

        # Query in parallelo: il caso peggiore è un solo `lifetime`, non 5.
        with ThreadPoolExecutor(max_workers=len(self.RECORD_TYPES)) as pool:
            outcomes = list(pool.map(lambda t: self._query(domain, t), self.RECORD_TYPES))

        for rdtype, records in outcomes:
            if isinstance(records, dns.resolver.NXDOMAIN):
                raise SourceUnavailable(f'NXDOMAIN: {domain} does not exist') from records
            if isinstance(records, dns.resolver.NoAnswer):
                continue
            if isinstance(records, dns.exception.Timeout):
                errors[rdtype] = 'timeout'
                continue
            if isinstance(records, Exception):
                errors[rdtype] = type(records).__name__
                continue
            if rdtype == 'SOA':
                results['SOA'] = records[0] if records else None
            else:
                results[rdtype] = records

        has_records = any(results[k] for k in ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA'))
        if not has_records:
            if errors:
                raise TransientSourceError(f'DNS resolution failed: {errors}')
            raise SourceUnavailable('No DNS records found')
        results['errors'] = errors
        return results
