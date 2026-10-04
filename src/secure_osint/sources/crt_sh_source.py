import re
from typing import Any, Dict, Optional

from secure_osint.sources.base import BaseSource, SourceUnavailable, require_domain
from secure_osint.sources.registry import register_source
from secure_osint.utils.http_client import SafeHttpClient, raise_for_status, shared_client


# crt.sh 'not_before' values are naive ISO timestamps; only that exact shape is trusted, so a plain string
# comparison orders them correctly.
_NOT_BEFORE = re.compile(r'\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2})?')


@register_source('crt_sh')
class CRTshSource(BaseSource):
    # crt.sh è lento su domini con molti certificati: 30-60s sono normali.
    """Subdomain enumeration via crt.sh certificate transparency logs."""

    TIMEOUT = 60.0

    def __init__(self, client: Optional[SafeHttpClient] = None):
        """Initialize CRTshSource."""
        self.client = client or shared_client()

    def fetch(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Query crt.sh certificate transparency (subdomains for a domain) and return the collected data.

        Args:
            params: Step parameters; always includes ``input`` (the target) and ``upstream``.

        Returns:
            A dict of results specific to this source.

        Raises:
            SourceUnavailable: Permanent failure (invalid input, 404, blocked, missing key).
            TransientSourceError: Temporary failure worth retrying (timeout, 429, 5xx).
        """
        domain = require_domain(params)
        response = self.client.get(
            'https://crt.sh/', params={'q': f'%.{domain}', 'output': 'json'}, timeout=self.TIMEOUT
        )
        raise_for_status(response, 'crt.sh')
        data = response.json()
        if not isinstance(data, list):
            raise SourceUnavailable('crt.sh: unexpected response format')

        subdomains = set()
        earliest: Optional[str] = None
        for entry in data:
            if not isinstance(entry, dict):
                continue
            not_before = entry.get('not_before')
            if isinstance(not_before, str) and _NOT_BEFORE.fullmatch(not_before):
                earliest = not_before if earliest is None else min(earliest, not_before)
            # name_value può contenere più nomi separati da newline, anche wildcard.
            for name in str(entry.get('name_value', '')).split('\n'):
                clean_name = name.strip().lower().removeprefix('*.')
                if clean_name != domain and clean_name.endswith('.' + domain):
                    subdomains.add(clean_name)
        # earliest_certificate feeds the correlation timeline (C9): first certificate logged for the domain.
        return {'subdomains_found': len(subdomains), 'subdomains': sorted(subdomains), 'earliest_certificate': earliest}
