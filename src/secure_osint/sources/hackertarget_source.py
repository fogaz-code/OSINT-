from typing import Any, Dict, Optional

from secure_osint.sources.base import BaseSource, SourceUnavailable, require_domain
from secure_osint.sources.registry import register_source
from secure_osint.utils.http_client import SafeHttpClient, raise_for_status, shared_client


@register_source('hackertarget')
class HackerTargetSource(BaseSource):
    """Reverse-DNS / host search for a domain via the HackerTarget API."""

    def __init__(self, client: Optional[SafeHttpClient] = None):
        """Initialize HackerTargetSource."""
        self.client = client or shared_client()

    def fetch(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Query HackerTarget host search for a domain and return the collected data.

        Args:
            params: Step parameters; always includes ``input`` (the target) and ``upstream``.

        Returns:
            A dict of results specific to this source.

        Raises:
            SourceUnavailable: Permanent failure (invalid input, 404, blocked, missing key).
            TransientSourceError: Temporary failure worth retrying (timeout, 429, 5xx).
        """
        domain = require_domain(params)
        # Host Search API (gratuita, no key, quota giornaliera). Risponde in testo: "hostname,ip".
        response = self.client.get('https://api.hackertarget.com/hostsearch/', params={'q': domain})
        raise_for_status(response, 'api.hackertarget.com')
        text = response.text.strip()

        hosts = []
        for line in text.splitlines():
            hostname, sep, ip = line.partition(',')
            if sep:
                hosts.append({'hostname': hostname.strip(), 'ip': ip.strip()})
        if not hosts and text:
            # Nessuna riga "host,ip": il corpo è un messaggio di errore/quota dell'API.
            raise SourceUnavailable(f'hackertarget: {text[:120]}')
        return {'hosts_found': len(hosts), 'hosts': hosts}
