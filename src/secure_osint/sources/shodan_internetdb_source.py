import ipaddress
from typing import Any, Dict, List, Optional

from secure_osint.security.ssrf_guard import is_public_ip
from secure_osint.sources.base import BaseSource, SourceUnavailable
from secure_osint.sources.registry import register_source
from secure_osint.utils.http_client import SafeHttpClient, raise_for_status, shared_client

FIELDS = ('ports', 'hostnames', 'cpes', 'tags', 'vulns')


def _list(value: Any) -> List[Any]:
    """Lista ordinata e deduplicata; qualsiasi forma inattesa diventa lista vuota."""
    if not isinstance(value, list):
        return []
    items = {v for v in value if isinstance(v, (str, int)) and not isinstance(v, bool)}
    return sorted(items, key=lambda v: (isinstance(v, str), v))


@register_source('shodan_internetdb')
class ShodanInternetDBSource(BaseSource):
    """Shodan InternetDB: porte aperte, CVE, hostname, CPE e tag per un IP pubblico. Nessuna API key.

    Dati aggiornati settimanalmente da Shodan, non una scansione live. 404 = IP mai visto (risultato valido).
    Rate limit applicato: 1 richiesta/secondo (HostPolicies), per rispetto del servizio gratuito.
    """

    API = 'https://internetdb.shodan.io'

    def __init__(self, client: Optional[SafeHttpClient] = None):
        """Initialize ShodanInternetDBSource."""
        self.client = client or shared_client()

    def fetch(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Query Shodan InternetDB exposure for a public IP and return the collected data.

        Args:
            params: Step parameters; always includes ``input`` (the target) and ``upstream``.

        Returns:
            A dict of results specific to this source.

        Raises:
            SourceUnavailable: Permanent failure (invalid input, 404, blocked, missing key).
            TransientSourceError: Temporary failure worth retrying (timeout, 429, 5xx).
        """
        raw = self.require_input(params)
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError as e:
            raise SourceUnavailable(f'Invalid IP address: {raw!r}') from e
        if not is_public_ip(ip):
            # Shodan non ha dati su reti private: inviarle servirebbe solo a rivelare la topologia interna.
            raise SourceUnavailable(f'Not a public IP address: {ip}')

        response = self.client.get(f'{self.API}/{ip.compressed}', timeout=10.0)
        if response.status_code == 404:
            return {'ip': ip.compressed, 'found': False, **{f: [] for f in FIELDS}}
        raise_for_status(response, 'internetdb.shodan.io')
        data = response.json()
        if not isinstance(data, dict):
            raise SourceUnavailable('internetdb: unexpected response format')
        return {'ip': ip.compressed, 'found': True, **{f: _list(data.get(f)) for f in FIELDS}}
