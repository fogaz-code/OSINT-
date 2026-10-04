import ipaddress
from typing import Any, Dict, Optional

from secure_osint.sources.base import BaseSource, SourceUnavailable, require_domain
from secure_osint.sources.registry import register_source
from secure_osint.utils.http_client import SafeHttpClient, raise_for_status, shared_client


@register_source('rdap')
class RDAPSource(BaseSource):
    """Registration data (RDAP) for a domain or IP address."""

    def __init__(self, client: Optional[SafeHttpClient] = None):
        """Initialize RDAPSource."""
        self.client = client or shared_client()

    def fetch(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Query RDAP registration data for a domain or IP and return the collected data.

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
        except ValueError:
            ip = None
        # rdap.org fa da bootstrap e redirige al server RDAP del registry/RIR competente.
        url = f'https://rdap.org/ip/{ip}' if ip else f'https://rdap.org/domain/{require_domain(params)}'
        response = self.client.get(url)
        raise_for_status(response, 'rdap.org')
        data = response.json()
        if not isinstance(data, dict):
            raise SourceUnavailable('RDAP: unexpected response format')

        extracted = {
            'handle': data.get('handle'),
            'status': data.get('status', []),
            'events': {
                ev.get('eventAction'): ev.get('eventDate') for ev in data.get('events', []) if isinstance(ev, dict)
            },
        }
        if ip:
            extracted.update({key: data.get(key) for key in ('name', 'startAddress', 'endAddress', 'country')})
        else:
            extracted['nameservers'] = [
                ns.get('ldhName') for ns in data.get('nameservers', []) if isinstance(ns, dict) and ns.get('ldhName')
            ]
        return extracted
