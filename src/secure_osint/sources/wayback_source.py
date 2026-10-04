from typing import Any, Dict, Optional

from secure_osint.sources.base import BaseSource, SourceUnavailable, require_domain
from secure_osint.sources.registry import register_source
from secure_osint.utils.http_client import SafeHttpClient, raise_for_status, shared_client


@register_source('wayback')
class WaybackSource(BaseSource):
    """Archived URLs for a domain from the Wayback Machine CDX API."""

    QUERY_LIMIT = 50
    SAMPLE_SIZE = 20

    def __init__(self, client: Optional[SafeHttpClient] = None):
        """Initialize WaybackSource."""
        self.client = client or shared_client()

    def fetch(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Query Wayback Machine archived URLs for a domain and return the collected data.

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
            'https://web.archive.org/cdx/search/cdx',
            params={
                'url': f'*.{domain}/*',
                'output': 'json',
                'fl': 'original',
                'collapse': 'urlkey',
                'limit': self.QUERY_LIMIT,
            },
            timeout=30.0,
        )
        raise_for_status(response, 'web.archive.org')
        data = response.json() if response.content.strip() else []
        if not isinstance(data, list):
            raise SourceUnavailable('wayback: unexpected response format')

        # Il primo elemento è l'header, il resto sono righe [original].
        rows = data[1:]
        urls = sorted({row[0] for row in rows if isinstance(row, list) and row})
        return {
            'unique_urls_returned': len(urls),
            'truncated': len(rows) >= self.QUERY_LIMIT,
            'sample_urls': urls[: self.SAMPLE_SIZE],
        }
