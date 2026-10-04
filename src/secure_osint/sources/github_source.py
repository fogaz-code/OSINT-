import re
from typing import Any, Dict, Optional
from urllib.parse import quote

from secure_osint.config import get_api_key
from secure_osint.sources.base import BaseSource, SourceUnavailable
from secure_osint.sources.registry import register_source
from secure_osint.utils.http_client import HttpResponse, SafeHttpClient, raise_for_status, shared_client

_NAME = re.compile(r'^[A-Za-z0-9_.-]{1,100}$')


@register_source('github')
class GitHubSource(BaseSource):
    """GitHub lookups: repository metadata for ``owner/repo`` or a user search."""

    API = 'https://api.github.com'

    def __init__(self, client: Optional[SafeHttpClient] = None):
        """Initialize GitHubSource."""
        self.client = client or shared_client()

    def _headers(self) -> Dict[str, str]:
        headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}
        token = get_api_key('GITHUB_TOKEN')
        if token:
            headers['Authorization'] = f'Bearer {token}'
        return headers

    def _check(self, response: HttpResponse) -> None:
        if response.status_code in (403, 429) and response.headers.get('x-ratelimit-remaining') == '0':
            # Il reset può essere tra un'ora: riprovare subito è inutile.
            raise SourceUnavailable('GitHub API rate limit exceeded (set GITHUB_TOKEN)')
        raise_for_status(response, 'api.github.com')

    def fetch(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Query GitHub (repository metadata or user search) and return the collected data.

        Args:
            params: Step parameters; always includes ``input`` (the target) and ``upstream``.

        Returns:
            A dict of results specific to this source.

        Raises:
            SourceUnavailable: Permanent failure (invalid input, 404, blocked, missing key).
            TransientSourceError: Temporary failure worth retrying (timeout, 429, 5xx).
        """
        query = self.require_input(params)
        if '/' in query:
            owner, _, repo = query.partition('/')
            if not (_NAME.match(owner) and _NAME.match(repo)):
                raise SourceUnavailable('Invalid owner/repo')
            response = self.client.get(f'{self.API}/repos/{quote(owner)}/{quote(repo)}', headers=self._headers())
            self._check(response)
            data = response.json()
            return {
                'kind': 'repository',
                'full_name': data.get('full_name'),
                'description': data.get('description'),
                'html_url': data.get('html_url'),
                'language': data.get('language'),
                'stargazers_count': data.get('stargazers_count'),
                'forks_count': data.get('forks_count'),
                'archived': data.get('archived'),
                'created_at': data.get('created_at'),
                'pushed_at': data.get('pushed_at'),
                'license': (data.get('license') or {}).get('spdx_id'),
            }

        response = self.client.get(
            f'{self.API}/search/users', params={'q': query, 'per_page': 5}, headers=self._headers()
        )
        self._check(response)
        data = response.json()
        # La search API non restituisce followers/public_repos: servirebbe una chiamata per utente.
        matches = [
            {'login': u.get('login'), 'html_url': u.get('html_url'), 'type': u.get('type')}
            for u in data.get('items', [])[:5]
            if isinstance(u, dict)
        ]
        return {'kind': 'user_search', 'total_count': data.get('total_count', 0), 'top_matches': matches}
