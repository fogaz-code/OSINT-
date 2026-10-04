"""v1.1.0: confidenza per piattaforma, soft 404, PyPI via XML-RPC, metadati pubblici, pivot suggeriti.

Il bug di partenza (confermato dal vivo con `nosuchuser123456789`): TikTok, Pinterest e PyPI
rispondevano HTTP 200 anche per utenti inesistenti e lo strumento li segnava "exists: true".
"""

import json
import xmlrpc.client

import pytest

from secure_osint.core.correlation import build_correlations, format_pivot_lines, format_summary_lines
from secure_osint.core.graph import FILTERS, graph_elements, graph_model
from secure_osint.core.reporter import ReportGenerator
from secure_osint.sources.base import SourceError
from secure_osint.sources.username_source import (
    CHALLENGE_MSG,
    PYPI_NO_PACKAGES_MSG,
    SOFT_404_MSG,
    UNCALIBRATED_MSG,
    UsernameSource,
)
from tests.test_sources import ok
from tests.test_username import ScriptedClient, _all_absent, only_for, xmlrpc_packages


def _run(by_host, username='alice'):
    client = ScriptedClient(by_host)
    return UsernameSource(client).fetch({'input': username}), client


# --- soft 404 (the live bug) ---


def test_tiktok_soft_404_is_not_reported_as_existing():
    # TikTok answers 200 with a generic page for ANY username: no signal, so never "exists".
    by = _all_absent()
    by['www.tiktok.com'] = ok('<html>generic app shell</html>', 200)
    data, client = _run(by, 'nosuchuser123456789')
    tiktok = data['platforms']['tiktok']
    assert tiktok['exists'] is None and tiktok['confidence'] == 'MANUAL'
    assert tiktok['error'] == SOFT_404_MSG
    assert sum('tiktok' in u for u in client.urls_called) == 2  # the target plus one calibration probe


def test_pinterest_soft_404_is_not_reported_as_existing():
    by = _all_absent()
    by['www.pinterest.com'] = ok('<html>pinterest shell</html>', 200)
    data, _ = _run(by, 'nosuchuser123456789')
    assert data['platforms']['pinterest']['exists'] is None
    assert data['platforms']['pinterest']['error'] == SOFT_404_MSG


@pytest.mark.parametrize(
    'host,name,body',
    [
        ('www.tiktok.com', 'tiktok', "<p>Couldn't find this account</p>"),
        ('www.tiktok.com', 'tiktok', '<p>Couldn&#39;t find this account</p>'),
        ('www.pinterest.com', 'pinterest', "<h1>Sorry! We couldn't find that page</h1>"),
    ],
)
def test_not_found_text_on_a_200_page_means_absent(host, name, body):
    by = _all_absent()
    by[host] = ok(body, 200)
    data, _ = _run(by)
    assert data['platforms'][name]['exists'] is False


def test_calibrated_web_page_is_medium_confidence():
    by = _all_absent()
    by['www.pinterest.com'] = only_for('alice', ok('<html>alice boards</html>'), ok('', 404))
    data, _ = _run(by)
    assert data['platforms']['pinterest']['exists'] is True
    assert data['platforms']['pinterest']['confidence'] == 'MEDIUM'


def test_failed_calibration_downgrades_to_low():
    by = _all_absent()
    by['www.tiktok.com'] = only_for('alice', ok('<html>alice</html>'), SourceError('probe failed'))
    data, _ = _run(by)
    tiktok = data['platforms']['tiktok']
    assert tiktok['exists'] is True and tiktok['confidence'] == 'LOW'
    assert tiktok['error'] == UNCALIBRATED_MSG


def test_calibration_uses_a_random_non_target_username():
    by = _all_absent()
    by['codepen.io'] = only_for('alice', ok('<html>alice</html>'), ok('', 404))
    _, first = _run(by)
    _, second = _run(by)
    probes = [
        u.rsplit('/', 1)[-1] for c in (first, second) for u in c.urls_called if 'codepen' in u and 'alice' not in u
    ]
    assert len(probes) == 2 and probes[0] != probes[1]  # a new random control username per run
    assert all(p.startswith('zz') and p != 'alice' for p in probes)


def test_json_apis_are_not_calibrated_and_are_high():
    by = _all_absent()
    by['api.github.com'] = ok({'login': 'alice'})
    data, client = _run(by)
    assert data['platforms']['github']['confidence'] == 'HIGH'
    assert sum('api.github.com' in u for u in client.urls_called) == 1  # no extra probe for APIs


def test_anti_bot_challenge_page_is_manual_not_found():
    by = _all_absent()
    by['codepen.io'] = ok('<html><title>Client Challenge</title></html>', 200)
    data, _ = _run(by)
    assert data['platforms']['codepen']['exists'] is None
    assert data['platforms']['codepen']['error'] == CHALLENGE_MSG


def test_stack_overflow_name_search_is_low():
    by = _all_absent()
    by['api.stackexchange.com'] = ok({'total': 4})
    data, _ = _run(by)
    assert data['platforms']['stackoverflow']['exists'] is True
    assert data['platforms']['stackoverflow']['confidence'] == 'LOW'


def test_auth_walled_platforms_are_manual():
    data, _ = _run(_all_absent())
    assert all(data['platforms'][p]['confidence'] == 'MANUAL' for p in ('linkedin', 'instagram', 'facebook', 'x'))


# --- PyPI ---


def test_pypi_uses_xmlrpc_user_packages_not_the_project_api():
    by = _all_absent()
    by['pypi.org'] = xmlrpc_packages([['Owner', 'alice-tools'], ['Maintainer', 'other']])
    data, client = _run(by)
    pypi = data['platforms']['pypi']
    assert pypi['exists'] is True and pypi['confidence'] == 'HIGH'
    assert pypi['profile'] == {'packages': 2}
    url, body = client.posted[0]
    assert url == 'https://pypi.org/pypi'
    assert xmlrpc.client.loads(body) == (('alice',), 'user_packages')
    assert not any('/json' in u for u in client.urls_called)  # never the project JSON API


def test_pypi_without_packages_is_not_found_with_caveat():
    data, _ = _run(_all_absent())  # _all_absent answers user_packages with []
    pypi = data['platforms']['pypi']
    assert pypi['exists'] is False and pypi['confidence'] == 'MEDIUM'
    assert pypi['error'] == PYPI_NO_PACKAGES_MSG


@pytest.mark.parametrize('body', ['<html><title>Client Challenge</title></html>', 'not xml', '<a/>'])
def test_pypi_unexpected_response_is_manual_never_found(body):
    by = _all_absent()
    by['pypi.org'] = ok(body, 200)
    data, _ = _run(by)
    assert data['platforms']['pypi']['exists'] is None
    assert data['platforms']['pypi']['confidence'] == 'MANUAL'


# --- enriched public metadata ---


def test_github_profile_metadata_and_avatar_url_only():
    by = _all_absent()
    by['api.github.com'] = ok(
        {
            'login': 'alice',
            'name': 'Alice Example',
            'bio': 'Builder of <b>things</b>\x07',
            'created_at': '2015-03-01T10:00:00Z',
            'avatar_url': 'https://avatars.githubusercontent.com/u/1?v=4',
            'email': 'alice@example.com',
        }
    )
    data, client = _run(by)
    assert data['platforms']['github']['profile'] == {
        'display_name': 'Alice Example',
        'bio': 'Builder of things',  # HTML and control characters stripped
        'created_at': '2015-03-01T10:00:00Z',
        'avatar_url': 'https://avatars.githubusercontent.com/u/1?v=4',
    }
    assert 'avatars.githubusercontent.com' not in client.hosts_called  # the image is never downloaded
    assert 'email' not in data['platforms']['github']['profile']  # not collected


def test_keybase_profile_metadata():
    by = _all_absent()
    by['keybase.io'] = ok(
        {
            'them': [
                {
                    'profile': {'full_name': 'Alice K', 'bio': 'crypto'},
                    'basics': {'ctime': 1420070400},
                    'pictures': {'primary': {'url': 'https://s3.amazonaws.com/keybase/alice.jpg'}},
                }
            ]
        }
    )
    data, _ = _run(by)
    assert data['platforms']['keybase']['profile'] == {
        'display_name': 'Alice K',
        'bio': 'crypto',
        'created_at': '2015-01-01T00:00:00Z',
        'avatar_url': 'https://s3.amazonaws.com/keybase/alice.jpg',
    }


def test_profile_sanitising_limits_and_https_only_avatar():
    by = _all_absent()
    by['api.github.com'] = ok({'name': 'A', 'bio': 'x' * 1000, 'avatar_url': 'javascript:alert(1)'})
    data, _ = _run(by)
    profile = data['platforms']['github']['profile']
    assert len(profile['bio']) == 280 and 'avatar_url' not in profile


def test_dockerhub_never_records_gravatar_email():
    by = _all_absent()
    by['hub.docker.com'] = ok({'full_name': 'Alice D', 'date_joined': '2019-01-01', 'gravatar_email': 'a@b.co'})
    data, _ = _run(by)
    assert data['platforms']['dockerhub']['profile'] == {'display_name': 'Alice D', 'created_at': '2019-01-01'}


def test_hackernews_about_html_and_unix_created():
    by = _all_absent()
    by['hacker-news.firebaseio.com'] = ok(
        {'id': 'alice', 'about': 'Hi &amp; <a href="x">link</a>', 'created': 1200000000}
    )
    data, _ = _run(by)
    assert data['platforms']['hackernews']['profile'] == {'bio': 'Hi & link', 'created_at': '2008-01-10T21:20:00Z'}


# --- correlations, report, pivots ---


def _results(**platforms):
    return {'u': {'status': 'SUCCESS', 'data': {'username': 'alice', 'platforms': platforms}}}


def _p(exists, confidence, profile=None, label='X'):
    entry = {'exists': exists, 'error': None, 'url': f'https://ex/{label}', 'label': label, 'confidence': confidence}
    if profile:
        entry['profile'] = profile
    return entry


def test_summary_reports_confidence_counts():
    corr = ReportGenerator().correlations(
        _results(
            github=_p(True, 'HIGH', label='GitHub'),
            tiktok=_p(True, 'MEDIUM', label='TikTok'),
            pinterest=_p(True, 'MEDIUM', label='Pinterest'),
            stackoverflow=_p(True, 'LOW', label='Stack Overflow'),
            gitlab=_p(False, 'HIGH', label='GitLab'),
        ),
        'alice',
    )
    text = '\n'.join(format_summary_lines(corr))
    assert '**Username found on:** 4 platform(s) (1 High, 2 Medium, 1 Low confidence)' in text
    assert 'Low confidence (verify manually): `Stack Overflow`' in text
    assert '**Checked, not found:** 1 platform(s)' in text


def test_profile_pii_is_redacted_in_the_report():
    corr = ReportGenerator().correlations(
        _results(github=_p(True, 'HIGH', {'display_name': 'Alice', 'bio': 'mail alice@example.com'}, 'GitHub')), 'alice'
    )
    assert 'alice@example.com' not in json.dumps(corr)
    assert corr['accounts'][0]['profile']['bio'] == 'mail [REDACTED]'


def test_pivots_suggest_names_usernames_and_emails():
    results = _results(
        github=_p(True, 'HIGH', {'display_name': 'Alice Example'}, 'GitHub'),
        keybase=_p(True, 'HIGH', {'display_name': 'Alice Example'}, 'Keybase'),
        gitlab=_p(False, 'HIGH', {'display_name': 'Not Her'}, 'GitLab'),  # not found: no pivot
    )
    results['repo'] = {'status': 'SUCCESS', 'data': {'login': 'alice-work', 'username': 'alice-work'}}
    pivots = build_correlations('alice', results)['suggested_pivots']
    assert 'Name: Alice Example (from GitHub, Keybase)' in pivots
    assert 'Username: alice-work' in pivots
    assert not any('Not Her' in p for p in pivots)
    assert not any(p.lower().endswith(': alice') for p in pivots)  # never the target itself


def test_soa_contact_becomes_an_email_pivot_but_stays_redacted_in_report():
    dns = {
        'dns': {'status': 'SUCCESS', 'data': {'SOA': {'mname': 'ns1.example.com', 'rname': 'hostmaster.example.com.'}}}
    }
    raw = build_correlations('example.com', dns)['suggested_pivots']
    assert 'Email: hostmaster@example.com (DNS SOA contact)' in raw
    reported = ReportGenerator().correlations(dns, 'example.com')['suggested_pivots']
    assert reported == ['Email: [REDACTED] (DNS SOA contact)']  # emails are always redacted


def test_markdown_has_suggested_pivots_section(tmp_path):
    results = _results(github=_p(True, 'HIGH', {'display_name': 'Alice Example'}, 'GitHub'))
    out = tmp_path / 'r.md'
    ReportGenerator().generate_markdown(results, 'alice', 'username', str(out))
    text = out.read_text(encoding='utf-8')
    assert '## Suggested Pivots' in text and 'Name: Alice Example (from GitHub)' in text
    assert 'does **not** run them' in text
    assert text.index('## Suggested Pivots') < text.index('## Results')


def test_no_pivots_means_none_identified():
    assert '_none identified_' in format_pivot_lines({'suggested_pivots': []})


def test_pivots_are_never_run_automatically(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from secure_osint.cli import app
    from secure_osint.core.workflow import StepResult, StepStatus

    calls = []

    def execute(self, wf, inp):
        calls.append(inp)
        data = {'username': inp, 'platforms': {'github': _p(True, 'HIGH', {'display_name': 'Alice Example'}, 'GitHub')}}
        return {'u': StepResult(status=StepStatus.SUCCESS, data=data)}

    monkeypatch.setattr('secure_osint.core.engine.WorkflowEngine.execute', execute)
    result = CliRunner().invoke(app, ['run', 'alice', '--no-cache', '-q', '--output-dir', str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert 'Name: Alice Example' in (tmp_path / 'latest.md').read_text(encoding='utf-8')  # suggested...
    assert calls == ['alice']  # ...but only the requested investigation ran


# --- graph ---


def _graph_corr():
    return ReportGenerator().correlations(
        _results(
            github=_p(
                True,
                'HIGH',
                {'display_name': 'Alice Example', 'bio': 'Builder', 'avatar_url': 'https://a/1.png'},
                'GitHub',
            ),
            tiktok=_p(True, 'MEDIUM', label='TikTok'),
            stackoverflow=_p(True, 'LOW', label='Stack Overflow'),
        ),
        'alice',
    )


def test_graph_tooltips_show_profile_and_confidence():
    nodes, _ = graph_elements(_graph_corr())
    github = next(n for n in nodes if n['id'] == 'account:github')
    for line in (
        'Confidence: HIGH',
        'Name: Alice Example',
        'Bio: Builder',
        'Avatar (URL only, not downloaded): https://a/1.png',
    ):
        assert line in github['title']
    low = next(n for n in nodes if n['id'] == 'account:stackoverflow')
    assert low['label'].endswith('(low confidence)') and 'Low confidence: verify manually' in low['title']


def test_graph_never_renders_avatar_images():
    nodes, _ = graph_elements(_graph_corr(), filters=FILTERS)
    assert all(n.get('shape') not in ('image', 'circularImage') and 'image' not in n for n in nodes)


def test_graph_pivot_nodes_are_distinct_and_filterable():
    model = graph_model(_graph_corr())
    pivot = next(n for n in model['nodes'] if n['category'] == 'pivots')
    assert pivot['label'] == 'Suggested Pivot: Name: Alice Example (from GitHub)'
    assert pivot['shapeProperties'] == {'borderDashes': [5, 5]} and pivot['color']['border'] == '#9ca3af'
    assert 'not run automatically' in pivot['title']
    shown, _ = graph_elements(_graph_corr())
    hidden, _ = graph_elements(_graph_corr(), filters=[f for f in FILTERS if f != 'pivots'])
    assert any(n['category'] == 'pivots' for n in shown) and not any(n['category'] == 'pivots' for n in hidden)


def test_rendered_pivot_graph_is_offline(tmp_path):
    pytest.importorskip('pyvis')
    import re

    from secure_osint.core.graph import build_correlation_graph, save_graph_html

    html = save_graph_html(build_correlation_graph(_graph_corr()), tmp_path / 'g.html').read_text(encoding='utf-8')
    assert 'Suggested Pivot: Name: Alice Example' in html
    assert not re.search(r'(?:src|href)\s*=\s*["\']https?://', html, re.IGNORECASE)
    assert '<img' not in html
