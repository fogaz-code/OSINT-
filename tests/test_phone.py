import json

import pytest
from typer.testing import CliRunner

from secure_osint.cli import DEFAULT_WORKFLOW_DIR
from secure_osint.core.privacy import CATEGORIES, PrivacyGuard
from secure_osint.core.reporter import ReportGenerator
from secure_osint.core.validator import detect_input_type
from secure_osint.core.workflow import load_workflow_from_file
from secure_osint.sources.base import SourceUnavailable
from secure_osint.sources.phone_source import PhoneSource
from secure_osint.sources.tool_catalog import build_catalog


def _fetch(raw, **params):
    return PhoneSource().fetch({'input': raw, **params})


def test_us_number_fields():
    data = _fetch('+14155552671')
    assert data['valid'] is True and data['possible'] is True
    assert data['country_code'] == 1 and data['region'] == 'US'
    assert data['location'] == 'San Francisco, CA'
    assert data['carrier'] is None  # '' normalised to None
    assert data['line_type'] == 'fixed_line_or_mobile'
    assert data['e164'] == '+14155552671'


def test_gb_mobile_has_carrier():
    data = _fetch('+447400123456')
    assert data['country_code'] == 44 and data['region'] == 'GB'
    assert data['carrier'] == 'Three'
    assert data['line_type'] == 'mobile'


def test_timezone_field_is_a_list_of_iana_zones():
    us = _fetch('+14155552671')
    assert us['timezone'] == ['America/Los_Angeles']
    it = _fetch('+390612345678')
    assert it['timezone'] == ['Europe/Rome']
    # A number can map to several zones (e.g. shared UK area codes): all are listed, none dropped.
    gb = _fetch('+447400123456')
    assert isinstance(gb['timezone'], list) and 'Europe/London' in gb['timezone']
    assert len(gb['timezone']) > 1


def test_toll_free_and_fixed_line_types():
    assert _fetch('+18002223333')['line_type'] == 'toll_free'
    assert _fetch('+390612345678')['line_type'] == 'fixed_line'


def test_region_param_parses_national_format():
    data = _fetch('020 7946 0018', region='GB')
    assert data['region'] == 'GB' and data['e164'] == '+442079460018'
    assert data['location'] == 'London'


def test_parseable_but_invalid_number():
    data = _fetch('+1 555 555 5555')
    assert data['possible'] is True and data['valid'] is False
    assert data['country_code'] == 1


def test_formats_us_number():
    assert _fetch('+1 (415) 555-2671')['formats'] == {
        'e164': '+14155552671',
        'international': '+1 415-555-2671',
        'national': '(415) 555-2671',
        'rfc3966': 'tel:+1-415-555-2671',
        'digits': '14155552671',
    }


def test_formats_from_national_input_with_region():
    formats = _fetch('020 7946 0018', region='GB')['formats']
    assert formats['e164'] == '+442079460018'
    assert formats['national'] == '020 7946 0018'
    assert formats['international'] == '+44 20 7946 0018'
    assert formats['rfc3966'] == 'tel:+44-20-7946-0018'
    assert formats['digits'] == '442079460018'


def test_formats_drop_extension_from_digits():
    formats = _fetch('+14155552671 ext. 123')['formats']
    assert formats['digits'] == '14155552671'
    assert formats['rfc3966'] == 'tel:+1-415-555-2671;ext=123'


def test_formats_present_for_parseable_but_invalid_number():
    formats = _fetch('+1 555 555 5555')['formats']
    assert formats['e164'] == '+15555555555' and formats['digits'] == '15555555555'


def test_existing_top_level_keys_unchanged():
    data = _fetch('+14155552671')
    assert data['e164'] == data['formats']['e164']
    assert data['international'] == data['formats']['international']


@pytest.mark.parametrize('raw', ['hello', '+15', '', 'not-a-number', '   '])
def test_unparseable_is_unavailable(raw):
    with pytest.raises(SourceUnavailable):
        _fetch(raw)


def test_source_is_offline_and_not_cached():
    # Nessun client HTTP richiesto: la fonte è 100% offline e non messa in cache.
    assert PhoneSource.cacheable is False
    assert PhoneSource().client is None


# --- redaction: number hidden by default, shown only with --keep-network ---


def _report(keep_network: bool) -> str:
    categories = CATEGORIES - {'network'} if keep_network else CATEGORIES
    guard = PrivacyGuard(categories=categories)
    results = {'phone_check': {'status': 'SUCCESS', 'data': _fetch('+447400123456')}}
    import tempfile
    import os

    fd, path = tempfile.mkstemp(suffix='.json')
    os.close(fd)
    try:
        ReportGenerator(guard).generate_json(results, '+447400123456', 'phone', path)
        with open(path, encoding='utf-8') as fh:
            return fh.read()
    finally:
        os.unlink(path)


def test_number_redacted_by_default():
    text = _report(keep_network=False)
    assert '+447400123456' not in text
    assert '[REDACTED]' in text
    # Country and carrier survive so the report is still useful.
    assert 'Three' in text and '"country_code": 44' in text
    assert '"region": "GB"' in text


def test_e164_international_rfc3966_formats_redacted_by_default():
    guard = PrivacyGuard()
    for raw in ('+14155552671', '+447400123456', '+33612345678'):
        formats = _fetch(raw)['formats']
        for key in ('e164', 'international', 'rfc3966'):
            assert '[REDACTED]' in guard.redact(formats[key]), (raw, key)


def test_every_format_redacted_by_default():
    # Bare digits and national layouts have no safe regex: the guard redacts them by key (phone record).
    guard = PrivacyGuard()
    for raw in ('+14155552671', '+447400123456', '+33612345678'):
        data = _fetch(raw)
        redacted = json.dumps(guard.redact_dict(data))
        for key, value in data['formats'].items():
            assert value not in redacted, (raw, key, value)
        assert data['carrier'] is None or data['carrier'] in redacted  # the useful fields survive


def test_every_format_shown_with_keep_network():
    guard = PrivacyGuard(categories={'secrets', 'personal', 'location', 'crypto'})
    data = _fetch('+14155552671')
    assert guard.redact_dict(data)['formats'] == data['formats']


def test_number_shown_with_keep_network():
    text = _report(keep_network=True)
    assert '+447400123456' in text
    assert 'Three' in text


def test_phone_rule_is_network_category():
    # Il numero è un identificativo "network-like": redatto di default, svelato con --keep-network.
    assert PrivacyGuard(categories={'personal', 'secrets'}).redact('call +447400123456') == 'call +447400123456'
    assert '[REDACTED]' in PrivacyGuard(categories={'network'}).redact('call +447400123456')


# --- routing + workflow ---


@pytest.mark.parametrize(
    'value,expected',
    [
        ('+14155552671', 'phone'),
        ('+442079460018', 'phone'),
        ('+39 06 1234 5678', 'phone'),
    ],
)
def test_detect_phone_input_type(value, expected):
    assert detect_input_type(value) == expected


def test_plain_digits_not_auto_phone():
    # Senza '+' resta ambiguo: non lo classifichiamo come phone in auto-detect.
    assert detect_input_type('4155552671') != 'phone'


def test_registered_and_in_workflow():
    assert 'phone' in build_catalog(load_plugins=False)
    wf = load_workflow_from_file(f'{DEFAULT_WORKFLOW_DIR}/phone.yaml')
    assert wf.name == 'phone_recon'
    assert [s.type for s in wf.steps] == ['phone']


def test_cli_routes_phone(tmp_path):
    from secure_osint.cli import app

    result = CliRunner().invoke(app, ['dry-run', '+14155552671'])
    assert result.exit_code == 0
    assert 'workflow: phone' in result.output
