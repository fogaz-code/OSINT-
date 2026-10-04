"""ReDoS regression tests: every redaction regex runs over attacker-controlled text.

Remote bios, DNS TXT records, HTML titles and exception messages all reach PrivacyGuard. A pattern
with catastrophic (or merely quadratic) backtracking turns a crafted 50 kB profile into a CPU hang of
the whole run, so every rule is timed against adversarial near-miss inputs.
"""

import time

import pytest

from secure_osint.core import privacy
from secure_osint.core.privacy import RULES, PrivacyGuard

SIZE = 50_000
# Linear patterns finish these inputs in a few milliseconds; quadratic ones take seconds.
PER_RULE_BUDGET = 0.5
WHOLE_GUARD_BUDGET = 3.0


def _fill(unit: str, size: int = SIZE) -> str:
    return (unit * (size // len(unit) + 1))[:size]


ADVERSARIAL = {
    'letters': _fill('a'),
    'digits': _fill('1'),
    'hex': _fill('f'),
    'spaces': _fill(' '),
    'digit_space': _fill('1 '),
    'digit_dot': _fill('1.'),
    'digit_colon': _fill('1:'),
    'colons': _fill(':'),
    'hex_colon': _fill('a:'),
    'space_colon': _fill(': '),
    'email_local_run': _fill('a.') + '@',
    'email_at_chain': _fill('a@'),
    'email_domain_dots': 'x@' + _fill('a.'),
    'email_no_tld': _fill('a') + '@' + _fill('b'),
    'jwt_dash_chain': _fill('eyJ-'),
    'jwt_dot_chain': _fill('eyJa.'),
    'jwt_no_second_part': 'eyJ' + _fill('a') + '.',
    'pem_headers_without_end': _fill('-----BEGIN PRIVATE KEY-----\nMIIabc\n'),
    'pem_header_spaces': '-----BEGIN ' + _fill('A ') + 'x',
    'phone_plus_chain': _fill('+12345678901234567890x '),
    'phone_plus_groups': _fill('+1 (23) 45-67 89x '),
    'phone_paren_chain': _fill('(0123) '),
    'phone_trailing_dash': _fill('+39 333 1234567-'),
    'card_digits_dash': _fill('4111-'),
    'card_digit_space_x': _fill('1 1 1 1 1 1 1 1 1 1 1 1 1x'),
    'iban_like': _fill('IT60 X054 '),
    'btc_base58_run': _fill('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN'),
    'bech32_run': 'bc1' + _fill('q'),
    'eth_run': '0x' + _fill('a'),
    'tron_run': _fill('T' + 'R7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6'),
    'ipv4_chain': _fill('1.1.1.'),
    'ipv6_chain': _fill('aaaa:bbbb::'),
    'token_spaces': 'token' + _fill(' ') + 'x',
    'token_chain': _fill('token '),
    'apikey_chain': _fill('api_key: "'),
    'key_equals_chain': _fill('key='),
    'secret_eq_short': _fill('secret=abc '),
    'github_pat_chain': _fill('github_pat_'),
    'sk_chain': _fill('sk-'),
    'coord_decimals': '45.' + _fill('1'),
    'coord_pair_chain': _fill('45.12345,'),
    'coord_sep_spaces': '45.12345' + _fill(' ') + ',',
    'coord_minus_chain': _fill('-1.1234 '),
    'dms_chain': _fill("45°27'"),
    'dms_spaces': _fill('45 ° 27 \' 51 " '),
    'latlon_label_chain': _fill('lat: '),
    'url_chain': _fill('http://'),
    'url_long_host': 'https://' + _fill('a.'),
    'url_userinfo_chain': 'https://' + _fill('a:'),
    'codice_fiscale_like': _fill('RSSMRA85T10'),
}


def _rule_ids():
    return [rule.name for rule in RULES]


def _apply_rule(rule, text: str) -> None:
    guard = PrivacyGuard(secrets=[])
    rule.pattern.sub(guard._replacement(rule), text)


@pytest.mark.timeout(120)
@pytest.mark.parametrize('rule', RULES, ids=_rule_ids())
def test_every_rule_is_linear_on_adversarial_input(rule):
    slow = {}
    for name, text in ADVERSARIAL.items():
        started = time.perf_counter()
        _apply_rule(rule, text)
        elapsed = time.perf_counter() - started
        if elapsed > PER_RULE_BUDGET:
            slow[name] = round(elapsed, 3)
    assert not slow, f'{rule.name} backtracks on: {slow}'


@pytest.mark.timeout(120)
@pytest.mark.parametrize('name', sorted(ADVERSARIAL))
def test_whole_guard_is_bounded(name):
    started = time.perf_counter()
    PrivacyGuard(secrets=[]).redact(ADVERSARIAL[name])
    assert time.perf_counter() - started < WHOLE_GUARD_BUDGET


@pytest.mark.timeout(120)
@pytest.mark.parametrize('name', sorted(ADVERSARIAL))
def test_log_guard_is_bounded(name):
    started = time.perf_counter()
    privacy.log_guard().redact(ADVERSARIAL[name])
    assert time.perf_counter() - started < WHOLE_GUARD_BUDGET


@pytest.mark.timeout(120)
def test_log_only_patterns_are_linear():
    privacy.register_sensitive_values(['target_user'])
    try:
        for pattern, sub in privacy.log_only_patterns():
            for name, text in ADVERSARIAL.items():
                started = time.perf_counter()
                pattern.sub(sub, text)
                elapsed = time.perf_counter() - started
                assert elapsed < PER_RULE_BUDGET, f'{pattern.pattern[:40]} backtracks on {name}'
    finally:
        privacy.clear_sensitive_values()


def test_oversized_field_is_truncated_not_scanned_forever():
    text = 'x ' * (privacy.MAX_FIELD_CHARS // 2 + 1000)
    started = time.perf_counter()
    out = PrivacyGuard(secrets=[]).redact(text)
    assert time.perf_counter() - started < 10
    assert len(out) < privacy.MAX_FIELD_CHARS + 100
    assert out.endswith(']') and '[TRUNCATED' in out


def test_truncation_never_leaves_half_a_secret():
    secret = 'urlscan-key-0123456789abcdefghijklmnop'
    pad = 'x' * (privacy.MAX_FIELD_CHARS - 10) + ' '
    out = PrivacyGuard(secrets=[secret]).redact(pad + secret + ' tail')
    # The key straddles the cap: its first half must not survive the truncation.
    assert 'urlscan-k' not in out
