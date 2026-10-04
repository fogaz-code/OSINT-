"""Terminal-safe rendering of untrusted (remote) text."""

import io

import pytest
from rich.console import Console

from secure_osint.utils.terminal import ensure_console_encoding, rich_safe, safe_text

OSC8_LINK = '\x1b]8;;http://evil.example/\x1b\\click me\x1b]8;;\x1b\\'

HOSTILE = [
    OSC8_LINK,  # OSC 8 hyperlink: the visible text hides where it points
    '\x1b]52;c;ZXZpbA==\x07',  # OSC 52: write to the clipboard
    '\x1b[2J\x1b[H',  # clear screen, cursor home
    '\x1b]0;pwned\x07',  # change the window title
    '\x9b31m',  # single-byte C1 CSI
    'safe‮exe.txt',  # bidi override (Trojan Source)
    'zero​width⁦iso⁩',
    'bell\x07back\x08cr\r',
]


@pytest.mark.parametrize('value', HOSTILE)
def test_safe_text_removes_every_control_and_invisible_format_char(value):
    cleaned = safe_text(value)
    assert not any(ord(c) < 0x20 and c not in '\t\n' for c in cleaned)
    assert not any(0x7F <= ord(c) <= 0x9F for c in cleaned)
    assert not any(c in cleaned for c in '‮​⁦⁩')


def test_safe_text_keeps_ordinary_unicode_and_newlines():
    assert safe_text('José 日本 \U0001f600\nline 2\tx') == 'José 日本 \U0001f600\nline 2\tx'


def test_single_line_flattens_whitespace_controls():
    assert safe_text('a\nb\tc', single_line=True) == 'a b c'


def test_safe_text_accepts_non_strings():
    assert safe_text(42) == '42' and safe_text(None) == 'None'


def test_rich_safe_escapes_markup_and_strips_escapes():
    console = Console(file=io.StringIO(), force_terminal=True, color_system='standard', width=200)
    console.print(rich_safe('[link=http://evil.example]x[/link] ' + OSC8_LINK), highlight=False)
    out = console.file.getvalue()
    assert '[link=http://evil.example]x[/link]' in out  # shown literally, not interpreted
    assert '\x1b]' not in out  # no OSC sequence of any kind reaches the terminal


def test_cp1252_stream_replaces_instead_of_crashing():
    strict = io.TextIOWrapper(io.BytesIO(), encoding='cp1252')
    with pytest.raises(UnicodeEncodeError):  # what a Windows console does today
        strict.write('日本 ✓')
        strict.flush()
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding='cp1252', newline='')
    ensure_console_encoding(stream)
    stream.write('café 日本 ✓\n')
    stream.flush()
    assert raw.getvalue() == 'café ?? ?\n'.encode('cp1252')


def test_utf8_stream_is_left_alone():
    stream = io.TextIOWrapper(io.BytesIO(), encoding='utf-8', errors='strict')
    ensure_console_encoding(stream)
    assert stream.errors == 'strict'


def test_streams_without_reconfigure_are_ignored():
    ensure_console_encoding(io.StringIO())  # no exception
