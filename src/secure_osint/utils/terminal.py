"""Terminal-safe text: remote data must never drive the user's terminal.

Values shown on screen (profile bios, DNS TXT records, page titles, error messages) come from
servers we do not control. Printed raw they could:

* inject Rich markup (``[link=http://evil]click[/link]``) when rendered through Rich;
* inject ANSI/OSC escape sequences (``ESC ] 8 ;; url ESC \\`` hyperlinks, cursor moves, title
  changes, clipboard writes via OSC 52) - Rich passes ESC and C1 bytes through untouched;
* hide or reorder text with Unicode bidi overrides and zero-width characters (Trojan Source).

``safe_text`` strips all of these; ``rich_safe`` additionally escapes Rich markup.
"""

import codecs
import io
import re
import sys
from typing import Any, Optional, TextIO

from rich.markup import escape

# C0 controls except TAB and LF, DEL, C1 controls (0x80-0x9f, including the single-byte CSI 0x9b),
# bidi embeddings/overrides/isolates, zero-width and other invisible format characters, BOM.
_UNSAFE = re.compile('[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]')


def safe_text(value: Any, single_line: bool = False) -> str:
    """Return ``value`` as text with every terminal control and invisible formatting character removed.

    Args:
        value: Any value; non-strings are converted with ``str``.
        single_line: Also turn TAB and newlines into spaces (for table cells and one-line messages).
    """
    text = _UNSAFE.sub('', value if isinstance(value, str) else str(value))
    if single_line:
        text = text.replace('\t', ' ').replace('\n', ' ')
    return text


def rich_safe(value: Any, single_line: bool = False) -> str:
    """``safe_text`` plus Rich markup escaping: the result renders literally through Rich."""
    return escape(safe_text(value, single_line))


def ensure_console_encoding(stream: Optional[TextIO] = None) -> None:
    """Make a non-UTF-8 text stream replace unencodable characters instead of raising.

    On a Windows console or a redirected stdout the encoding is often cp1252: a username bio with an
    emoji or a CJK page title would otherwise crash the run with ``UnicodeEncodeError`` after the
    network work is done. With no argument, both ``sys.stdout`` and ``sys.stderr`` are fixed.
    """
    streams = (stream,) if stream is not None else (sys.stdout, sys.stderr)
    for target in streams:
        encoding = getattr(target, 'encoding', None)
        reconfigure = getattr(target, 'reconfigure', None)
        if not isinstance(encoding, str) or not callable(reconfigure):
            continue
        try:
            if codecs.lookup(encoding).name == 'utf-8':
                continue
            reconfigure(errors='replace')
        except (LookupError, ValueError, OSError, io.UnsupportedOperation):
            continue  # best effort: a stream we cannot reconfigure is left as it is
