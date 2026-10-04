"""Render untrusted text inside Markdown reports without it becoming Markdown or HTML.

Remote data (profile names, bios, Gravatar labels, verified-account URLs) ends up in ``latest.md`` and in
the GUI's Markdown view. Left raw, ``![x](https://evil/beacon.png)`` makes every viewer fetch an
attacker-chosen image: a tracking beacon that tells the target an investigation is running and from
which IP. These helpers make such text inert.
"""

import html
import re
from typing import Any

from secure_osint.utils.terminal import safe_text

# '_' is left alone: intraword underscores (control_error) never start emphasis in CommonMark.
# '(' and ')' too: a link or image needs '](' and ']' is always escaped, so they stay readable.
_MD_SPECIAL = re.compile(r'([\\`*{}\[\]#+!|~<>])')


def md_text(value: Any) -> str:
    """Remote text as inert Markdown: no HTML, no Markdown syntax, no control characters, one line."""
    return _MD_SPECIAL.sub(r'\\\1', html.escape(safe_text(value, single_line=True), quote=False))


def md_code(value: Any) -> str:
    """Remote text as an inline code span (backticks removed: they would close the span; '|' escaped for tables)."""
    return '`' + safe_text(value, single_line=True).replace('`', '').replace('|', '\\|') + '`'
