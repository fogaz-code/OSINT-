import re

_LABEL = re.compile(r'^(?!-)[a-z0-9-]{1,63}(?<!-)$')


def sanitize_input(input_str: str, max_length: int = 256) -> str:
    """Normalizza l'input CLI: lunghezza massima, niente caratteri di controllo."""
    if len(input_str) > max_length:
        raise ValueError(f'Input exceeds maximum length of {max_length} characters.')
    input_str = re.sub(r'[\x00-\x1f\x7f]', '', input_str).strip()
    if not input_str:
        raise ValueError('Input cannot be empty or only whitespace.')
    return input_str


def normalize_domain(value: str) -> str:
    """Hostname in forma ASCII (punycode) validato label per label. Solleva ValueError."""
    candidate = value.strip().rstrip('.').lower()
    try:
        candidate = candidate.encode('idna').decode('ascii')
    except UnicodeError as e:
        raise ValueError(f'Invalid domain: {value!r}') from e
    labels = candidate.split('.')
    if len(candidate) > 253 or len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        raise ValueError(f'Invalid domain: {value!r}')
    if labels[-1].isdigit():
        raise ValueError(f'Invalid domain (numeric TLD): {value!r}')
    return candidate
