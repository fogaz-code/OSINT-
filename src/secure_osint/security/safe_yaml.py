import yaml

MAX_YAML_BYTES = 1024 * 1024


def load_workflow(filepath: str, max_bytes: int = MAX_YAML_BYTES) -> dict:
    """yaml.safe_load (nessun tag Python eseguibile) con limite di dimensione e root obbligatoriamente mapping."""
    try:
        with open(filepath, 'rb') as file:
            raw = file.read(max_bytes + 1)
    except OSError as e:
        raise ValueError(f'File {filepath} does not exist or is not readable.') from e
    if len(raw) > max_bytes:
        raise ValueError(f'File size exceeds {max_bytes} bytes.')
    try:
        data = yaml.safe_load(raw.decode('utf-8-sig'))
    except (yaml.YAMLError, UnicodeDecodeError) as e:
        raise ValueError(f'Invalid YAML content: {e}') from e
    if not isinstance(data, dict):
        raise ValueError('Workflow root must be a mapping.')
    return data
