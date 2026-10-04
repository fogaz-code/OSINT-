"""Riferimenti ai dati di step precedenti nei parametri dei workflow.

Sintassi: {{ steps.<step_id>.data.<chiave>[<indice>].<chiave>... }}

Nessuna valutazione di espressioni: un'unica regex riconosce la forma ammessa, tutto il resto
(`{{ ... }}` con altro contenuto, graffe spaiate) è un errore di validazione. Un riferimento che
occupa l'intera stringa mantiene il tipo originale (lista, numero...); dentro un testo più lungo
viene convertito in stringa ed è ammesso solo per valori scalari.
"""

import copy
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Mapping, Optional, Tuple, Union

PathToken = Union[str, int]

_TEMPLATE = re.compile(r'\{\{(.*?)\}\}', re.S)
_REFERENCE = re.compile(r'^\s*steps\.(?P<step>[A-Za-z0-9_-]{1,64})\.data(?P<path>(?:\.[A-Za-z0-9_-]+|\[\d+\])+)\s*$')
_TOKEN = re.compile(r'\.([A-Za-z0-9_-]+)|\[(\d+)\]')
_SCALARS = (str, int, float, bool)


class UnresolvedReference(Exception):
    """Raised when a ``{{ steps... }}`` reference cannot be resolved at run time."""

    pass


@dataclass(frozen=True)
class Reference:
    """A parsed reference to an earlier step's data (``{{ steps.<id>.data.<path> }}``)."""

    step_id: str
    path: Tuple[PathToken, ...]
    raw: str

    def __str__(self) -> str:
        path = ''.join(f'[{t}]' if isinstance(t, int) else f'.{t}' for t in self.path)
        return f'{{{{ steps.{self.step_id}.data{path} }}}}'


def _parse(body: str) -> Reference:
    match = _REFERENCE.match(body)
    if not match:
        raise ValueError(f'Invalid reference {{{{{body}}}}}: expected {{{{ steps.<step_id>.data.<path> }}}}')
    path: List[PathToken] = [key if key else int(index) for key, index in _TOKEN.findall(match['path'])]
    return Reference(match['step'], tuple(path), body)


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def _references_in(text: str) -> List[Reference]:
    refs = [_parse(m.group(1)) for m in _TEMPLATE.finditer(text)]
    leftover = _TEMPLATE.sub('', text)
    if '{{' in leftover or '}}' in leftover:
        raise ValueError(f'Invalid reference: unbalanced braces in {text!r}')
    return refs


def find_references(params: Mapping[str, Any]) -> List[Reference]:
    """Tutti i riferimenti nei parametri (anche annidati). Solleva ValueError se uno è malformato."""
    refs: List[Reference] = []
    for text in _strings(dict(params)):
        refs.extend(_references_in(text))
    return refs


def _lookup(ref: Reference, data: Mapping[str, Optional[Dict[str, Any]]]) -> Any:
    current: Any = data.get(ref.step_id)
    if current is None:
        raise UnresolvedReference(f'Unresolved reference {ref}: step {ref.step_id!r} produced no data')
    for token in ref.path:
        if isinstance(token, int):
            if not isinstance(current, list) or token >= len(current):
                size = f'list has {len(current)} items' if isinstance(current, list) else 'value is not a list'
                raise UnresolvedReference(f'Unresolved reference {ref}: index {token} not available ({size})')
            current = current[token]
        else:
            if not isinstance(current, dict) or token not in current:
                raise UnresolvedReference(f'Unresolved reference {ref}: key {token!r} not found')
            current = current[token]
    return current


def _resolve_text(text: str, data: Mapping[str, Optional[Dict[str, Any]]]) -> Any:
    matches = list(_TEMPLATE.finditer(text))
    if not matches:
        return text
    if len(matches) == 1 and matches[0].group(0) == text.strip():
        return copy.deepcopy(_lookup(_parse(matches[0].group(1)), data))

    def substitute(match: 're.Match[str]') -> str:
        """Resolve one embedded reference to its scalar string value."""
        ref = _parse(match.group(1))
        value = _lookup(ref, data)
        if not isinstance(value, _SCALARS):
            raise UnresolvedReference(
                f'Cannot embed non-scalar value of {ref} inside text; use the reference as the whole parameter value'
            )
        return str(value)

    return _TEMPLATE.sub(substitute, text)


def _resolve_value(value: Any, data: Mapping[str, Optional[Dict[str, Any]]]) -> Any:
    if isinstance(value, str):
        return _resolve_text(value, data)
    if isinstance(value, dict):
        return {k: _resolve_value(v, data) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_resolve_value(v, data) for v in value]
    return value


def resolve(params: Mapping[str, Any], data: Mapping[str, Optional[Dict[str, Any]]]) -> Dict[str, Any]:
    """Copia di `params` con i riferimenti sostituiti. Solleva UnresolvedReference se un path manca."""
    return {key: _resolve_value(value, data) for key, value in params.items()}
