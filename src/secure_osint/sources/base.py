from abc import ABC, abstractmethod
from typing import Any, ClassVar, Dict

from secure_osint.security.input_sanitizer import normalize_domain


class SourceError(Exception):
    """Errore di una fonte. `transient=True` significa che ha senso riprovare."""

    transient: ClassVar[bool] = False


class SourceUnavailable(SourceError):
    """Fallimento permanente: input non valido, 404, SSRF bloccato, circuit aperto."""


class TransientSourceError(SourceError):
    """Fallimento temporaneo: timeout, errori di connessione, 429, 5xx."""

    transient = True


class BaseSource(ABC):
    """Contratto: `fetch` restituisce i dati in caso di successo, altrimenti solleva SourceError.

    `params` contiene sempre `input` (il target) e `upstream` (dati degli step da cui dipende),
    più i parametri dichiarati nel workflow YAML.
    """

    name: ClassVar[str] = ''
    # False per fonti con effetti collaterali o dati che devono essere sempre freschi.
    cacheable: ClassVar[bool] = True

    @abstractmethod
    def fetch(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Run the source and return its data dict, or raise SourceError on failure."""
        ...

    @staticmethod
    def require_input(params: Dict[str, Any]) -> str:
        """Return the stripped ``input`` param, or raise SourceUnavailable if missing."""
        value = str(params.get('input') or '').strip()
        if not value:
            raise SourceUnavailable('No input provided')
        return value


def require_domain(params: Dict[str, Any]) -> str:
    """Return the normalised domain from ``input``, or raise SourceUnavailable."""
    try:
        return normalize_domain(BaseSource.require_input(params))
    except ValueError as e:
        raise SourceUnavailable(str(e)) from e
