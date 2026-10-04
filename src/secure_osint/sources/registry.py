import logging
import threading
from importlib.metadata import entry_points
from typing import Callable, Dict, Iterator, Mapping, Optional, Type, TypeVar

from secure_osint.sources.base import BaseSource

logger = logging.getLogger(__name__)

ENTRY_POINT_GROUP = 'secure_osint.sources'

_FACTORIES: Dict[str, Callable[[], BaseSource]] = {}

S = TypeVar('S', bound=Type[BaseSource])


def register_source(name: str) -> Callable[[S], S]:
    """Decoratore: registra una fonte con il nome usato nel campo `type` dei workflow."""

    def decorator(cls: S) -> S:
        """Register ``cls`` under the source name and return it unchanged."""
        if name in _FACTORIES and _FACTORIES[name] is not cls:
            raise ValueError(f'Source {name!r} already registered')
        cls.name = name
        _FACTORIES[name] = cls
        return cls

    return decorator


class SourceRegistry(Mapping[str, BaseSource]):
    """Mapping nome -> istanza, istanziata alla prima richiesta (import leggero, dry-run senza client)."""

    def __init__(self, factories: Optional[Dict[str, Callable[[], BaseSource]]] = None):
        """Initialize SourceRegistry."""
        self._factories = dict(_FACTORIES if factories is None else factories)
        self._instances: Dict[str, BaseSource] = {}
        self._lock = threading.Lock()

    def __getitem__(self, name: str) -> BaseSource:
        with self._lock:
            if name not in self._instances:
                self._instances[name] = self._factories[name]()
            return self._instances[name]

    def __iter__(self) -> Iterator[str]:
        return iter(self._factories)

    def __len__(self) -> int:
        return len(self._factories)

    def __contains__(self, name: object) -> bool:
        return name in self._factories

    def load_entry_points(self) -> None:
        """Carica fonti di terze parti dichiarate come entry point `secure_osint.sources`."""
        for ep in entry_points(group=ENTRY_POINT_GROUP):
            try:
                cls = ep.load()
            except Exception:
                logger.exception('Failed to load source plugin %s', ep.name)
                continue
            if not (isinstance(cls, type) and issubclass(cls, BaseSource)):
                logger.error('Plugin %s is not a BaseSource subclass, ignored', ep.name)
                continue
            self._factories.setdefault(ep.name, cls)
