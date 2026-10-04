from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator  # noqa: F401

from secure_osint.core.references import find_references
from secure_osint.security.safe_yaml import load_workflow

Risk = Literal['low', 'medium', 'high']


class StepStatus(str, Enum):
    """Outcome of a single workflow step."""

    SUCCESS = 'SUCCESS'  # eseguito, tutte le dipendenze OK
    DEGRADED = 'DEGRADED'  # eseguito con successo ma con dipendenze fallite/mancanti
    ERROR = 'ERROR'  # fallito (dopo i tentativi) o timeout
    UNAVAILABLE = 'UNAVAILABLE'  # fonte non disponibile: tool mancante, 404, quota, circuit aperto
    SKIPPED = 'SKIPPED'  # non eseguito: dipendenza obbligatoria fallita e partial results disattivati


class StepConfig(BaseModel):
    """Validated configuration of one workflow step (from YAML)."""

    model_config = ConfigDict(extra='forbid')

    id: str = Field(pattern=r'^[A-Za-z0-9_-]{1,64}$')
    type: str = Field(min_length=1, max_length=64)
    params: Dict[str, Any] = Field(default_factory=dict)
    depends_on: List[str] = Field(default_factory=list)
    optional_dependencies: List[str] = Field(default_factory=list)
    # Budget complessivo dello step in secondi, tentativi inclusi.
    timeout: int = Field(default=30, ge=1, le=600)
    # Numero TOTALE di tentativi (compatibile con i workflow esistenti); 0 equivale a 1.
    retry: int = Field(default=1, ge=0, le=10)
    risk: Risk = 'low'
    require_confirmation: bool = False


class WorkflowConfig(BaseModel):
    """A validated workflow: an acyclic graph of steps with typed fields."""

    model_config = ConfigDict(extra='forbid')

    name: str = Field(min_length=1, max_length=128)
    description: str
    input_type: str
    risk: Risk
    steps: List[StepConfig] = Field(min_length=1, max_length=200)

    @model_validator(mode='after')
    def _check_graph(self) -> 'WorkflowConfig':
        ids = [step.id for step in self.steps]
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        if duplicates:
            raise ValueError(f'Duplicate step ids: {duplicates}')
        known = set(ids)
        for step in self.steps:
            deps = step.depends_on + step.optional_dependencies
            missing = sorted(set(deps) - known)
            if missing:
                raise ValueError(f'Step {step.id!r} depends on unknown steps: {missing}')
            if step.id in deps:
                raise ValueError(f'Step {step.id!r} depends on itself')
            try:
                refs = find_references(step.params)
            except ValueError as e:
                raise ValueError(f'Step {step.id!r}: {e}') from e
            for ref in refs:
                if ref.step_id not in known:
                    raise ValueError(f'Step {step.id!r} references unknown step {ref.step_id!r} in {ref}')
                if ref.step_id not in step.depends_on:
                    # optional_dependencies non basta: un dato opzionale mancante lascerebbe il riferimento vuoto.
                    raise ValueError(f'Step {step.id!r} uses {ref} and must list {ref.step_id!r} in depends_on')
        self.topological_order()  # solleva se c'è un ciclo
        return self

    def topological_order(self) -> List[str]:
        """Ordinamento di Kahn, stabile rispetto all'ordine del file."""
        deps = {s.id: set(s.depends_on) | set(s.optional_dependencies) for s in self.steps}
        order: List[str] = []
        ready = [s.id for s in self.steps if not deps[s.id]]
        while ready:
            current = ready.pop(0)
            order.append(current)
            for step in self.steps:
                if current in deps[step.id]:
                    deps[step.id].discard(current)
                    if not deps[step.id] and step.id not in order and step.id not in ready:
                        ready.append(step.id)
        if len(order) != len(self.steps):
            cyclic = sorted(set(deps) - set(order))
            raise ValueError(f'Dependency cycle among steps: {cyclic}')
        return order


class StepResult(BaseModel):
    """The result of executing one step: status, data, timing and errors."""

    status: StepStatus
    data: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    execution_time: float = 0.0
    attempts: int = 0
    cached: bool = False


def load_workflow_from_file(filepath: str) -> WorkflowConfig:
    """Solleva ValueError (file/YAML) o pydantic.ValidationError (schema/grafo)."""
    return WorkflowConfig.model_validate(load_workflow(filepath))
