"""Recursive investigation: follow the selectors a run discovers, inside an explicit scope.

A single workflow run stops at its own target; the correlations it builds only *suggest* pivots. This
module turns those suggestions into a bounded breadth-first expansion:

* only the selector kinds the analyst opted into are followed (``username``, ``email``, ``domain``);
* ``max_depth`` bounds how far from the seed the expansion goes, ``max_targets`` how many workflow runs
  it may start in total (the seed included);
* every candidate goes through ``confirm`` before it is run, so a human decides each hop;
* every candidate that is NOT run is still recorded, with the reason (declined, out of budget, too deep),
  so the record shows what was left on the table instead of silently dropping it.

Nothing here touches the network itself: ``run_target`` does. Values are kept raw in memory; the
reporter redacts them before anything is written.
"""

import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, FrozenSet, Iterable, List, Optional, Tuple

from secure_osint.core.correlation import ENTITY_BUCKETS, _walk
from secure_osint.core.validator import detect_input_type

PIVOT_KINDS: Tuple[str, ...] = ('username', 'email', 'domain')
# Workflow each followed kind runs, and the correlation bucket its values come from.
WORKFLOW_BY_KIND: Dict[str, str] = {'username': 'username', 'email': 'email', 'domain': 'domain'}
BUCKET_BY_KIND: Dict[str, str] = {'username': 'usernames', 'email': 'emails', 'domain': 'domains'}

MAX_DEPTH_CAP = 3
MAX_TARGETS_CAP = 50

# Same rule as the username source: no '/', '?', '#', '%' or spaces can reach a profile URL.
_USERNAME = re.compile(r'^[A-Za-z0-9_.]{1,38}[A-Za-z0-9_]$|^[A-Za-z0-9_]$')

# Shared mailbox providers: recon of gmail.com says nothing about the person who uses it, and running
# crt.sh/Wayback/HackerTarget against them only burns quota on someone else's infrastructure.
WEBMAIL_DOMAINS: FrozenSet[str] = frozenset(
    {
        'aol.com',
        'fastmail.com',
        'gmail.com',
        'gmx.com',
        'gmx.de',
        'gmx.net',
        'googlemail.com',
        'hey.com',
        'hotmail.com',
        'hotmail.it',
        'icloud.com',
        'libero.it',
        'live.com',
        'mac.com',
        'mail.com',
        'mail.ru',
        'me.com',
        'msn.com',
        'outlook.com',
        'outlook.it',
        'pm.me',
        'proton.me',
        'protonmail.com',
        'qq.com',
        'tutanota.com',
        'tuta.io',
        'virgilio.it',
        'web.de',
        'yahoo.com',
        'yahoo.it',
        'yandex.com',
        'yandex.ru',
        'zoho.com',
    }
)

# Outcomes of a candidate.
RUN, DECLINED, BUDGET, DEPTH = 'run', 'declined', 'budget_exhausted', 'max_depth'
FAILED = 'failed'


@dataclass(frozen=True)
class PivotCandidate:
    """A selector found in a run's results that could be investigated on its own."""

    kind: str
    value: str
    found_in: Tuple[str, ...]  # step ids whose data contained it

    @property
    def key(self) -> Tuple[str, str]:
        """Identity used to never investigate the same selector twice."""
        return self.kind, self.value.lower()


@dataclass
class InvestigationNode:
    """One selector of the investigation: the seed, a pivot that ran, or one that did not."""

    id: int
    kind: str
    value: str
    depth: int
    parent: Optional[int]
    found_in: Tuple[str, ...] = ()
    workflow: Optional[str] = None
    outcome: str = RUN
    error: Optional[str] = None
    results: Optional[Dict[str, Any]] = field(default=None, repr=False)  # raw StepResults when it ran


@dataclass
class Investigation:
    """The whole expansion: nodes in the order they were decided, the seed first."""

    nodes: List[InvestigationNode]
    max_depth: int
    max_targets: int
    follow: Tuple[str, ...]

    @property
    def runs(self) -> List[InvestigationNode]:
        """Nodes whose workflow actually ran."""
        return [node for node in self.nodes if node.outcome == RUN and node.results is not None]


def _valid(kind: str, value: str) -> bool:
    if kind == 'username':
        return bool(_USERNAME.match(value))
    try:
        detected = detect_input_type(value, allow_files=False)
    except ValueError:
        return False
    if kind == 'email':
        return detected == 'email'
    if kind == 'domain':
        return detected == 'domain' and value.lower() not in WEBMAIL_DOMAINS
    return False


def pivot_candidates(target: str, plain_results: Dict[str, Any], follow: Iterable[str]) -> List[PivotCandidate]:
    """Selectors of the ``follow`` kinds found in a run's raw (not redacted) step data.

    The same extraction the report's correlations use (``correlation._walk``), done step by step so each
    candidate says where it came from. The target itself, invalid values and shared webmail domains are
    never candidates.
    """
    kinds = [kind for kind in PIVOT_KINDS if kind in set(follow)]
    seen: Dict[Tuple[str, str], List[str]] = {}
    values: Dict[Tuple[str, str], str] = {}
    target_key = target.strip().lower()
    for step_id, result in plain_results.items():
        data = result.get('data') if isinstance(result, dict) else None
        if not isinstance(data, dict):
            continue
        acc: Dict[str, set] = {bucket: set() for bucket in ENTITY_BUCKETS}
        _walk(data, '', acc)
        for kind in kinds:
            for value in sorted(acc[BUCKET_BY_KIND[kind]]):
                value = value.strip()
                key = (kind, value.lower())
                if value.lower() == target_key or not _valid(kind, value):
                    continue
                values.setdefault(key, value)
                if step_id not in seen.setdefault(key, []):
                    seen[key].append(step_id)
    return [PivotCandidate(key[0], values[key], tuple(steps)) for key, steps in seen.items()]


RunTarget = Callable[[str, str], Tuple[Dict[str, Any], Dict[str, Any]]]
Confirm = Callable[[PivotCandidate, InvestigationNode], bool]


def investigate(
    seed: str,
    seed_kind: str,
    seed_workflow: str,
    run_target: RunTarget,
    *,
    follow: Iterable[str] = PIVOT_KINDS,
    max_depth: int = 1,
    max_targets: int = 10,
    confirm: Optional[Confirm] = None,
    on_node: Optional[Callable[[InvestigationNode], None]] = None,
) -> Investigation:
    """Run ``seed`` and, breadth first, the pivots its results reveal.

    Args:
        seed: The first target (already sanitized and normalized).
        seed_kind: Its detected input type (only used for de-duplication and the record).
        seed_workflow: Workflow to run on the seed.
        run_target: ``(value, workflow) -> (raw StepResults, plain results)``; may raise, which records
            the node as failed without stopping the investigation.
        follow: Selector kinds to follow, a subset of ``PIVOT_KINDS``.
        max_depth: Hops from the seed (0 = the seed only). Capped at ``MAX_DEPTH_CAP``.
        max_targets: Workflow runs in total, the seed included. Capped at ``MAX_TARGETS_CAP``.
        confirm: Asked before each pivot runs; ``None`` approves every pivot.
        on_node: Called after each node is decided (and run, when it ran).

    Returns:
        The investigation record, nodes in decision order.
    """
    follow_kinds = tuple(kind for kind in PIVOT_KINDS if kind in set(follow))
    unknown = set(follow) - set(PIVOT_KINDS)
    if unknown:
        raise ValueError(f'Unknown pivot kind(s): {", ".join(sorted(unknown))}')
    max_depth = max(0, min(int(max_depth), MAX_DEPTH_CAP))
    max_targets = max(1, min(int(max_targets), MAX_TARGETS_CAP))

    nodes: List[InvestigationNode] = []
    seen = {(seed_kind, seed.strip().lower())}
    queue: Deque[InvestigationNode] = deque()
    runs = 0

    def execute(node: InvestigationNode) -> None:
        nonlocal runs
        runs += 1
        try:
            node.results, plain = run_target(node.value, node.workflow or '')
        except Exception as e:  # one failed target must not lose the rest of the investigation
            node.outcome, node.error = FAILED, f'{type(e).__name__}: {e}'
            plain = None
        nodes.append(node)
        if on_node is not None:
            on_node(node)
        if plain is not None:  # also at max_depth: its pivots are recorded as not followed
            node_plain[node.id] = plain
            queue.append(node)

    node_plain: Dict[int, Dict[str, Any]] = {}
    execute(InvestigationNode(id=0, kind=seed_kind, value=seed, depth=0, parent=None, workflow=seed_workflow))

    while queue:
        parent = queue.popleft()
        for candidate in pivot_candidates(parent.value, node_plain.pop(parent.id), follow_kinds):
            if candidate.key in seen:
                continue
            seen.add(candidate.key)
            node = InvestigationNode(
                id=len(nodes),
                kind=candidate.kind,
                value=candidate.value,
                depth=parent.depth + 1,
                parent=parent.id,
                found_in=candidate.found_in,
                workflow=WORKFLOW_BY_KIND[candidate.kind],
            )
            if node.depth > max_depth:
                node.outcome = DEPTH
            elif runs >= max_targets:
                node.outcome = BUDGET
            elif confirm is not None and not confirm(candidate, parent):
                node.outcome = DECLINED
            else:
                execute(node)
                continue
            nodes.append(node)
            if on_node is not None:
                on_node(node)
    return Investigation(nodes=nodes, max_depth=max_depth, max_targets=max_targets, follow=follow_kinds)
