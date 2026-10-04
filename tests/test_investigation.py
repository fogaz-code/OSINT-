import json
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from secure_osint.cli import app
from secure_osint.core.investigation import (
    BUDGET,
    DECLINED,
    DEPTH,
    FAILED,
    RUN,
    investigate,
    pivot_candidates,
)
from secure_osint.core.investigation_report import InvestigationReporter
from secure_osint.core.privacy import PrivacyGuard
from secure_osint.core.reporter import ReportGenerator, canonical_json
from secure_osint.core.workflow import StepResult, StepStatus


def _plain(data):
    return {'step': {'status': 'SUCCESS', 'data': data}}


# --- candidate extraction ---


def test_candidates_come_from_the_correlation_keys_with_their_step():
    plain = {
        'gh': {'status': 'SUCCESS', 'data': {'login': 'octocat', 'email': 'octo@acme.io'}},
        'mail': {'status': 'SUCCESS', 'data': {'email_domain': 'acme.io'}},
    }
    found = {(c.kind, c.value): c.found_in for c in pivot_candidates('seed', plain, ('username', 'email', 'domain'))}
    assert found == {
        ('username', 'octocat'): ('gh',),
        ('email', 'octo@acme.io'): ('gh',),
        ('domain', 'acme.io'): ('mail',),
    }


def test_candidates_respect_follow_and_skip_target_webmail_and_invalid():
    plain = _plain({'login': ['Seed', 'bad/name', 'alice'], 'domain': ['gmail.com', 'acme.io'], 'email': 'a@b.io'})
    found = {(c.kind, c.value) for c in pivot_candidates('seed', plain, ('username', 'domain'))}
    assert found == {('username', 'alice'), ('domain', 'acme.io')}


def test_failed_steps_without_data_give_no_candidates():
    assert pivot_candidates('x', {'s': {'status': 'ERROR', 'data': None}}, ('username',)) == []


# --- expansion ---


def _runner(graph):
    """run_target over a fake world: value -> step data."""
    calls = []

    def run(value, workflow):
        calls.append((value, workflow))
        return {'step': value}, _plain(graph.get(value, {}))

    return run, calls


def test_breadth_first_expansion_with_depth_limit():
    graph = {'seed.io': {'email': 'boss@seed.io'}, 'boss@seed.io': {'login': 'bossman'}, 'bossman': {'login': 'deep'}}
    run, calls = _runner(graph)
    inv = investigate('seed.io', 'domain', 'domain', run, max_depth=2)
    assert calls == [('seed.io', 'domain'), ('boss@seed.io', 'email'), ('bossman', 'username')]
    outcomes = {n.value: (n.outcome, n.depth, n.parent) for n in inv.nodes}
    assert outcomes['bossman'] == (RUN, 2, 1)
    # Found at depth 3: recorded, never run.
    assert outcomes['deep'] == (DEPTH, 3, 2)


def test_depth_zero_runs_only_the_seed_but_records_its_pivots():
    run, calls = _runner({'seed': {'login': 'other'}})
    inv = investigate('seed', 'username', 'username', run, max_depth=0)
    assert calls == [('seed', 'username')]
    assert [(n.value, n.outcome) for n in inv.nodes] == [('seed', RUN), ('other', DEPTH)]


def test_budget_counts_the_seed_and_records_what_was_left():
    run, calls = _runner({'seed': {'login': ['a1', 'b2', 'c3']}})
    inv = investigate('seed', 'username', 'username', run, max_targets=2)
    assert len(calls) == 2
    assert [n.outcome for n in inv.nodes] == [RUN, RUN, BUDGET, BUDGET]


def test_declined_pivots_are_not_run_and_budget_is_not_asked_for():
    asked = []
    run, calls = _runner({'seed': {'login': ['a1', 'b2', 'c3']}})

    def confirm(candidate, parent):
        asked.append(candidate.value)
        return candidate.value == 'b2'

    inv = investigate('seed', 'username', 'username', run, max_targets=2, confirm=confirm)
    assert [c[0] for c in calls] == ['seed', 'b2']
    # After b2 the budget is spent: c3 is recorded without bothering the analyst.
    assert asked == ['a1', 'b2']
    assert [(n.value, n.outcome) for n in inv.nodes] == [('seed', RUN), ('a1', DECLINED), ('b2', RUN), ('c3', BUDGET)]


def test_a_selector_is_never_investigated_twice():
    run, calls = _runner({'seed': {'login': ['alice', 'ALICE']}, 'alice': {'login': 'seed'}})
    investigate('seed', 'username', 'username', run, max_depth=3)
    assert [(value.lower(), workflow) for value, workflow in calls] == [('seed', 'username'), ('alice', 'username')]


def test_a_failing_target_is_recorded_and_the_rest_continues():
    def run(value, workflow):
        if value == 'bad1':
            raise RuntimeError('boom')
        return {}, _plain({'login': ['bad1', 'good']} if value == 'seed' else {})

    inv = investigate('seed', 'username', 'username', run)
    assert [(n.value, n.outcome) for n in inv.nodes] == [('seed', RUN), ('bad1', FAILED), ('good', RUN)]
    assert 'boom' in inv.nodes[1].error


def test_limits_are_capped_and_unknown_kinds_rejected():
    run, _ = _runner({})
    inv = investigate('s', 'username', 'username', run, max_depth=99, max_targets=999)
    assert (inv.max_depth, inv.max_targets) == (3, 50)
    with pytest.raises(ValueError):
        investigate('s', 'username', 'username', run, follow=('phone',))


# --- deliverables ---


def _result(data):
    return {'step': StepResult(status=StepStatus.SUCCESS, data=data)}


def test_record_is_redacted_hashed_and_links_every_report(tmp_path):
    def run(value, workflow):
        data = {'email': 'boss@acme.io'} if value == 'acme.io' else {'login': 'bossman'}
        results = _result(data)
        return results, ReportGenerator().plain_results(results)

    inv = investigate('acme.io', 'domain', 'domain', run, max_depth=1)
    paths = InvestigationReporter(ReportGenerator(PrivacyGuard(), case_id='CASE-7')).write(inv, tmp_path)

    record = json.loads(paths['json'].read_text(encoding='utf-8'))
    text = paths['json'].read_text(encoding='utf-8') + paths['markdown'].read_text(encoding='utf-8')
    assert 'boss@acme.io' not in text  # emails stay redacted in the record, as in every report
    assert record['case_id'] == 'CASE-7'
    assert [n['outcome'] for n in record['nodes']] == [RUN, RUN, DEPTH]
    for node in record['nodes'][:2]:
        for info in node['reports'].values():
            assert (tmp_path / info['path']).is_file()
            assert 'acme' not in info['path']  # folders carry node ids, never targets
    integrity = record.pop('integrity')
    import hashlib

    assert integrity['value'] == hashlib.sha256(canonical_json(record).encode()).hexdigest()


# --- CLI ---

runner = CliRunner()


def _cli(monkeypatch, tmp_path, *args, input_text=None):
    source = Mock()
    source.fetch.side_effect = lambda params: {'login': 'pivotuser'} if params['input'] == 'seeduser' else {}
    monkeypatch.setattr('secure_osint.sources.tool_catalog.tool_catalog', {'dns': source})
    wf_dir = tmp_path / 'wf'
    wf_dir.mkdir(exist_ok=True)
    (wf_dir / 'username.yaml').write_text(
        'name: u\ndescription: d\ninput_type: username\nrisk: low\nsteps:\n  - id: only\n    type: dns\n',
        encoding='utf-8',
    )
    out = tmp_path / 'out'
    result = runner.invoke(
        app,
        ['investigate', 'seeduser', '--workflow-dir', str(wf_dir), '--output-dir', str(out), '--no-cache', *args],
        input=input_text,
    )
    return result, source, out


def test_cli_asks_before_each_pivot_and_defaults_to_no(monkeypatch, tmp_path):
    result, source, out = _cli(monkeypatch, tmp_path, input_text='\n')
    assert result.exit_code == 0, result.output
    assert source.fetch.call_count == 1  # the pivot was declined
    record = json.loads((out / 'investigation.json').read_text(encoding='utf-8'))
    assert [n['outcome'] for n in record['nodes']] == [RUN, DECLINED]


def test_cli_approve_pivots_runs_them(monkeypatch, tmp_path):
    result, source, out = _cli(monkeypatch, tmp_path, '--approve-pivots')
    assert result.exit_code == 0, result.output
    assert source.fetch.call_count == 2
    assert (out / 'targets' / '001' / 'latest.md').is_file()


def test_cli_yes_does_not_approve_pivots(monkeypatch, tmp_path):
    result, source, _ = _cli(monkeypatch, tmp_path, '--yes', input_text='n\n')
    assert result.exit_code == 0, result.output
    assert source.fetch.call_count == 1


def test_cli_rejects_images(tmp_path):
    image = tmp_path / 'a.jpg'
    image.write_bytes(b'\xff\xd8\xff\xd9')
    result = runner.invoke(app, ['investigate', str(image), '--output-dir', str(tmp_path / 'o')])
    assert result.exit_code == 1
    assert 'run' in result.output
