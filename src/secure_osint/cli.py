import logging
import os
import re
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Dict, FrozenSet, List, NoReturn, Optional, Tuple
from urllib.parse import urlparse

import typer
from rich.console import Console

from secure_osint.config import describe_keys, env_file_path, load_env_file
from secure_osint.core.privacy import CATEGORIES, PrivacyGuard, register_sensitive_values
from secure_osint.core.reporter import ReportGenerator
from secure_osint.core.validator import detect_input_type
from secure_osint.core.workflow import StepConfig, WorkflowConfig, load_workflow_from_file
from secure_osint.security.input_sanitizer import sanitize_input
from secure_osint.utils.log_redaction import redacting_logger
from secure_osint.utils.logging_config import configure_logging
from secure_osint.utils.terminal import ensure_console_encoding, rich_safe, safe_text

if TYPE_CHECKING:
    from secure_osint.utils.cache import ResultCache

# Tracebacks can carry target data (an export or cache error message): always fully redacted.
logger = redacting_logger(__name__)

app = typer.Typer(help='Secure OSINT Workflow Tool: privacy-first OSINT workflows on public data.')

WORKFLOW_BY_TYPE = {
    'domain': 'domain',
    'url': 'domain',
    'ipv4': 'ip',
    'ipv6': 'ip',
    'email': 'email',
    'username': 'username',
    'github_repo': 'github',
    'phone': 'phone',
    'image_file': 'image',
    'wallet': 'wallet',
    'generic': 'generic',
}


class ExportFormat(str, Enum):
    """Correlation export formats (see core.export.export_correlations)."""

    graphml = 'graphml'
    gexf = 'gexf'
    maltego_csv = 'maltego_csv'
    json = 'json'


EXPORT_FORMATS: Tuple[str, ...] = tuple(f.value for f in ExportFormat)
# One file per format, next to latest.json/latest.md (correlations.json never collides with latest.json).
EXPORT_FILENAMES: Dict[str, str] = {
    'graphml': 'correlations.graphml',
    'gexf': 'correlations.gexf',
    'maltego_csv': 'correlations_maltego.csv',
    'json': 'correlations.json',
}
EXPORT_MISSING_MSG = 'Correlation export is not available in this installation (secure_osint.core.export is missing).'


def default_workflow_dir() -> str:
    """Workflow directory: SECURE_OSINT_WORKFLOW_DIR when set, otherwise the one shipped in the package.

    Resolved relative to this file, never the current directory: it works from pipx/wheel installs and
    inside a PyInstaller binary (the YAML files must be bundled as ``secure_osint/workflows``).
    """
    return os.environ.get('SECURE_OSINT_WORKFLOW_DIR') or str(Path(__file__).resolve().parent / 'workflows')


DEFAULT_WORKFLOW_DIR = default_workflow_dir()
_WORKFLOW_NAME = re.compile(r'^[A-Za-z0-9_-]{1,64}$')


@app.callback()
def main() -> None:
    """Secure OSINT Workflow Tool."""
    # A cp1252 Windows console must not crash on an emoji in a profile bio after the network work is done.
    ensure_console_encoding()
    # Single .env source: ~/.config/secure_osint/.env. Never the current directory.
    load_env_file()


def privacy_categories(
    keep_network: bool = False, keep_location: bool = False, keep_crypto: bool = False, keep_device: bool = False
) -> FrozenSet[str]:
    """Redaction categories for the run: every known category minus the ones explicitly kept.

    Only a real ``True`` keeps a category (the GUI API could send truthy strings). Categories that do
    not exist in this build are simply ignored, so the flags are safe before the privacy module grows them.
    """
    kept = {
        name
        for name, keep in (
            ('network', keep_network),
            ('location', keep_location),
            ('crypto', keep_crypto),
            ('device', keep_device),
        )
        if keep is True
    }
    return frozenset(CATEGORIES - kept)


def _normalize_input(input_str: str, input_type: str) -> str:
    if input_type == 'url':
        return urlparse(input_str).hostname or input_str
    if input_type == 'image_file':
        # Absolute path: the report and the source see the same file whatever the working directory.
        return str(Path(input_str).expanduser().resolve())
    if input_type == 'wallet':
        if input_str[:2].lower() == '0x':
            return '0x' + input_str[2:].lower()  # EVM: hex is case-insensitive (EIP-55 case is only a checksum)
        if input_str[:3].lower() in ('bc1', 'tb1'):
            return input_str.lower()  # bech32 must be single-case; explorers expect lowercase
        return input_str  # base58 (BTC legacy, TRON) is case-sensitive
    return input_str


def _report_subject(input_str: str, workflow: str) -> str:
    """What reports, exports and the graph call the target.

    The engine needs the absolute path of a local image, but deliverables must not carry the analyst's
    home directory, account name or folder layout: they get the file name only (the image_exif result
    still identifies the file precisely by its SHA-256).
    """
    return Path(input_str).name if workflow == 'image' else input_str


def _resolve(input_str: str, workflow: str, quiet: bool = False) -> Tuple[str, str]:
    input_str = sanitize_input(input_str)
    if workflow == 'auto':
        input_type = detect_input_type(input_str)
        workflow = WORKFLOW_BY_TYPE.get(input_type, 'generic')
        input_str = _normalize_input(input_str, input_type)
        if not quiet:
            typer.echo(f'Auto-detected type: {input_type} -> workflow: {workflow}')
    elif detect_input_type(input_str, allow_files=False) == 'wallet':
        # Explicit workflow: still canonicalise wallets so reports and redaction see one spelling.
        input_str = _normalize_input(input_str, 'wallet')
    return input_str, workflow


def _load(workflow: str, workflow_dir: str) -> WorkflowConfig:
    # Plain names only: no '../' to load arbitrary YAML from outside the workflow directory.
    if not _WORKFLOW_NAME.match(workflow):
        raise ValueError(f'Invalid workflow name: {workflow!r}')
    path = Path(workflow_dir) / f'{workflow}.yaml'
    if not path.is_file():
        raise ValueError(f'Workflow {workflow} not found in {workflow_dir}.')
    return load_workflow_from_file(str(path))


def _open_cache(ttl: int) -> Optional['ResultCache']:
    from secure_osint.utils.cache import ResultCache

    try:
        return ResultCache(default_ttl=ttl)
    except Exception as e:  # cache unavailable: carry on without it
        logger.debug('cache disabled', exc_info=True)  # the user sees the echo below
        typer.echo(f'Warning: cache disabled ({safe_text(e, single_line=True)})', err=True)
        return None


def _fail(message: str) -> NoReturn:
    typer.echo(f'Error: {safe_text(message, single_line=True)}', err=True)
    raise typer.Exit(code=1)


def _open_cache_or_fail() -> 'ResultCache':
    """Open the cache for a cache-* command; a cache that cannot be secured is an error, not a traceback."""
    from secure_osint.utils.cache import ResultCache

    try:
        return ResultCache()
    except Exception as e:  # e.g. InsecurePermissionsError: fail closed, with a readable message
        logger.debug('cache unavailable', exc_info=True)
        _fail(f'cache unavailable ({e})')


def load_exporter() -> Callable[..., Any]:
    """``core.export.export_correlations``, imported lazily. Raises RuntimeError when the module is missing."""
    try:
        from secure_osint.core.export import export_correlations
    except ImportError as e:
        raise RuntimeError(EXPORT_MISSING_MSG) from e
    return export_correlations


@app.command()
def run(
    input: str = typer.Argument(..., help='Target: domain, URL, IP, email, username, phone, wallet or image path.'),
    workflow: str = typer.Option('auto', help='Workflow name, or auto to pick it from the input type.'),
    workflow_dir: str = typer.Option(DEFAULT_WORKFLOW_DIR, help='Directory containing the workflow YAML files.'),
    output_dir: str = typer.Option('reports', help='Directory where reports are written.'),
    keep_network: bool = typer.Option(False, help='Do not redact IP addresses (useful for domain recon).'),
    keep_location: bool = typer.Option(False, help='Do not redact GPS coordinates and map links.'),
    keep_crypto: bool = typer.Option(False, help='Do not redact cryptocurrency wallet addresses.'),
    keep_device: bool = typer.Option(
        False, help='Do not redact camera/lens serial numbers (a device pivot across photos).'
    ),
    yes: bool = typer.Option(False, '--yes', '-y', help='Automatically confirm steps that require confirmation.'),
    max_workers: int = typer.Option(8, min=1, max=64, help='Maximum number of steps running in parallel.'),
    log_level: str = typer.Option('WARNING', help='Log level (DEBUG, INFO, WARNING, ERROR).'),
    log_json: bool = typer.Option(False, help='Structured JSON logs on stderr.'),
    quiet: bool = typer.Option(False, '--quiet', '-q', help='No output except errors (for scripts).'),
    show_data: bool = typer.Option(False, help='Print the collected (redacted) data in the terminal.'),
    cache: bool = typer.Option(True, '--cache/--no-cache', help='Encrypted cache of source results.'),
    cache_ttl: int = typer.Option(3600, min=0, help='Cache lifetime in seconds (0 = do not store).'),
    case_id: Optional[str] = typer.Option(
        None, '--case-id', help='Case ID stamped on reports and logs (chain of custody).'
    ),
    graph: bool = typer.Option(
        False, '--graph', help="Also write the interactive correlation graph (needs the 'graph' extra)."
    ),
    export: Optional[List[ExportFormat]] = typer.Option(
        None,
        '--export',
        case_sensitive=False,
        help='Also export the redacted correlations: graphml, gexf, maltego_csv or json. Repeatable.',
    ),
) -> None:
    """Run an OSINT workflow, auto-detecting the input type."""
    formats = list(dict.fromkeys(f.value for f in export or []))  # de-duplicated, order kept
    exporter: Optional[Callable[..., Any]] = None
    if formats:
        # Before any network call: a missing exporter must not cost the user a whole investigation.
        try:
            exporter = load_exporter()
        except RuntimeError as e:
            _fail(str(e))
    if graph:
        from secure_osint.core.graph import ensure_graph_support

        try:
            ensure_graph_support()
        except RuntimeError as e:
            _fail(str(e))
    configure_logging(log_level, log_json)
    # Logs scrub the target itself: a username in a message has no shape a regex could recognise.
    register_sensitive_values([input])
    if case_id:
        logging.getLogger('secure_osint').info('run started', extra={'case_id': case_id})
    from secure_osint.core.engine import WorkflowEngine
    from secure_osint.ui import ProgressObserver, data_panels, partial_notice, results_table, username_table

    try:
        input, workflow = _resolve(input, workflow, quiet)
        wf = _load(workflow, workflow_dir)
    except ValueError as e:
        _fail(str(e))
    register_sensitive_values([input])  # the normalised form too

    def confirm(step: StepConfig) -> bool:
        """Prompt (or auto-confirm) a step that requires confirmation."""
        # The workflow file may come from a third party: its text must not drive the terminal.
        prompt = safe_text(f'Step {step.id} ({step.type}, risk={step.risk}) requires confirmation. Run it?', True)
        return yes or typer.confirm(prompt)

    guard = PrivacyGuard(categories=privacy_categories(keep_network, keep_location, keep_crypto, keep_device))
    console = Console()
    result_cache = _open_cache(cache_ttl) if cache else None

    def make_engine(observer: Optional[ProgressObserver] = None) -> WorkflowEngine:
        """Build a WorkflowEngine wired to the shared options and optional observer."""
        return WorkflowEngine(
            allow_partial_results=True,
            max_workers=max_workers,
            confirm=confirm,
            observer=observer,
            cache=result_cache,
            cache_ttl=cache_ttl,
        )

    try:
        if quiet:
            results = make_engine().execute(wf, input)
        else:
            # Progress on stderr: stdout stays clean for the results table.
            with ProgressObserver(Console(stderr=True), total_steps=len(wf.steps)) as observer:
                results = make_engine(observer).execute(wf, input)
    finally:
        if result_cache is not None:
            result_cache.close()

    subject = _report_subject(input, workflow)
    if not quiet:
        console.print(results_table(results, title=f'{wf.name}: {guard.redact(subject)}', guard=guard))
        for step_id, result in results.items():
            if result.data and isinstance(result.data.get('platforms'), dict):
                console.print(username_table(result.data, guard, title=step_id))
        notice = partial_notice(results, guard)
        if notice is not None:
            console.print(notice)
        if show_data:
            console.print(data_panels(results, guard))

    reporter = ReportGenerator(guard, case_id=case_id)
    json_path = str(Path(output_dir) / 'latest.json')
    md_path = str(Path(output_dir) / 'latest.md')
    reporter.generate_json(results, subject, workflow, json_path)
    reporter.generate_markdown(results, subject, workflow, md_path)
    if not quiet:
        console.print(
            f'Reports saved to {rich_safe(json_path)} and {rich_safe(md_path)}', soft_wrap=True, highlight=False
        )

    correlations = reporter.correlations(results, subject) if graph or formats else None
    if graph and correlations is not None:
        from secure_osint.core.graph import build_correlation_graph, graph_filename, save_graph_html

        # Same (already redacted) correlations as the report: the graph shows nothing the report hides.
        graph_path = Path(output_dir) / graph_filename(case_id)
        save_graph_html(build_correlation_graph(correlations, guard=guard), graph_path)
        if not quiet:
            console.print(f'Interactive graph saved to {rich_safe(graph_path)}', soft_wrap=True, highlight=False)

    failed_exports = 0
    if exporter is not None and correlations is not None:
        for fmt in formats:
            try:
                path = exporter(correlations, fmt, Path(output_dir) / EXPORT_FILENAMES[fmt])
            except Exception as e:  # one failed export must not hide the others: reported, exit code 1
                logger.exception('export failed', extra={'export_format': fmt})
                typer.echo(
                    f'Error: export to {fmt} failed: {safe_text(guard.redact(str(e)), single_line=True)}', err=True
                )
                failed_exports += 1
                continue
            if not quiet:
                console.print(f'Correlations exported ({fmt}) to {rich_safe(path)}', soft_wrap=True, highlight=False)
    if failed_exports:
        raise typer.Exit(code=1)


@app.command()
def dry_run(
    input: str = typer.Argument(..., help='Target to plan an investigation for.'),
    workflow: str = typer.Option('auto', help='Workflow name, or auto to pick it from the input type.'),
    workflow_dir: str = typer.Option(DEFAULT_WORKFLOW_DIR, help='Directory containing the workflow YAML files.'),
) -> None:
    """Show the execution plan without touching the network."""
    try:
        input, workflow = _resolve(input, workflow)
        wf = _load(workflow, workflow_dir)
    except ValueError as e:
        _fail(str(e))
    steps = {step.id: step for step in wf.steps}
    typer.echo(f'Dry run. Workflow: {safe_text(wf.name, single_line=True)}')
    for step_id in wf.topological_order():
        step = steps[step_id]
        deps = (
            f' after {step.depends_on + step.optional_dependencies}'
            if step.depends_on or step.optional_dependencies
            else ''
        )
        line = f'  - [{step.type}] {step.id} (timeout={step.timeout}s, attempts={max(1, step.retry)}){deps}'
        typer.echo(safe_text(line, single_line=True))
    typer.echo('No network calls made. Simulation complete.')


@app.command()
def validate(workflow_path: str = typer.Argument(..., help='Path of the workflow YAML file to check.')) -> None:
    """Validate a workflow YAML file."""
    try:
        wf = load_workflow_from_file(workflow_path)
        typer.echo(f'Valid workflow: {safe_text(wf.name, single_line=True)}')
    except Exception as e:  # any parse/schema error is a user-facing validation failure
        typer.echo(f'Invalid workflow: {safe_text(e)}', err=True)
        raise typer.Exit(code=1)


@app.command()
def sources(
    load_plugins: bool = typer.Option(True, help='Include sources registered by installed plugins.'),
) -> None:
    """List the available sources (built-in and plugins)."""
    from secure_osint.sources.tool_catalog import build_catalog

    for name in sorted(build_catalog(load_plugins=load_plugins)):
        typer.echo(safe_text(name, single_line=True))


@app.command()
def cache_audit() -> None:
    """Show what is cached: source, redacted input, expiry, PII categories in the data."""
    from secure_osint.ui import cache_table

    store = _open_cache_or_fail()
    try:
        entries = store.audit()
        if entries:
            Console().print(cache_table(entries))
        typer.echo(f'{len(entries)} cached entries in {store.directory}' if entries else 'No cached entries.')
        if entries.undecryptable:
            typer.echo(f'{entries.undecryptable} cached entries could not be decrypted with the current key.')
    finally:
        store.close()


@app.command()
def cache_clear() -> None:
    """Delete every cached entry."""
    store = _open_cache_or_fail()
    try:
        typer.echo(f'Removed {store.clear()} cached entries.')
    finally:
        store.close()


@app.command()
def keys() -> None:
    """Show which API keys are configured (never their values)."""
    for entry in describe_keys():
        state = 'set' if entry['set'] else 'not set'
        typer.echo(f'{entry["name"]:<20} {state:<8} {entry["usage"]}')
    typer.echo(f'Keys are read from the environment and from {env_file_path()}')


@app.command()
def gui(
    host: str = typer.Option(
        '127.0.0.1',
        help='Listen address (loopback by default). Any other address requires SECURE_OSINT_GUI_AUTH=user:password.',
    ),
    port: int = typer.Option(7860, min=1, max=65535, help='Port of the web interface.'),
    open_browser: bool = typer.Option(True, '--open-browser/--no-open-browser', help='Open the browser.'),
    output_dir: str = typer.Option('reports', help='Directory where GUI reports are written (one folder per run).'),
    cache_ttl: int = typer.Option(3600, min=0, help='Cache lifetime in seconds for GUI runs (0 = do not store).'),
    log_level: str = typer.Option('WARNING', help='Log level (DEBUG, INFO, WARNING, ERROR).'),
) -> None:
    """Start the local web interface (needs the optional 'gui' extra).

    Credentials are read only from the SECURE_OSINT_GUI_AUTH environment variable, never from the
    command line (arguments are visible in the process list).
    """
    configure_logging(log_level)  # the GUI logs failures: install the redacting handler first
    from secure_osint.app import launch

    try:
        launch(host=host, port=port, open_browser=open_browser, output_dir=output_dir, cache_ttl=cache_ttl)
    except RuntimeError as e:
        _fail(str(e))


@app.command()
def security_check(
    env_file: Optional[str] = typer.Option('.env', help='Path of a .env file that must not be committed.'),
) -> None:
    """Run basic security checks."""
    typer.echo('Running security checks...')
    if env_file and Path(env_file).exists():
        typer.echo(f'Warning: {env_file} file exists. Ensure it is in .gitignore')
    if os.environ.get('SECURE_OSINT_TRUST_ENV') == '1':
        typer.echo('Warning: SECURE_OSINT_TRUST_ENV=1, DNS pinning is disabled when a proxy is used.')
    if os.environ.get('SECURE_OSINT_GUI_AUTH'):
        typer.echo('Note: SECURE_OSINT_GUI_AUTH is set; the web interface will require a login.')
    typer.echo('Security check complete.')


if __name__ == '__main__':
    app()
