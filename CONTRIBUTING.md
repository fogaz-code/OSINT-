# Contributing

Thanks for helping improve the Secure OSINT Workflow Tool. This project favours small, well-tested,
legally-defensible changes.

## Development environment

Requires Python 3.10 to 3.13.

```bash
git clone https://github.com/fogaz-code/OSINT-
cd OSINT
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Run the checks a contributor runs locally:

```bash
ruff check src tests      # lint
ruff format               # format
mypy src                  # type check
pytest -q                 # tests
```

Or reproduce the full CI matrix (a clean virtualenv per Python version) in one command:

```bash
scripts/ci-matrix.sh
```

## Workflow

- **Tests first.** Write the failing test, watch it fail for the right reason, then implement.
- **Keep CI green.** A push that turns CI red costs a cycle and reviewer trust. Run
  `scripts/ci-matrix.sh` before every push.
- **Conventional Commits.** `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `ci:`, `chore:`.
- **Google-style docstrings** on public classes and methods (Args / Returns / Raises where useful).

## Merge-commit only (stacked-PR house rule)

Pull requests are merged with a **merge commit** (never squash), so history stays bisectable.

When PRs are stacked (PR N+1 targets PR N's branch instead of `main`):

1. Merge PR N into `main`.
2. **Before merging PR N+1, retarget its base to `main`.** Only then merge it.
3. Delete a branch only after confirming its content is in `main`
   (`git merge-base --is-ancestor origin/<branch> origin/main`).

Merging PR N+1 while it still targets PR N's branch puts its commits into that branch, not into
`main`: GitHub shows it as merged, yet `main` does not contain it.

## Ethical boundaries (non-negotiable)

This tool is for **self-footprint audits and authorized investigations with explicit consent**
(licensed private investigation, corporate due diligence, personal audits). Contributions must stay
within these boundaries:

- **Public, verifiable data only.** No logging into platforms on a user's behalf, no bypassing
  authentication, no scraping content that requires a session. Platforms that require a session
  (LinkedIn, Instagram, Facebook, X) are reported `UNAVAILABLE` with a manual-verification note,
  never scraped.
- **No illegal or unverified data sources.** No breach dumps, leak databases, or "combolists".
- **No Terms-of-Service-violating probing.** No WhatsApp/Telegram registration checks or similar
  intrusive techniques.
- **Privacy by default.** Reports redact PII; phone numbers and IP addresses appear only with the
  explicit `--keep-network` flag. Reports are written with `0600` permissions.
- **User responsibility.** Verifying findings and complying with local privacy law (e.g. GDPR) is the
  responsibility of the end user, as stated in every generated report.

A change that cannot be implemented within these boundaries will not be accepted.

## Adding a source

1. Subclass `BaseSource`, implement `fetch(params)`, and register it with `@register_source("name")`.
2. Raise `SourceUnavailable` for permanent failures and `TransientSourceError` for retryable ones;
   never return an error dict.
3. Use `SafeHttpClient` for network access (SSRF-guarded, rate-limited). Add a per-host rate limit in
   `utils/resilience.py` if the service warrants one.
4. Write at least three tests (success, failure, edge case) with mocked responses.
5. Add the source to the relevant workflow YAML and the README source table.
