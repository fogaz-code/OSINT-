# Secure OSINT Workflow Tool

Modular OSINT framework: YAML workflows executed as a parallel DAG, SSRF-hardened HTTP client,
automatic PII redaction in reports.

**Designed for professional, legally compliant use: licensed private investigation, corporate due
diligence, and personal digital-footprint audits.** It gathers only public, verifiable information
through documented methods; it does not scrape behind logins, use breach/leak databases, or probe
services in ways that violate their terms.

## Professional use cases

- **Personal self-audit.** See what is publicly exposed about your own identifiers (username, email,
  phone) so you can lock things down.
- **Corporate due diligence.** Vet a company's public footprint (domains, certificates, exposure) and
  publicly listed contact details as part of KYC / vendor / M&A review.
- **Authorized background checks.** For a licensed investigator or an authorized internal
  investigation, collect and document publicly available data with a case ID and integrity hash for a
  defensible record.

Each report carries a case ID (with `--case-id`), a SHA-256 integrity hash, and a legal disclaimer, so
findings can be filed as part of a professional record.

## Legal & ethical guidelines

- **Public data only.** The tool queries public endpoints and offline libraries. It does **not** log
  into platforms on your behalf, bypass authentication, or scrape content that requires a session.
- **No illegal or unverified leak databases.** It never integrates breach dumps or "combolists".
- **No ToS-violating probing.** No WhatsApp/Telegram registration checks or similar intrusive probes.
  Platforms that require an authenticated session (LinkedIn, Instagram, Facebook, X) are reported as
  `UNAVAILABLE` with a note to verify manually, never scraped.
- **Privacy by default.** Reports redact PII (emails, IPs, phone numbers, secrets, financial
  identifiers, GPS coordinates and crypto wallet addresses). Phone numbers and IPs are shown only with
  the explicit `--keep-network` flag, GPS positions only with `--keep-location`, wallet addresses only
  with `--keep-crypto`, camera serial numbers only with `--keep-device`. Logs are always fully
  redacted, whatever these flags say. Reports are readable
  by their owner only (`0600` on POSIX, a private ACL on Windows).
- **Consent and lawful basis.** Use the tool only for a self-audit or an investigation you are
  authorized to conduct. Verifying findings and complying with local privacy law (e.g. GDPR) is the
  responsibility of the end user, as stated in every generated report.

**Use only on targets you are authorized to investigate, or on your own identifiers.**

## Installation for End Users

Requires Python 3.10 or newer.

### Recommended: `pipx` (isolated CLI install)

`pipx` installs the `secure-osint` command into its own virtual environment and puts it on your
`PATH`, so it never clashes with other Python tools:

```bash
# one-time: install pipx itself (see https://pipx.pypa.io for OS-specific steps)
python -m pip install --user pipx
python -m pipx ensurepath

# from a checkout of this repository:
pipx install .

# or, once published to PyPI:
pipx install secure-osint

# verify
secure-osint --help
```

Upgrade with `pipx upgrade secure-osint`; remove with `pipx uninstall secure-osint`.

### Alternative: `pip` into a virtual environment

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install .
secure-osint --help
```

### Standalone executable for non-technical clients (PyInstaller)

For clients without Python installed, build a single self-contained executable. Build on the **same
operating system** you are targeting (a Linux build does not run on Windows, and vice versa):

```bash
pip install ".[build]"          # inside a virtual environment
scripts/build-binary.sh         # builds dist/secure-osint and smoke-tests it outside the repo
```

The script runs this PyInstaller command (use it directly on systems without `bash`, e.g. Windows
`cmd`/PowerShell, as a single line):

```bash
pyinstaller --noconfirm --clean --onefile --name secure-osint --collect-all secure_osint src/secure_osint/__main__.py
```

Two details matter, and getting either wrong produces a binary that fails with
`Workflow ... not found`:

- **`--collect-all secure_osint`** bundles the workflow YAML files, which ship as package data in
  `secure_osint/workflows/`. Without it the binary builds fine but has no workflows.
- **The entry point is `src/secure_osint/__main__.py`, not `cli.py`.** Using `cli.py` as the script
  makes it run as `__main__`, and the workflow lookup then points to the wrong place inside the binary.

The binary is written to `dist/secure-osint` (`dist\secure-osint.exe` on Windows), is about 30 MB, and
runs with no Python installation on the target machine. It does not include the web interface (the
`gui` extra); `secure-osint gui` in a binary prints how to install it. The script's smoke test only
checks that the workflows are bundled: still try the binary on a clean machine of the target OS before
shipping.

### Licensing note for distributors

The source code is open source under the MIT License (`LICENSE`), so anyone may use, modify, and
redistribute it. Acceptable use is governed separately by `ACCEPTABLE_USE_POLICY.md`, whose terms apply
to **official services** (support, premium/hosted API integrations, and maintainer-distributed
binaries) rather than to the MIT-licensed source, which cannot be revoked. Get legal counsel before
offering commercial services around the tool.

For contributor/development setup, see [Development](#development).

## Commercial Services & Support

The tool itself is free and open source (MIT). For organisations that need more than the community
edition, a professional tier is available:

- **Official priority support** — direct, SLA-backed help with setup, workflows, and integration,
  ahead of community best-effort.
- **Pre-compiled standalone binaries** — signed, ready-to-run executables for **Windows, macOS, and
  Linux** (built via PyInstaller), so non-technical staff can run the tool without a Python
  toolchain.
- **Premium integrations** — additional data sources offered under the same public-data, lawful-use
  boundaries as the core tool, for example:
  - **Breach-exposure intelligence** via *licensed* providers (whether an identifier appears in a
    publicly disclosed breach — notification only, using lawfully-sourced data; the tool never
    ingests or redistributes raw breach dumps or "combolists");
  - **Advanced corporate email-pattern discovery** for authorised due-diligence and KYC.

Professional-tier access is governed by the [Acceptable Use Policy](ACCEPTABLE_USE_POLICY.md):
support, premium integrations, and binaries are conditional on adhering to it.

Contact: open an issue on the repository (no personal e-mail is published).

## Usage

```bash
secure-osint run example.com            # auto-detects input type and workflow
secure-osint run example.com --keep-network   # keep IP addresses in the report
secure-osint run photo.jpg --keep-location    # image workflow; show the EXIF GPS position
secure-osint run example.com --export graphml --export maltego_csv   # also export the correlations
secure-osint investigate example.com --depth 1 --max-targets 10   # follow pivots, asking for each one
secure-osint dry-run octocat/hello-world
secure-osint validate my_workflow.yaml     # check a custom workflow file
secure-osint sources                    # list built-in and plugin sources
```

Terminal output uses Rich: a progress bar with a spinner per running step (on stderr), then a
colour-coded results table (green `SUCCESS`, yellow `DEGRADED`, red `ERROR`, magenta `UNAVAILABLE`,
dim `SKIPPED`). `--show-data` prints each step's data as highlighted JSON, redacted with the same
rules as the reports. `--quiet` / `-q` prints nothing except errors, for scripts.

Reports are written to `reports/latest.json` and `reports/latest.md`, readable by their owner only.
`--export FMT` (repeatable: `graphml`, `gexf`, `maltego_csv`, `json`) also writes the already-redacted
correlations next to them for Gephi, yEd or Maltego. The Markdown report ends with **Manual search
queries** (JSON: `manual_queries`): search-engine dorks built from the correlations that the tool
never runs.

### Recursive investigation (`investigate`)

`secure-osint investigate <target>` runs the target's workflow, then the usernames, emails and domains
its results reveal, breadth first, inside an explicit scope:

- `--follow username|email|domain` (repeatable, default all three) picks the selector kinds to follow;
- `--depth N` (0-3, default 1) bounds the hops from the seed, `--max-targets N` (1-50, default 10) the
  workflow runs in total, the seed included;
- **every pivot is confirmed by the analyst** (default answer: no). `--approve-pivots` approves them in
  advance; `--yes` only confirms workflow steps, never pivots;
- shared webmail domains (gmail.com, outlook.com, ...) are never followed, and no selector runs twice.

Pivots that are not run are still recorded with the reason (declined, budget exhausted, beyond the
depth limit), so the record shows what was left out. Output, under `--output-dir`:
`targets/NNN/latest.{json,md}` (one ordinary report per target, folders named by node id, never by
target) and `investigation.{json,md}`: the pivot tree, where each pivot was found, the entities across
all targets, and the SHA-256 of every per-target report, all covered by the record's own integrity hash.
Values are redacted exactly as in the per-target reports.

Each pivot is still a separate processing of personal data: approve only those you have a lawful basis
for. A link between two targets is co-occurrence in public data, not a verified identity.

### Interactive investigation graph (`--graph`)

```bash
pip install ".[graph]"                                   # optional extra (pyvis)
secure-osint run jroe --graph --case-id ACME-14         # also writes reports/ACME-14_graph.html
```

`--graph` also writes an interactive HTML graph of what the investigation found, with the target (red
star) in the centre:

| Node | Meaning | Edge from the target |
|---|---|---|
| Blue dot, e.g. `GitHub: jroe` | The username exists on that platform, **HIGH** confidence | `username found on` (solid, thick blue) |
| Blue dot | Found, **MEDIUM** confidence (web page, calibrated) | `username found on` (dashed blue) |
| Gray-blue dot, `… (low confidence)` | Found, **LOW** confidence (name search, or calibration failed) | `low-confidence match` (thin, gray, dotted) |
| Yellow diamond, `LinkedIn (manual check required)` | Could not be checked automatically: login required, blocked, or error | `needs manual verification` (dashed) |
| Gray dot, `GitLab: not found` | Checked, username absent (hidden by default) | `not found on` (dotted) |
| Green square | Domain or email | the relation the data shows, e.g. `uses domain` |
| Orange triangle | IP or host | e.g. `resolves to`, `nameserver`, `mail server` |
| Gray box, dashed border, `Suggested Pivot: …` | A selector you may investigate next (never run automatically) | `suggested pivot` (dashed) |

Hover a node for its status, confidence, public profile data (name, bio, creation date, avatar URL),
profile URL and the run time; **double-click a platform to open its profile** in a new tab. Edge style
shows confidence, not an invented "strength". Avatars are shown as a URL only: the image is never
downloaded or drawn (drawing it would make the browser fetch it from the platform). Relations such as `resolves to` are drawn only where the data proves them (the target
domain's DNS records, an email's domain); anything else is linked as `observed with`. The file is
named after the case ID (`<case-id>_graph.html`, or `latest_graph.html` without one) and saved with
`0600` permissions.

> **A username found on a platform does not prove the target owns that account.** The graph says
> "username found on", never "owns". Treat every node as a lead to verify.

- **Built from the report, nothing else:** it uses the report's own correlation data (the per-platform
  results and relations are also in the JSON `correlations` object and the Markdown summary), so it
  makes no network calls and shows exactly what the report shows. Emails and IPs appear as
  `[REDACTED]` unless `--keep-network` reveals IPs (emails are never revealed).
- **Timestamps:** the tool does not record when each platform was checked, so the graph shows the run
  time.
- **Works offline:** vis-network is embedded in the file, and the Bootstrap stylesheet/script that
  pyvis would load from a CDN is removed, so opening the graph contacts no third-party server. If a
  future pyvis version adds an external resource that cannot be removed, the tool refuses to write the
  file rather than produce one that "phones home".
- Without the extra installed, `--graph` stops **before** running the investigation and prints how to
  install it.
- Note: pyvis's last release is 0.3.2 (2023), and it pulls in IPython and networkx.

## Running the Web Interface

A local web interface lets non-technical users (investigators, HR, auditors) run investigations
from the browser, without the terminal. It is an optional extra, so CLI-only installs and the
standalone binaries stay lean:

```bash
pip install ".[gui]"          # or: pipx install ".[gui]"  /  pip install "secure-osint[gui]"
pip install ".[gui,graph]"    # with the interactive entity graph
secure-osint gui              # or: python -m secure_osint.app
```

It opens `http://127.0.0.1:7860` in your browser (`--port` to change it, `--no-open-browser` to
skip). The interface is a thin wrapper around the same engine as `secure-osint run`: same input
checks, same workflows, same redaction, same reports.

- **Inputs:** Target (username, domain, email, phone or wallet address), Workflow (`auto`,
  `username`, `domain`, `email`, `phone`, `wallet`), optional Case ID, and the "Keep network / location
  / crypto / device data" boxes (the GUI equivalents of `--keep-network`, `--keep-location`, `--keep-crypto`, `--keep-device`).
  Local image analysis is CLI-only: the GUI never reads files on the server.
- **Output:** the Markdown report rendered in the page (with the Entity Correlation Summary), plus
  download links for the JSON and Markdown reports. Each run writes to its own folder under
  `reports/gui/`, so runs never overwrite each other.
- **Interactive graph:** with "Generate Interactive Graph" ticked (the default) and the `graph` extra
  installed, the investigation graph appears below the report, and its standalone HTML is added to
  the downloads. **Graph filters** above it (existing accounts, platforms requiring manual check,
  not-found platforms (off by default), infrastructure, domains/emails, suggested pivots) redraw the graph instantly
  from the run's data, without re-running the investigation, and the downloadable HTML is rewritten
  to match. The graph runs in a sandboxed frame (scripts and popups allowed, no same-origin access),
  so its code cannot read or change the rest of the page; double-clicking a platform opens its
  profile in a new tab. Without the extra, the report still appears, and the graph panel shows how
  to install it.
- **Ethical gate:** the Acceptable Use Policy summary is shown on the page and the **Run** button stays
  disabled until you tick "I agree to the Acceptable Use Policy and will use this tool for authorized
  purposes only". The check is also enforced on the server, so it cannot be bypassed by calling the
  app directly.
- **Private by default:** it listens on `127.0.0.1` only, never creates a public share link, has
  Gradio telemetry turned off, and purges its temporary copies of reports after an hour. Steps that
  require interactive confirmation are skipped (there is no prompt in the GUI).
- **Network exposure needs a login:** `secure-osint gui --host <non-loopback address>` refuses to start
  unless `SECURE_OSINT_GUI_AUTH=user:password` (password of at least 12 characters) is set in the
  environment; it is never accepted as a command-line argument, which would show in the process list.
  When set, the login is required on loopback too, and repeated failures lock the user out for a
  while. Requests whose `Host` is not loopback, the `--host` value or a name in
  `SECURE_OSINT_GUI_ALLOWED_HOSTS` (comma-separated, e.g. behind a reverse proxy that preserves `Host`)
  are refused, which blocks DNS-rebinding attacks against the local UI.

## Capabilities

- Auto-routing by input type: domain, URL, IPv4/IPv6, email, username, phone (E.164), generic.
- Workflows run as a parallel dependency DAG with per-step timeouts, retries with jittered backoff,
  a per-host rate limiter and circuit breaker, and a shared connection pool.
- SSRF-hardened HTTP client (DNS-pinned, blocks private/loopback/link-local and cloud metadata).
- Encrypted on-disk result cache (opt-out with `--no-cache`).
- Reports in JSON and Markdown with automatic PII redaction, `--case-id` stamping, and a SHA-256
  integrity hash.
- Automated Entity Correlation Summaries: each report opens with the unique entities (usernames,
  emails, domains, infrastructure) observed across all steps, and the JSON carries a root-level
  `correlations` object for downstream tools (Maltego, custom dashboards). Purely local synthesis of
  data already collected: no extra network calls, and the same redaction rules apply (emails and IPs
  are hidden unless `--keep-network`). These are co-occurrence observations, not verified identity
  links.
- Interactive Entity Graph Visualization: the investigation's findings as a draggable, zoomable
  graph: one node per platform where the username was found, platforms needing manual verification,
  domains, emails and infrastructure, with labelled relations (`--graph` in the CLI, a filterable
  panel in the web interface). Self-contained and offline, with the same redaction as the report.
  Optional extra: `secure-osint[graph]`.
- The correlation summary also lists per-platform results (where the username was found, possible
  matches, platforms needing manual verification, how many were checked and not found) and the
  relations proven by the data (`accounts` and `relations` in the JSON `correlations`).

## Sources

| Type | What it returns | Network |
|---|---|---|
| `dns` | A/AAAA (system resolver), CNAME, MX, NS, TXT, SOA (dnspython) | system DNS resolver |
| `rdap` | Registration data for domains and IPs | rdap.org |
| `shodan_internetdb` | Open ports, CVEs, hostnames, CPEs, tags for a public IP (weekly data, not a live scan). 404 = never seen, reported as `found: false` | internetdb.shodan.io, no key, 1 req/s |
| `crt_sh` | Subdomains from certificate transparency | crt.sh |
| `wayback` | Archived URLs | web.archive.org |
| `hackertarget` | Host search | api.hackertarget.com |
| `github` | Repository metadata or user search | api.github.com |
| `phone` | **Offline** validation via libphonenumber (no network): validity, country code, region, geographic area, carrier, line type (mobile/fixed/VOIP/toll-free...). No registration probing. The number is redacted by default (only country/carrier/type shown) and revealed only with `--keep-network` | none, fully offline |
| `username` | Handle presence on **30 platforms**: 26 checked automatically, 4 flagged for manual verification (full list in [Username platforms](#username-platforms)): GitHub, GitLab, Bitbucket, SourceForge, Keybase, Reddit, Hacker News, Telegram, TikTok, Mastodon (mastodon.social), Pinterest, Medium, Dev.to, Stack Overflow, CodePen, Docker Hub, PyPI, Hackaday, about.me, Tumblr, WordPress.org, Gravatar, SoundCloud, Flickr, Linktree, Carrd. Per platform: `exists` true/false/unknown, an `error` note, a `confidence` (`HIGH`/`MEDIUM`/`LOW`/`MANUAL`, see below) and, where the platform's public API exposes it, a `profile` (display name, bio, creation date, avatar URL, PyPI package count); a public platform that returns 401/403 is reported as manual verification. LinkedIn, Instagram, Facebook and X are **not** requested (they require an authenticated session) | public endpoints, no key |
| `email` | Gravatar presence, disposable domain, domain resolution | gravatar, kickbox |

Private, loopback and other non-public IPs are rejected before any request: third-party services
have no data on them, and sending them would only leak internal topology.

### Built-in workflows

| Workflow | Auto-selected for | Steps |
|---|---|---|
| `domain_recon` | domains, URLs | `dns`, `rdap`, `wayback`, `hackertarget`, `crt_sh` in parallel; then `shodan_internetdb` on the first resolved IPv4 |
| `ip_recon` | IPv4, IPv6 | `rdap` and `shodan_internetdb` in parallel; then `dns` on the first hostname InternetDB reports for the IP, to check that it still resolves (InternetDB data can be a week old) |
| `email_recon` | emails | `email` (MX, Gravatar, disposable domain); then `dns` on the email's domain (never on the full address) |
| `username_recon` | usernames | `username` |
| `phone_recon` | `+E.164` numbers | `phone` (offline) |
| `github_recon` | `owner/repo` | `github` (repository metadata) |
| `wallet` | BTC, ETH and TRON addresses (checksum-validated) | `chain` (public block-explorer summary: transaction count, first/last seen, balance) |
| `image` | existing local image files | `image_exif` (offline EXIF/XMP metadata; the file is never uploaded) |
| `generic` | anything else (names, hyphenated handles, free text) | `github` user search |

**The `generic` workflow** handles targets that are not a domain, IP, email, phone, username or
`owner/repo`, for example a person's or an organisation's name (`"Jane Doe"`) or a hyphenated handle
(`jane-doe`). It runs a public GitHub user search, the only built-in source that accepts free text, and
lists up to five matching accounts. Those matches are candidates sharing a name, not identified
accounts: verify them manually, and treat each as a separate investigation (a suggested pivot), which
the tool never starts by itself. The domain sources and the username check are deliberately left out,
because they reject free text and would always end `UNAVAILABLE`. To force a different workflow, pass
`--workflow <name>`.

A step that consumes another step's data (the `shodan_internetdb` step in `domain_recon`, the
hostname check in `ip_recon`) ends as `ERROR` when that data is missing, for example a domain with no
A record or an IP with no known hostname: the reference is reported, never guessed (see
[Passing data between steps](#passing-data-between-steps)).

### Username confidence and soft 404s

Some platforms answer HTTP 200 with a generic page even for usernames that do not exist ("soft
404"). Taking that 200 at face value produced false positives (confirmed live on TikTok, Pinterest and
PyPI). Every "found" result now carries a confidence:

| Confidence | When | Examples |
|---|---|---|
| `HIGH` | A public API with a clear answer (404 or an empty result means absent) | GitHub, GitLab, Bitbucket, Keybase, Reddit, Hacker News, Dev.to, Docker Hub, PyPI |
| `MEDIUM` | A web page, **calibrated**: the same check is run with a random username that cannot exist, and "found" is kept only if that control comes back "not found" | TikTok, Pinterest, Telegram, Medium, CodePen, Hackaday, Mastodon, about.me, SourceForge, Tumblr, WordPress.org, Gravatar, SoundCloud, Flickr, Linktree, Carrd |
| `LOW` | An ambiguous match (Stack Overflow searches names that *contain* the term), or the calibration request failed | verify manually |
| `MANUAL` | Not determined: login required, blocked, anti-bot challenge page, or a soft 404 detected by calibration | LinkedIn, Instagram, Facebook, X |

- If the control username also comes back "found", the platform gives no signal: the result is
  reported as **manual verification** ("Soft 404 …"), never as "exists".
- Known "not found" texts (e.g. TikTok's "Couldn't find this account") are recognised on 200 pages.
  These texts change often and could not all be verified from the development environment; the
  calibration is the safety net that does not depend on them.
- **PyPI:** its user pages return an anti-bot challenge (HTTP 200) for every username, so they cannot
  be used. The tool uses PyPI's public XML-RPC `user_packages` call instead: packages found means the
  account exists (`HIGH`, with the package count). An account that owns no packages cannot be told
  apart from a missing one, so "not found" there is `MEDIUM` with a note. (`/pypi/<name>/json` is the
  API for *projects*, not users.)
- Web-page platforms cost one extra request each (the control check), subject to the same per-host
  rate limits.

**Public profile data.** Where the platform's public API already returns it in the same response
(GitHub, Keybase, GitLab, Bitbucket, Dev.to, Docker Hub, Hacker News, PyPI), the result records a
display name, a short bio (max 280 characters, HTML stripped), the creation date and the avatar
**URL**. No extra requests are made for this, avatars are never downloaded, and emails exposed by an
API (such as Docker Hub's gravatar email) are not collected. Everything goes through the same
redaction as the rest of the report (an email written in a bio appears as `[REDACTED]`).

### Username platforms

The `username` source covers **30 platforms**: 26 checked automatically, 4 flagged for manual verification.
The key is the name used in the JSON report (`platforms.<key>`). "Confidence" is the reliability of a
clear "found" answer (see the table above); any platform can still end as `MANUAL` when it is blocked,
returns an error or fails calibration. A `*` in the endpoint stands for the username (one subdomain per
user). This table is checked against the code by `tests/test_docs.py`, so it cannot drift silently.

| Platform | Key | Checked automatically | Confidence | Endpoint |
|---|---|---|---|---|
| GitHub | `github` | yes | `HIGH` | `api.github.com` |
| Keybase | `keybase` | yes | `HIGH` | `keybase.io` |
| Reddit | `reddit` | yes | `HIGH` | `www.reddit.com` |
| Hacker News | `hackernews` | yes | `HIGH` | `hacker-news.firebaseio.com` |
| Telegram | `telegram` | yes | `MEDIUM` | `t.me` |
| TikTok | `tiktok` | yes | `MEDIUM` | `www.tiktok.com` |
| Pinterest | `pinterest` | yes | `MEDIUM` | `www.pinterest.com` |
| GitLab | `gitlab` | yes | `HIGH` | `gitlab.com` |
| Bitbucket | `bitbucket` | yes | `HIGH` | `api.bitbucket.org` |
| Medium | `medium` | yes | `MEDIUM` | `medium.com` |
| Dev.to | `devto` | yes | `HIGH` | `dev.to` |
| Stack Overflow | `stackoverflow` | yes | `LOW` | `api.stackexchange.com` |
| CodePen | `codepen` | yes | `MEDIUM` | `codepen.io` |
| Docker Hub | `dockerhub` | yes | `HIGH` | `hub.docker.com` |
| PyPI | `pypi` | yes | `HIGH` | `pypi.org` |
| Hackaday | `hackaday` | yes | `MEDIUM` | `hackaday.io` |
| Mastodon | `mastodon` | yes | `MEDIUM` | `mastodon.social` |
| about.me | `aboutme` | yes | `MEDIUM` | `about.me` |
| SourceForge | `sourceforge` | yes | `MEDIUM` | `sourceforge.net` |
| Tumblr | `tumblr` | yes | `MEDIUM` | `*.tumblr.com` |
| WordPress.org | `wordpress` | yes | `MEDIUM` | `profiles.wordpress.org` |
| Gravatar | `gravatar` | yes | `MEDIUM` | `gravatar.com` |
| SoundCloud | `soundcloud` | yes | `MEDIUM` | `soundcloud.com` |
| Flickr | `flickr` | yes | `MEDIUM` | `www.flickr.com` |
| Linktree | `linktree` | yes | `MEDIUM` | `linktr.ee` |
| Carrd | `carrd` | yes | `MEDIUM` | `*.carrd.co` |
| LinkedIn | `linkedin` | no, login required | `MANUAL` | not queried |
| Instagram | `instagram` | no, login required | `MANUAL` | not queried |
| Facebook | `facebook` | no, login required | `MANUAL` | not queried |
| X | `x` | no, login required | `MANUAL` | not queried |

Tumblr, WordPress.org (the community profile on `profiles.wordpress.org`, not a wordpress.com blog),
Gravatar, SoundCloud, Flickr, Linktree and Carrd have no verified "not found" text: they rely on
calibration alone, so a platform that serves the same page to everyone is reported as a soft 404 for
manual verification, never as "found".

### WhatsMyName catalog (optional)

The `username` step can also sweep the sites of the community
[WhatsMyName](https://github.com/WebBreacher/WhatsMyName) catalog (data by WebBreacher and
contributors, licensed **CC BY-SA 4.0**). The tool never downloads it: point the step at a local copy
of `wmn-data.json` with the `wmn_path` parameter or the `SECURE_OSINT_WMN_PATH` environment variable,
and choose the set with `platform_set`: `builtin` (default, the curated platforms above), `wmn`
(WhatsMyName sites only) or `all` (built-ins first, then WhatsMyName sites whose host is not already
covered). Entries are validated strictly (https only, no IP literals, no custom headers or POST
bodies, no signup / username-availability / login / recovery endpoints, NSFW sites only with `wmn_include_nsfw: true`, auth-walled networks never requested), every
WhatsMyName result has `MEDIUM` confidence and is calibrated against soft 404s, and the result's
`catalog` block records the attribution and the file's SHA-256 (never its local path). Checks run
concurrently (`max_workers`, default 8) within the step timeout; checks still pending at the deadline
are reported with `error_kind: deadline`. A result with any transiently failed check (timeout, rate
limit, deadline, connection) is never cached; when more than 25% of the automated checks fail, or an
API-backed platform fails transiently, it is also marked partial (`DEGRADED`).

### Suggested pivots

The report ends its summary with a **Suggested Pivots** section, the JSON `correlations` carries a
`suggested_pivots` list, and the graph shows them as gray, dashed-border nodes: public names found on
confirmed profiles, other usernames, and emails observed in the data (including a domain's DNS SOA
contact). **`run` never runs them.** Each pivot is a separate investigation you start yourself (or
approve one by one in `investigate`), only if you have a lawful basis for it (data minimisation). Emails stay redacted, so an email pivot
shows only that one exists.

### DNS record semantics

Each DNS record type is queried independently and in parallel. A failure on one type does not fail
the step: it is reported under `errors` (for example `{"TXT": "timeout"}`, common when large TXT
answers are truncated over UDP and TCP is blocked). `NXDOMAIN` makes the step `UNAVAILABLE`; if no
record of any type could be resolved because of timeouts, the step fails as transient and is retried.

## Passing data between steps

A step parameter can reference the data of a step it depends on:

```
{{ steps.<step_id>.data.<key>[<index>].<key>... }}
```

- The referenced step must be listed in the step's `depends_on` (checked when the workflow is
  loaded, together with the syntax: a malformed `{{ ... }}` or an unknown step fails validation).
- There is no expression evaluation, no Jinja2: only this path syntax, matched by one regex.
  Keys are `[A-Za-z0-9_-]+`, indices are non-negative integers.
- A reference that is the whole value keeps its type (a list stays a list); inside longer text it is
  converted to a string, which is allowed only for scalar values.
- Setting `input` in `params` overrides the step's target; without it the step uses the run input.

At run time the reference is resolved just before the step starts:

| Situation | Step result |
|---|---|
| Referenced step succeeded and the path exists | runs with the resolved value |
| Referenced step succeeded but the path is missing (e.g. no A record) | `ERROR`, naming the unresolved reference; the source is not called |
| Referenced step failed, was skipped or unavailable | `SKIPPED`, even with partial results enabled, since there is no input to run on |

Resolved values go through the same redaction as everything else in reports and terminal output.

**Example** (shipped in `domain_recon`): check the exposure of the domain's first IPv4 address.

```yaml
steps:
  - id: dns_lookup
    type: dns
  - id: exposure
    type: shodan_internetdb
    depends_on: [dns_lookup]
    params:
      input: "{{ steps.dns_lookup.data.A[0] }}"
```

Only the first address is checked; iterating over every address is not supported yet.

## Cache

Source results are cached on disk (default TTL 1 hour) so repeated runs do not hit the APIs again.

```bash
secure-osint run example.com --cache-ttl 600   # custom TTL in seconds (0 = do not store)
secure-osint run example.com --no-cache        # bypass the cache for this run
secure-osint cache-audit                       # what is stored: source, redacted input, expiry, PII categories
secure-osint cache-clear                       # delete every entry
```

- Location: `$SECURE_OSINT_CACHE_DIR`, else `$XDG_CACHE_HOME/secure_osint`, else `~/.cache/secure_osint` (mode `0700`).
- Every value is encrypted with Fernet. The key comes from `SECURE_OSINT_CACHE_KEY` or from
  `~/.config/secure_osint/cache.key` (created `0600`), never from inside the cache directory.
- Cache keys are HMAC-SHA256 of source and parameters, so the directory alone does not reveal
  (or allow confirming by brute force) which targets were investigated.
- Only complete successes are cached: errors and partial results (non-empty `errors`) are not.
- Threat model: this protects copies, backups and sync of the cache directory. It does not protect
  against someone who can already read files as your user, since the key is on the same machine.

## API keys

Keys are read from the environment and from **`~/.config/secure_osint/.env`** only
(`$XDG_CONFIG_HOME/secure_osint/.env` if set). A `.env` in the current directory is never read.

```bash
mkdir -p ~/.config/secure_osint && chmod 700 ~/.config/secure_osint
printf 'VIRUSTOTAL_API_KEY=...\n' >> ~/.config/secure_osint/.env
chmod 600 ~/.config/secure_osint/.env
secure-osint keys          # shows which keys are set, never their values
```

- Variables already set in the environment win over the file.
- The file may only set the variables below and `SECURE_OSINT_*`; anything else (for example
  `SSL_CERT_FILE`, `HTTPS_PROXY`) is ignored with a warning, since it would change network behaviour.
- No `${VAR}` interpolation. A warning is printed if the file is readable by group or others.

| Variable | Needed by | Required |
|---|---|---|
| `GITHUB_TOKEN` | `github` | No, raises the rate limit |
| `VIRUSTOTAL_API_KEY` | `virustotal` (planned) | Yes, free tier 4 req/min |
| `ALIENVAULT_API_KEY` | `alienvault_otx` (planned) | Yes |
| `URLSCAN_API_KEY` | `urlscan` (planned) | Yes |
| `SHODAN_API_KEY` | full Shodan API (not implemented) | `shodan_internetdb` needs no key |

Sources without their key are skipped as `UNAVAILABLE`; the rest of the workflow still runs.

**Key redaction.** The actual values of every variable ending in `_API_KEY`, `_TOKEN` or `_SECRET`
(and the cache key) are removed from reports, terminal output and logs, whatever format they appear in.
Unconfigured keys are caught only in context (`apikey=…`, `x-apikey: …`, `key: …`): bare 64-hex and
32-character strings are deliberately left alone because they are indistinguishable from SHA-256 and
MD5 hashes, which are legitimate OSINT data.

## Configuration

| Variable | Effect |
|---|---|
| `GITHUB_TOKEN` | Authenticated GitHub API calls (higher rate limit) |
| `SECURE_OSINT_USER_AGENT` | Override the HTTP User-Agent |
| `SECURE_OSINT_TRUST_ENV=1` | Honour `HTTP(S)_PROXY`; disables DNS pinning (the proxy resolves names) |
| `SECURE_OSINT_WORKFLOW_DIR` | Directory with workflow YAML files (default: the built-in workflows shipped in the package, `secure_osint/workflows/`) |
| `SECURE_OSINT_CACHE_DIR` | Cache directory |
| `SECURE_OSINT_CACHE_KEY` | Fernet key for the cache (overrides the key file) |
| `SECURE_OSINT_WMN_PATH` | Local WhatsMyName `wmn-data.json` for the `username` step (see [WhatsMyName catalog](#whatsmyname-catalog-optional)) |
| `SECURE_OSINT_GUI_AUTH` | `user:password` login for the web interface; required to bind it to a non-loopback address |
| `SECURE_OSINT_GUI_ALLOWED_HOSTS` | Extra comma-separated `Host` names the web interface accepts (reverse proxy) |
| `SECURE_OSINT_DEBUG_HTTP=1` | Re-enable HTTP client logging (hosts and status codes; paths and PII stay redacted) |

## Development

```bash
pytest -q && ruff check . && mypy src
SECURE_OSINT_NETWORK_TESTS=1 pytest -q -k live   # opt-in tests against real DNS
pytest tests/test_ui.py --snapshot-update        # regenerate Rich snapshots after intended UI changes
scripts/ci-matrix.sh                             # same checks as CI, clean venv per Python 3.10-3.13
```

Third-party sources can be registered through the `secure_osint.sources` entry point group
(see `pyproject.toml`).

## Contributing

- Tests first: write the failing test, see it fail for the right reason, then implement.
- Before every push, run `scripts/ci-matrix.sh`: ruff check, `ruff format --check`, mypy and pytest
  in a clean venv for each Python version CI uses (the same steps as GitHub CI). A push that turns CI red is a wasted cycle.
- A PR is merged only when GitHub CI is green on its current head. Merge commits only, no squash.
- Commit messages follow Conventional Commits (`feat:`, `fix:`, `docs:`, `ci:`, `test:`, `refactor:`).

### Stacked PRs (house rule v2)

When PRs are stacked (PR N+1 targets PR N's branch instead of `main`):

1. Merge PR N into `main`.
2. **Before merging PR N+1, retarget its base to `main`** (PR page, "Edit" next to the title, change
   the base). Only then merge it.
3. Delete a branch only after checking that its content is in `main`.

Merging PR N+1 while it still targets PR N's branch puts its commits into that branch, not into
`main`: GitHub shows it as merged, yet `main` does not contain it. GitHub retargets automatically
only when the base branch is deleted after its merge. When in doubt, check with
`git merge-base --is-ancestor origin/<branch> origin/main`.

## License

- **Code:** MIT License — see [`LICENSE`](LICENSE).
- **Acceptable use:** [`ACCEPTABLE_USE_POLICY.md`](ACCEPTABLE_USE_POLICY.md). It states the software is
  provided "AS IS" with no warranty, that the end user is solely responsible for compliance with local
  privacy law (GDPR, CCPA, and others), and that any use for stalking, illegal doxxing, harassment, or
  unauthorized access is strictly prohibited.

This project uses an **open-source model**: the code is MIT-licensed and those rights are irrevocable,
so a policy violation cannot revoke your license to the source. What the Acceptable Use Policy governs
is **official services** — support, premium/hosted API integrations, and maintainer-distributed
binaries — which the maintainers may terminate on violation. Neither document is legal advice; consult
legal counsel before offering commercial services around the tool.

