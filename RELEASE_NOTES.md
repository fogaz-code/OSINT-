# Secure OSINT v1.0.0

## An Ethical, Professional-Grade Local OSINT Framework

Secure OSINT 1.0.0 is the first stable release. It gathers **publicly available information only**,
runs **entirely on your machine**, and produces reports built to stand up in a professional record:
case ID, integrity hash, and automatic redaction of personal data.

It is designed for licensed private investigation, corporate due diligence, and personal
digital-footprint self-audits. It deliberately does **not** scrape behind logins, use breach or leak
databases, or run probes that violate platforms' terms of service. That restraint is the point: every
finding in a report comes from a documented, lawful method you can defend.

---

## Key features

### Username presence across 23 platforms, with honest auth-wall handling
- **19 platforms checked automatically:** GitHub, GitLab, Bitbucket, Keybase, Reddit, Hacker News,
  Telegram, TikTok, Pinterest, Medium, Dev.to, Stack Overflow, CodePen, Docker Hub, PyPI, Hackaday,
  Mastodon (mastodon.social), about.me, SourceForge.
- **4 platforms flagged for manual verification, never queried:** LinkedIn, Instagram, Facebook, X.
  They require an authenticated session, so the tool reports them as
  "Platform requires authenticated session; manual verification recommended" instead of scraping
  them or guessing.
- Results are three-valued: found, not found, or **undetermined**. A block (HTTP 429/451/999) or an
  auth wall (401/403) is reported as undetermined with a reason, never as a false "not found".

### Phone and email checks, privacy-first
- **Phone validation is fully offline** (via `phonenumbers`): validity, region, location, carrier and
  line type, with no network request at all.
- **Email checks use three public lookups**, stated plainly: a Gravatar profile lookup, a
  disposable-domain check (Kickbox) and a DNS resolution of the domain. Note that Gravatar receives an
  MD5 hash of the address, which is effectively reversible for known emails. There is no mailbox
  enumeration or SMTP probing.
- **Automatic redaction:** emails, phone numbers, IP addresses, API keys, and financial and crypto
  identifiers are redacted in reports by default. Phone numbers and IPs are shown only with the
  explicit `--keep-network` flag. Reports are written with owner-only (`0600`) permissions.

### Automated Entity Correlation Summaries (100% local)
Every report opens with a summary of the unique entities observed across all steps: usernames,
emails, domains and infrastructure (IPs and hosts). The JSON report carries the same data as a
root-level `correlations` object that tools such as Maltego or custom dashboards can parse.
- Built only from data already collected: **no extra network calls**.
- Follows the same redaction rules as the rest of the report.
- Labelled for what it is: **co-occurrence observations, not verified identity links**.

### Local web interface with a server-side ethical gate
- `secure-osint gui` opens a dark-themed browser interface (Gradio) for non-technical users:
  investigators, HR and auditors.
- The Acceptable Use Policy is summarized on the page, and **Run stays disabled until the user
  accepts it**. The same check is **enforced on the server**, so it cannot be bypassed by calling the
  app directly.
- Private by default: it listens on `127.0.0.1` only, never creates a public share link, has
  telemetry off, and purges temporary report copies after an hour.
- Optional install (`secure-osint[gui]`), so command-line installs and standalone binaries stay lean.

### Forensic-grade reporting
- **Case ID tracking** (`--case-id` in the CLI, a field in the web interface) stamped on JSON and
  Markdown reports for chain of custody. The CLI also records it in the run log with
  `--log-level INFO`.
- **SHA-256 integrity hash** on every report: over the canonical JSON body, and in a footer covering
  the Markdown content. It is **tamper-evident, not a digital signature**: anyone who edits a report
  can recompute the hash. To prove integrity later, record the hash separately at the time the
  report is produced (for example in your case file).
- A legal disclaimer in every report places verification and privacy-law compliance with the end
  user.

### Engineering foundations
- **Workflows** in YAML, run as a parallel dependency graph with per-step timeouts, retries with
  jittered backoff, and per-host rate limiting and circuit breaking. Seven built-in workflows:
  domain, email, generic, GitHub, IP, phone, username.
- **Ten sources:** crt.sh, DNS, email, GitHub, HackerTarget, phone, RDAP, Shodan InternetDB,
  username, Wayback Machine.
- **Hardened HTTP client:** DNS-pinned SSRF protection that blocks private, loopback, link-local and
  cloud-metadata addresses.
- **Encrypted on-disk result cache** (Fernet, with HMAC-keyed entries), opt-out with `--no-cache`.
- **Portable packaging:** the workflows ship inside the package, so installs and standalone binaries
  run from any directory.
- Tested on Python 3.10, 3.11, 3.12 and 3.13.

---

## Legal & compliance

- **License:** the source code is **MIT**-licensed (`LICENSE`).
- **Acceptable Use Policy** (`ACCEPTABLE_USE_POLICY.md`): use is limited to authorized purposes.
  Stalking, illegal doxxing, harassment and unauthorized access are strictly prohibited. The end user
  is solely responsible for compliance with privacy law (GDPR, CCPA and others). Because the code is
  MIT-licensed, the policy governs **official services** (support, premium integrations,
  maintainer-distributed binaries), which can be terminated for violations.
- **Security policy** (`SECURITY.md`): report vulnerabilities privately, not in public issues.

This software is provided "as is", without warranty. None of these documents is legal advice.

---

## Installation

Requires Python 3.10 or newer.

**From the release wheel** (the file you distribute to clients; build it with `python -m build`
from a checkout of `v1.0.0`):

```bash
pipx install ./secure_osint-1.0.0-py3-none-any.whl
pipx install "./secure_osint-1.0.0-py3-none-any.whl[gui]"     # with the web interface

secure-osint --help
secure-osint gui          # web interface, if installed with [gui]
```

**From source** (requires access to the repository, which is currently private):

```bash
pipx install "git+https://github.com/fogaz-code/OSINT-.git@v1.0.0"
```

**From PyPI:** `pipx install secure-osint` will work once the package is published (not yet).

### Standalone executable for clients without Python

```bash
pip install ".[build]"          # inside a virtual environment, from a checkout of v1.0.0
scripts/build-binary.sh         # builds dist/secure-osint and smoke-tests it outside the repo
```

Build on the same operating system you are targeting. The script aborts if the workflows are not
bundled.

---

## Known limitations

Stated up front, so they don't surprise a client later:

- **Not yet on PyPI, and the repository is private.** Clients install from the wheel file or use a
  standalone binary. Installing from git works only for accounts with repository access.
- **Standalone binaries were built and tested on Linux only.** Windows and macOS binaries must be
  built on those systems. Test them on a clean machine of the target OS before shipping.
- **Username detection for the newest platforms is verified against mocked responses.** Platforms
  change their behaviour over time. Anything that becomes undeterminable is reported as such, never
  as a false "not found". Spot-check critical findings manually.
- **Contact:** security reports go through GitHub private vulnerability reporting (see SECURITY.md);
  everything else through repository issues. No personal e-mail address is published.
