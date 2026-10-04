# Security Policy

`secure-osint` processes untrusted data (responses from public services, workflow files, user-supplied
targets) and writes reports that may contain personal data. We take reports about weaknesses in that
handling seriously and appreciate coordinated disclosure.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x (latest release) | Yes: security fixes are released as 1.0.x patch versions |
| `main` branch | Yes: fixes land here first |
| Pre-1.0 snapshots | No |

Only the latest patch release receives fixes. Please check that the issue still reproduces on the latest
release or on `main` before reporting it.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub's private vulnerability reporting:

1. Go to <https://github.com/fogaz-code/OSINT-/security/advisories/new> (repository **Security** tab,
   then **Report a vulnerability**).
2. Describe the issue. Where you can, include:
   - the affected version or commit and your OS / Python version;
   - the impact (what an attacker gains, and under which preconditions);
   - minimal steps to reproduce or a proof of concept, preferably against a local test server rather
     than a real third-party service;
   - any logs or reports involved, **with real personal data and secrets removed**.

The report stays visible only to you and the maintainers. If the form is not available to you, open a
public issue that asks for a private contact channel **without any technical details**, and we will get
back to you.

## What happens next

| Step | Target |
|---|---|
| Acknowledgement of your report | within 5 business days |
| Initial assessment (confirmed or not, severity) | within 10 business days |
| Fix released for a confirmed issue | within 90 days, sooner for high severity |

We work on the fix in a private advisory fork, keep you informed of the progress, and may ask you to
verify it. Once a fixed release is available we publish a GitHub Security Advisory, request a CVE when
appropriate, and credit you unless you prefer to remain anonymous. Please keep the details private
until the advisory is published, or until 90 days have passed if we have stopped responding.

## Scope

In scope: vulnerabilities in this repository's code, packaged workflows and CI configuration, for
example:

- bypasses of the SSRF protections of the HTTP client (reaching private, loopback, link-local or
  metadata addresses, including through redirects, DNS rebinding or alternative IP encodings);
- personal data or secrets that survive redaction in reports, exports, graphs, logs or the cache
  (logs must always be fully redacted);
- unsafe handling of workflow YAML, references between steps, report paths or workflow names (code
  execution, path traversal, arbitrary file write or deletion);
- script or HTML injection in the generated reports and graph pages, or graph pages that load remote
  resources;
- tampering with the local result cache leading to code execution or file access outside it;
- the web interface starting on a non-loopback address without authentication, or bypassing that
  authentication;
- a workflow or source that executes a pivot, uploads target data to a third party, or performs
  authenticated scraping or account-recovery probing, contrary to the product rules in the README;
- weaknesses in the GitHub Actions workflows (script injection, over-broad token permissions,
  unpinned actions).

Out of scope:

- vulnerabilities in third-party services that the tool queries (report them to their owners) and in
  dependencies, unless `secure-osint` uses the dependency in a vulnerable way;
- attacks that require an attacker who already controls the user's account or machine (except where
  the tool's own documentation claims protection, such as the cache encryption);
- resource exhaustion caused by the user's own workflow or input on their own machine;
- the fact that public information about a person can be found: that is what the tool does. Misuse of
  the tool is covered by the [Acceptable Use Policy](ACCEPTABLE_USE_POLICY.md), not by this policy;
- missing hardening without a demonstrated impact, automated scanner output without a proof of concept,
  and social engineering of maintainers or users.

## Testing safely

Test against your own infrastructure or local servers. Do not run proofs of concept against third-party
services or real people, do not access data that is not yours, and do not degrade any service. Good-faith
research that follows this policy will not be pursued or reported by the maintainers.
