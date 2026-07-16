# Security Policy

This repository documents a recovery procedure for stale git lock files. It
should never contain secrets, but its guidance drives agents through a
destructive file deletion inside `.git`, so unsafe guidance is treated as a
security problem too.

## Supported Versions

The `main` branch is the supported version. Tagged releases receive fixes
through new tags on `main`.

## Reporting A Vulnerability

Use GitHub private vulnerability reporting for:

- A real secret, credential, or private identifier accidentally committed to
  this repository.
- Guidance that could cause agents to delete the wrong file (for example a
  safety condition that passes when it must not), corrupt a repository's
  `.git` contents, or run destructive commands outside the skill's scope.
- A validation gap that allows unsafe public examples.

Do not open a public issue containing tokens, credentials, private keys,
OAuth material, customer data, raw secret-bearing logs, or private
repository names and internal paths.

## Public Issue Safety

Public issues may include:

- Symptom class, such as "five-point check false pass" or "bulk cleanup
  deleted a live lock".
- Sanitized command classes, such as exclusive-open results or
  `Get-CimInstance` process-check summaries, without private paths.
- Placeholder repository, branch, and file names.

Public issues must not include:

- Secret values or secret-display command output.
- Private repository names, internal absolute paths, hostnames, or customer
  data.
- Raw agent transcripts that contain any of the above.

## Scanner Coverage

The private-marker scanner (`scripts/scan-private-markers.ps1`) is a
best-effort safety net, not a guarantee. It scans git-tracked text files for
a curated set of secret prefixes (GitHub, OpenAI, AWS, GCP, Slack, Stripe,
PEM key blocks, and similar), private-looking absolute Windows paths,
non-allowlisted GitHub repository URLs, and configured local markers, and it
redacts any matched value. It does not detect every possible secret format
and is no substitute for keeping real credentials out of the repository in
the first place. Treat a passing scan as "no known marker found," not
"definitely safe."

## Response Expectations

Maintainers should acknowledge actionable security reports when available,
remove or redact unsafe public material, and prefer guidance that reduces
data-exposure and work-destruction risk. If real exposure is possible,
rotate the affected secret outside this public repository and document only
the remediation status.
