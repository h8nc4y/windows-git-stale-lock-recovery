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

Raw process command lines are local/private evidence only because they may
contain a credential-bearing remote URL or internal location. Public reports
must provide only the command class (`no git.exe`, `read-only`, or
`index-writing`) and use `<repo>` placeholders instead of a private path.
If a maintainer needs the raw evidence, use private vulnerability reporting.

## PowerShell Module Cache Boundary

Windows PowerShell 5.1 writes `ModuleAnalysisCache` asynchronously after
module discovery. If its cache path is relative—such as when a restricted
host cannot resolve the normal local application-data location—a successful
long-running validation can otherwise leave a `Microsoft/Windows/PowerShell`
tree in the invocation working directory.

Every repository PowerShell entrypoint therefore bootstraps into a child of
the same host before validation or scanning begins. The entrypoint's initial
.NET-only phase points the current parent at `NUL` on Windows or `/dev/null`
on non-Windows before cmdlet or module discovery. The child inherits that
value before PowerShell starts, as
required by the Microsoft cache contract, and runs only when the launcher
marker and exact platform sink both matched before the entrypoint overwrote
the current parent. An ambient marker paired with a relative path cannot skip
the relaunch.

The platform null device creates no cache namespace entry. Consequently the
cache boundary performs no temporary-directory resolution and no cleanup;
repository aliases, attacker-selected `TEMP` / `TMP`, reparse points, and
validate-to-delete races cannot redirect cache creation or deletion. The
launcher also inherits the parent's raw standard handles, preserves the exact
child exit code, and strips its cache path and isolation marker before native
Git is launched. A missing helper fails closed with a fixed diagnostic.

Supported commands use `-NoProfile -File`, so the first entrypoint operation
precedes module discovery. A profile or long-lived embedded host that already
performed module discovery before invoking the script is outside this
bootstrap guarantee; start a fresh documented CLI process in that case.

## Entrypoint Root Diagnostic Boundary

The scanner, its self-test, and the readiness validator distinguish an omitted
`-Path` from an explicitly empty or whitespace-only value. Only omission may
select the repository root. An invalid explicit scope fails closed before the
entrypoint can silently inspect a different tree.

Root-resolution failure emits only the entrypoint-specific
`scan-root-resolution-failed`, `self-test-root-resolution-failed`, or
`readiness-root-resolution-failed` code on its documented stream. Raw supplied
paths, resolved paths, control or Format characters, and PowerShell error
framing are not replayed. Readiness success is likewise a path-free fixed
UTF-8 line rather than a resolved host path.

Synthetic bounded fixtures exercise hostile missing roots, whitespace-only
explicit roots, and a validator success path reached through an owned
hostile-name junction or symlink under both supported Windows PowerShell
hosts. They neither create nor delete a real Git lock and do not inspect or
modify another process's lock.

## Scanner Coverage

The private-marker scanner (`scripts/scan-private-markers.ps1`) is a
best-effort safety net, not a guarantee. For stage-0 regular tracked files it
scans the index blob and current worktree file as separate provenance
sources. It looks for a curated set of secret prefixes (GitHub, OpenAI, AWS,
GCP, Slack, Stripe, PEM key blocks, and similar), private-looking absolute
Windows paths, non-allowlisted GitHub repository URLs, and configured local
markers, and it redacts any matched value. Dotenv names (`.env`, `.env.*`,
and `*.env`), `.pem`, `.key`, `.tfvars`, certificate/armored-key and common
config extensions, ordinary text/source extensions, and extensionless files
are text candidates. Unlisted extensions are skipped without decoding as a
binary-safe default. It does not detect every possible secret format and is
no substitute for keeping real credentials out of the repository in the
first place. Treat a passing scan as "no known marker found," not "definitely
safe."

Git-backed enumeration is isolated from ambient repository/index/object
redirection, config injection, tracing, prompts, and user-level Git config.
The scanner requires the exact repository root and fails closed on malformed
index/probe output, conflict or intent-to-add stages, gitlinks, symlinks,
missing/reparse-point or concurrently changed worktree files, and path
escape. The root diagnostic follows the shared entrypoint boundary above. A
tracked `.private-markers.local` is rejected without printing its contents. It
clones rather than mutates its parent environment, starts each Git command with
a finite process-and-pipe deadline, disables replacement objects and lazy
promisor fetches, and enforces per-stream, per-file, entry-count, line-count,
finding-count, local-marker, and total-text limits.
The concrete index layers are capped at 100,000 stage entries, 8,192 text
entries, 4 MiB per text file, 64 MiB combined text, and 16 MiB for each raw
index-debug listing. Non-Git fallback enumerates hidden files and explicitly
excludes nested `.git` directories and leaf `.git` control files.

All index blobs share one bounded `git cat-file --batch` invocation; together
with the probe, two stage listings, and two index-debug listings, a successful
text scan uses at most six Git children regardless of tracked text-file
count. Both initial/final `ls-files -z --stage` byte streams and initial/final
`ls-files -z --stage --debug` byte streams must match exactly, and each debug
listing must reconstruct the corresponding stage stream. The raw debug flags
also reject real `git add -N` entries through `CE_INTENT_TO_ADD`, including
the nonzero empty-blob object-ID representation. Worktree content must match
across two bounded byte snapshots.

Timeout or limit failure terminates the child tree, performs a bounded
re-wait, and removes scanner-owned temporary files in `finally`. Platform
selection uses the trusted runtime API, not the ambient `OS` value. On
Windows each Git child is created suspended, assigned to a per-command
kill-on-close Job with only stdin/stdout/stderr inherited, and then resumed.
This removes the spawn-before-assignment race and reclaims a pipe-holding
orphan when its launcher exits first; POSIX descendant termination is best
effort.
Before diagnostics are printed, Unicode control/Format characters and line
or paragraph separators in paths are rendered as visible code-point escapes.
Finding amplification is capped per line (32), per file/provenance source
(256), and globally (1,000). The complete finding payload—including failure
prefix, TSV header, rows, and explicit LF separators—is converted once to
UTF-8 and must fit within 64 KiB of actual bytes; otherwise only a generic
failure code is emitted.
This boundary protects the scan target and host environment; it does not make
the marker rules complete.

## Response Expectations

Maintainers should acknowledge actionable security reports when available,
remove or redact unsafe public material, and prefer guidance that reduces
data-exposure and work-destruction risk. If real exposure is possible,
rotate the affected secret outside this public repository and document only
the remediation status.
