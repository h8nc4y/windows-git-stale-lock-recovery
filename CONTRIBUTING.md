# Contributing

Thanks for improving this skill. This repository is intentionally small:
changes should make the stale-lock recovery safer, clearer, or easier to
verify.

## Before You Start

- Read [SKILL.md](SKILL.md) and the examples under [examples](examples).
- `SKILL.md` (English) is canonical. When you change it, update
  [docs/SKILL.ja.md](docs/SKILL.ja.md) in the same pull request so the two
  stay in sync.
- Do not paste tokens, credentials, private keys, OAuth codes, raw logs,
  customer data, private repository names, or internal absolute paths into
  issues, pull requests, commits, or examples. No token or secret value ever
  belongs in this repository.
- Use synthetic placeholders such as `<repo>`, `<workspace-root>`,
  `<pr-number>`, and `<default>` for examples.
- Put personal or organization-specific scan markers in an untracked
  `.private-markers.local` file, not in repository source. The scanner rejects
  a tracked copy and bounds local marker input to 64 KiB, 100 markers, and
  1,024 characters per marker.

## Grounding Rules

This skill's value is that every rule either traces to observed behavior or
is explicitly marked unverified. Keep it that way:

- Claims about git or lock behavior should be grounded in something
  observable (a reproducible command sequence, a measured incident). Mark
  speculation and design-derived-but-unvalidated guidance explicitly as
  unverified.
- Do not remove the existing honesty markers without evidence that changes
  their status. The three standing ones are: `config.lock` occurrence
  (unverified), the one-shot bulk-cleanup command (unverified as-is;
  measured record is per-repository deletion), and the mtime threshold
  (rule of thumb, no measured fixed value).
- Never weaken the five-point check or widen the deletion scope beyond the
  single stale lock file without an extraordinary, evidenced reason — a
  false refusal is recoverable; a wrong deletion may not be.

## Development Workflow

1. Create a focused branch.
2. Make the smallest coherent change.
3. Update examples or README text when user-facing guidance changes.
4. Add or adjust validation when a safety rule should be machine-checkable.
5. Run the validation commands before opening a pull request.

## Validation

From the repository root, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate-oss-readiness.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-scan-private-markers.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\scan-private-markers.ps1
git diff --check
```

If `pwsh` is available, it is also acceptable for the PowerShell scripts:

```powershell
pwsh -NoProfile -File .\scripts\validate-oss-readiness.ps1
pwsh -NoProfile -File .\scripts\test-scan-private-markers.ps1
pwsh -NoProfile -File .\scripts\scan-private-markers.ps1
```

The private-marker self-test always launches scanner children with the same
PowerShell host that launched the self-test. Running the `powershell` and
`pwsh` command sets above therefore provides two distinct compatibility
measurements; one invocation is not silently substituted for the other.
On Windows, the synthetic test compiles a local native Git probe wrapper to
verify the actual sanitized child environment, malformed/path-escape
rejection, the six-child batch bound, exact stage/index-debug comparison
after staged and flags-only mutations, atomic Job assignment, and descendant
cleanup. The wrapper is never built or launched on POSIX.

The portable real-Git fixtures run on Windows and POSIX. They cover exact-root
handling, index/worktree provenance, real merge-conflict stages, real
present/deleted `git add -N`, sensitive dotenv/PEM/key candidates, binary
safe-skip behavior, the 8,192 text-entry bound, incremental allowlist
evaluation, explicit nested `.git` directory/leaf exclusion, fixed raw root
diagnostics, and bounded explicit-LF UTF-8 finding output. GitHub Actions runs
the full PowerShell 7 suite on Ubuntu in addition to both Windows hosts. The
tests do not contact a service or use real credentials.

On macOS, Linux, or any POSIX shell with PowerShell 7 (`pwsh`) installed, use
forward slashes:

```bash
pwsh -NoProfile -File ./scripts/validate-oss-readiness.ps1
pwsh -NoProfile -File ./scripts/test-scan-private-markers.ps1
pwsh -NoProfile -File ./scripts/scan-private-markers.ps1
```

## Pull Request Expectations

- Explain the problem and the chosen fix.
- Include validation results.
- Call out any remaining unknowns.
- If the change alters the five-point check, the deletion scope, or the
  bulk-cleanup guard, describe the failure mode it prevents (or the false
  refusal it removes) concretely.

## Maintainer Notes

Prefer documentation and validation that prevent wrong deletions. Avoid
adding broad dependencies or network-backed checks unless they are clearly
necessary for public safety.
