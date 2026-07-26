# Changelog

All notable changes to this project are documented in this file.

The format loosely follows Keep a Changelog conventions.

## Unreleased

### Changed

- Hardened all three PowerShell entrypoints so omitted `-Path` still selects the
  repository root while explicit empty, whitespace-only, missing, or otherwise
  unresolvable roots fail closed with entrypoint-specific fixed UTF-8
  diagnostics. Readiness success no longer replays the resolved host path.
- Added bounded PowerShell 7 and Windows PowerShell 5.1 regressions for hostile
  missing roots, whitespace-only explicit roots, and path-free readiness
  success through an owned hostile-name junction or symlink. Hosted PS5.1
  invalid-root and full-readiness children use separate 45-second and
  90-second cold-start allowances inside a 210-second cumulative phase budget
  with remaining-time child deadlines and a 20-second cleanup reserve. Every
  tree-termination, process-exit, retry, and pipe wait consumes one shared
  absolute cleanup deadline; runner and cleanup exceptions collapse to a
  fixed anonymous failure code without replaying an executable path.
- Disabled the module-analysis cache at all PowerShell validation/scanner
  entrypoints with Microsoft's platform null-device values (`NUL` on Windows,
  `/dev/null` elsewhere), then relaunched the same host once so the child
  inherits the setting before startup. The pre-overwrite marker/path pair
  prevents a marker-only ambient value from skipping relaunch. The launcher
  creates and deletes no temporary cache object, eliminating physical-alias
  and cleanup races.
- Added synthetic regressions for a relative
  `Microsoft/Windows/PowerShell/ModuleAnalysisCache` working-directory leak
  plus exact raw stdout/stderr bytes, nonzero exit propagation, edge
  arguments, same-host/one-relaunch behavior, missing-helper failure, explicit
  target `TEMP`, and junction/symlink aliases. The artifact is intentionally
  not ignored, so recurrence stays visible. The hosted primary probe has a
  bounded 120-second cold-start allowance, while synthetic timeout coverage
  proves that reaching the deadline still fails closed; missing-helper and
  explicit-target children retain their shorter individual deadlines.
- Split the hosted Windows PowerShell 5.1 full self-test into its own bounded
  job and added opt-in anonymous phase markers, after the combined Windows job
  twice reached its deadline without identifying the stalled fixture.
- Hardened git-tracked private-marker enumeration against ambient `GIT_*`
  repository/index/object/config/trace redirection by using a cloned,
  sanitized child environment with isolated config, prompt, hooks,
  attributes, excludes, template, filter/fsmonitor, and temporary-file
  boundaries.
- Added finite child-process timeouts, process-tree termination with bounded
  pipe-task waits and re-wait, strict UTF-8 stdout decoding, 4 MiB
  metadata/file and 64 MiB total-text caps, a 100,000-entry cap, cleanup in
  `finally`, and adversarial fixtures that verify target-root retention,
  behavioral removal of present-empty and unknown `GIT_*` names, output-limit
  failure, redaction, descendant cleanup, and absence of external artifacts.
- Changed Git-backed coverage to the union of stage-0 index blobs and tracked
  worktree files with explicit provenance. Repository subdirectories and
  failed probes below a discovered `.git`, malformed/conflict/intent-to-add/
  gitlink entries, tracked symlinks, missing/reparse-point or concurrently
  changed worktree paths, and path escape now fail closed.
- Disabled lazy promisor fetches and Git replacement objects so index blob
  scanning remains local-only and uses the literal staged object ID.
- Rejected tracked `.private-markers.local` files without reading their values
  as publishable content, and bounded local marker sources, source lines, and
  finding output.
- Replaced whole-source line arrays and unbounded worktree copies with
  streaming line evaluation, bounded double snapshots, and exact byte
  stability checks. Non-Git fallback now shares the same file, entry, and
  total-text limits, enumerates hidden files, and explicitly excludes nested
  `.git` directories and leaf `.git` controls.
- Added Windows scanner and per-child kill-on-close Job containment so a
  pipe-holding descendant is reclaimed even when its launcher exits before
  timeout; POSIX tree cleanup remains best effort.
- Made Windows containment atomic by creating each Git child suspended,
  assigning it to its Job with an explicit stdin/stdout/stderr handle list,
  and resuming only after assignment. Added a no-delay immediate-descendant
  fixture that proves per-command Jobs do not accumulate orphans.
- Replaced one `cat-file` process per tracked text file with one bounded
  `cat-file --batch` exchange. Git-backed scans now use at most six Git
  children and compare initial/final raw stage and index-debug enumerations,
  with fixtures that perform a real staged addition/object-ID replacement and
  a flags-only mutation during the scan. Raw debug flags reject real
  present/deleted `git add -N` entries through `CE_INTENT_TO_ADD`.
- Added a separate 8,192 text-entry bound before blob batching, incremental
  allowlist matching, and synthetic amplification fixtures for both.
- Made platform selection independent of the ambient `OS` value by using the
  runtime platform API, with Windows containment fixtures for unset and
  spoofed values.
- Converted unresolved scan roots into the fixed
  `scan-root-resolution-failed` diagnostic before PowerShell can echo a
  hostile path or error frame. Added raw stdout/stderr byte assertions for
  bidi, zero-width, and line-separator path input.
- Limited the native C# Git wrapper to Windows-only containment tests and
  added portable real-Git root, index/worktree, intent-to-add, and merge
  conflict coverage plus an Ubuntu PowerShell 7 CI job.
- Expanded binary-safe text classification to dotenv names and `.env`,
  `.pem`, `.key`, `.tfvars`, certificate, and armored-key extensions, with
  separate staged-only and worktree-only provenance fixtures.
- Escaped Unicode control/Format, bidi, zero-width, and line-separator code
  points in diagnostic paths. Added per-line, per-file, global finding, field,
  and final-output caps with synthetic amplification fixtures. The complete
  prefix/header/row payload now uses explicit LF, is serialized once, and is
  capped by actual UTF-8 bytes.
- Made the self-test retain its invoking PowerShell host and added distinct
  PowerShell 7 and Windows PowerShell 5.1 CI measurements, UTF-8 BOM checks
  for Japanese-commented scripts, and an overall job timeout.

## 0.1.0 - 2026-07-16

### Added

- Initial Windows stale-git-lock recovery skill (`SKILL.md`): the
  five-point pre-delete safety check (no index-writing git process /
  intended repository / 0 bytes / old mtime / exclusive open), a nine-step
  recovery procedure from read-only confirmation through post-`gh pr merge`
  local alignment, a TOCTOU-aware bulk cleanup guarded by an mtime filter,
  stop and prohibited conditions, and prevention with
  `--no-optional-locks`.
- Explicit honesty markers separating field-tested behavior from
  design-derived guidance: `config.lock` occurrence, the one-shot bulk
  command, and the mtime threshold are all marked unverified.
- Japanese full version of the skill (`docs/SKILL.ja.md`).
- Synthetic examples: five-point check one-page checklist, single lock
  recovery walkthrough (PowerShell and Git Bash), and post-merge local
  sync recipe.
- Private-marker scan for common secret prefixes, private-looking absolute
  paths, and non-allowlisted GitHub repository URLs, with a self-test and
  local marker support through `.private-markers.local` or the
  `WINDOWS_GIT_STALE_LOCK_RECOVERY_PRIVATE_MARKERS` environment variable.
- OSS readiness validation script for required public project files and
  skill frontmatter.
- GitHub Actions workflow for validation, private-marker scanning, and
  whitespace checks.
- Issue and pull request templates with sanitized-report guidance.
- Contributor, security, code of conduct, editor, and Git attribute
  documentation.
