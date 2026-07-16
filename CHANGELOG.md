# Changelog

All notable changes to this project are documented in this file.

The format loosely follows Keep a Changelog conventions.

## Unreleased

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
