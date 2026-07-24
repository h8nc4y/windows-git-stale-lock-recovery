# windows-git-stale-lock-recovery

[![Validate](https://github.com/h8nc4y/windows-git-stale-lock-recovery/actions/workflows/validate.yml/badge.svg)](https://github.com/h8nc4y/windows-git-stale-lock-recovery/actions/workflows/validate.yml)

An agent skill for Claude Code and Codex: safely recover from the stale
0-byte `.git/index.lock` (and `.git/config.lock`) files that sandboxed git
processes leave behind on Windows — built around a five-point pre-delete
safety check, a TOCTOU-aware bulk cleanup guarded by an mtime filter, and
prevention with `--no-optional-locks`.

## What It Solves

On Windows machines where agent applications (for example the Codex app)
run short-lived sandboxed git commands such as `git status --porcelain`,
git sometimes cannot unlink its own lock file from inside the sandbox. The
result is a stale, 0-byte `.git/index.lock` that blocks every later
`git add` / `git switch` / `git commit` / `git merge` with:

- `fatal: Unable to create '.../.git/index.lock': File exists`
- `Another git process seems to be running in this repository`
- `error: could not lock config file .git/config: File exists`
- `warning: unable to unlink '.git/index.lock'`

The message text suggests concurrent work, but in this failure shape there
is none — waiting does not help, and deleting blindly is how repositories
get hurt. This skill documents the middle path:

- **A five-point pre-delete check** (no index-writing git process; lock is
  under the intended repository; 0 bytes; mtime older than your current
  work; exclusive open succeeds) that must pass **in full** before the one
  destructive step.
- **Deletion scoped to exactly one file** — the lock itself, never
  `.git/index`, `.git/config`, or anything else inside `.git`.
- **A TOCTOU-aware bulk cleanup** for sweeping many repositories, where the
  mtime filter — not the start-of-run process snapshot — is the guard that
  actually holds.
- **Post-`gh pr merge` recovery** that aligns the local clone without
  silently advancing the wrong branch ref.
- **Prevention**: agent read-only checks run `git --no-optional-locks
  status` so the optional lock is never created.

## Safety Philosophy

The skill treats lock deletion as a guarded destructive operation, not a
reflex:

- If **even one** of the five checks fails, nothing is deleted — the skill
  falls back to bounded rechecks and reporting.
- The deletion target is **only the single stale lock file**, never other
  `.git` contents.
- **Killing processes and disabling the sandbox are explicitly out of
  scope**; the skill continues with kill-free alternatives or stops and
  reports.
- Field-tested behavior and design-derived-but-unverified guidance are
  kept explicitly separate in the text (see Limitations).

## Who It Is For

- Claude Code users whose Windows machines run agent apps that spawn
  short-lived sandboxed git processes.
- Codex users hitting `index.lock` failures after `gh pr merge` or during
  routine `git add` / `commit` on Windows.
- Anyone who wants a written, checkable discipline for stale-lock recovery
  instead of the usual "just delete index.lock" advice.

## Install

Clone the repository:

```bash
git clone https://github.com/h8nc4y/windows-git-stale-lock-recovery.git
cd windows-git-stale-lock-recovery
```

### Claude Code

Claude Code auto-invokes the skill when a task matches the `description`
frontmatter. Install for your user account on shells with POSIX syntax:

```bash
dest="${HOME}/.claude/skills/windows-git-stale-lock-recovery"
if [ -e "$dest" ]; then
  echo "Install target already exists: $dest"
else
  mkdir -p "$dest"
  cp SKILL.md "$dest/SKILL.md"
fi
```

Install for your user account from PowerShell:

```powershell
$dest = Join-Path $HOME '.claude\skills\windows-git-stale-lock-recovery'
if (Test-Path -LiteralPath $dest) {
  throw "Install target already exists: $dest"
}
New-Item -ItemType Directory -Path $dest | Out-Null
Copy-Item -LiteralPath .\SKILL.md -Destination (Join-Path $dest 'SKILL.md')
```

Notes:

- If you set `CLAUDE_CONFIG_DIR`, replace `~/.claude` with that directory.
- To scope the skill to a single project instead, copy `SKILL.md` to
  `.claude/skills/windows-git-stale-lock-recovery/SKILL.md` inside that
  project's repository.

The existence guard is intentional: do not overwrite an already-installed
skill without reviewing the local copy first.

### Codex (agent skills)

Manual Codex-style skill install on shells with POSIX syntax:

```bash
dest="${HOME}/.agents/skills/windows-git-stale-lock-recovery"
if [ -e "$dest" ]; then
  echo "Install target already exists: $dest"
else
  mkdir -p "$dest"
  cp SKILL.md "$dest/SKILL.md"
fi
```

Manual Codex-style skill install from PowerShell:

```powershell
$dest = Join-Path $HOME '.agents\skills\windows-git-stale-lock-recovery'
if (Test-Path -LiteralPath $dest) {
  throw "Install target already exists: $dest"
}
New-Item -ItemType Directory -Path $dest | Out-Null
Copy-Item -LiteralPath .\SKILL.md -Destination (Join-Path $dest 'SKILL.md')
```

To scope the skill to a single project instead, copy `SKILL.md` to
`.agents/skills/windows-git-stale-lock-recovery/SKILL.md` inside that
repository — Codex scans `.agents/skills` from the working directory up to
the repository root (per the official skills documentation).

If your agent reads skills from a different directory, check its
documentation and copy `SKILL.md` into the matching
`skills/windows-git-stale-lock-recovery/` folder.

## Manual Use

Reach for the skill when you see one of these symptoms:

- `git add` / `git switch` / `git commit` / `git merge` fails with
  `Unable to create '.git/index.lock': File exists`.
- git claims `Another git process seems to be running in this repository`
  but you know nothing should be writing.
- `gh pr merge` succeeded on GitHub, yet the local post-processing failed
  or warned about `index.lock`.
- `git status` leaves `warning: unable to unlink '.git/index.lock'`.
- You find 0-byte `index.lock` files with old mtimes across several
  repositories after agent sessions.

Follow the procedure in [SKILL.md](SKILL.md): confirm state read-only with
`--no-optional-locks`, check running git processes and their command lines,
inspect the lock, confirm its path, run the exclusive-open test, delete
only when all five checks pass, re-run the blocked operation, align the
local clone after a remote-side merge, and sweep multiple repositories only
with the mtime-filtered bulk cleanup.

## Synthetic Examples

- [Five-point check checklist](examples/five-point-check-checklist.md) —
  the pre-delete check as a one-page checklist with commands and a
  decision table.
- [Single lock recovery walkthrough](examples/single-lock-recovery-walkthrough.md)
  — every command for one stuck repository, PowerShell and Git Bash side
  by side.
- [Post-merge local sync recipe](examples/post-merge-local-sync-recipe.md)
  — aligning the local clone after `gh pr merge` hit the stale lock,
  including the wrong-branch fast-forward hazard.

The examples use placeholders only. Do not replace them with secrets, real
repository paths you cannot publish, or customer data in public issues.

## 日本語概要 (Japanese Overview)

Windows で sandbox 化された git プロセス（Codex アプリ等が短命に走らせる
`git status --porcelain` など）が残す 0-byte の stale `.git/index.lock` /
`.git/config.lock` から安全に復旧するための手順です。

- 削除前の**5点チェック**: git.exe プロセス不在（または index 書込コマンド
  ラインなし）／意図した repo 配下／0 bytes／mtime が現行作業より古い／
  排他 open 成功 — **1つでも欠けたら削除しない**
- 削除は当該 lock **1ファイルのみ**。`.git/index` や `.git/config` 本体には
  触れない
- プロセスの強制終了・sandbox 解除は**スコープ外**
- 複数 repo の一括掃除は mtime フィルタで TOCTOU をガード
- 予防は `git --no-optional-locks status`（lock 自体を作らない）

日本語の完全版は [docs/SKILL.ja.md](docs/SKILL.ja.md) にあります。インストールは
上記の手順どおり、`SKILL.md` を Claude Code なら
`~/.claude/skills/windows-git-stale-lock-recovery/` へ、Codex なら
`~/.agents/skills/windows-git-stale-lock-recovery/` へコピーしてください。

## Safety Notes

- Delete nothing until all five checks pass at execution time; a lock that
  fails the exclusive-open test is treated as held by another process and
  skipped, never force-deleted.
- Never touch `.git/index`, `.git/config`, or other `.git` contents; the
  stale lock file is the only deletion target.
- Never paste tokens, credentials, private logs, or customer data into
  issues or examples.

## Limitations

The skill separates field-tested behavior from design-derived guidance.
Three items are explicitly marked unverified in the skill text and stay
that way until someone measures them:

- `.git/config.lock` recovery is included as the same failure shape as
  `index.lock`, but a `config.lock` occurrence itself has not been directly
  observed.
- The one-shot bulk-cleanup command has not been run as-is in live
  operation; the measured record is per-repository individual deletion
  (path check plus exclusive open, then delete).
- The mtime threshold has no measured fixed value; `-10` minutes is a rule
  of thumb, and the real rule is "only locks that predate your current
  work."

Also, the exclusive-open test and process inspection are Windows-specific
(PowerShell); the skill targets Windows and does not attempt POSIX-native
equivalents beyond calling PowerShell from Git Bash.

## Non-Goals

- No automation scripts that delete locks for you. This repository is a
  written discipline with copy-adaptable commands, not a tool.
- No general git-internals tutorial; the focus is the sandboxed-git
  stale-lock case on Windows and its safe recovery.
- No process killing as a recovery action, no sandbox disabling, and no
  `.git` surgery beyond the single lock file. The validation scanner may
  terminate only a child process tree that it created and that exceeded its
  finite deadline.

## Validation

Run the full local validation from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate-oss-readiness.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-scan-private-markers.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\scan-private-markers.ps1
```

If `pwsh` is available, the same checks can be run with:

```powershell
pwsh -NoProfile -File .\scripts\validate-oss-readiness.ps1
pwsh -NoProfile -File .\scripts\test-scan-private-markers.ps1
pwsh -NoProfile -File .\scripts\scan-private-markers.ps1
```

On macOS, Linux, or any POSIX shell with PowerShell 7 (`pwsh`) installed:

```bash
pwsh -NoProfile -File ./scripts/validate-oss-readiness.ps1
pwsh -NoProfile -File ./scripts/test-scan-private-markers.ps1
pwsh -NoProfile -File ./scripts/scan-private-markers.ps1
```

Also run Git whitespace checks on your working changes before publishing:

```bash
git diff --check
```

The GitHub Actions workflow runs the same validation, scan self-test,
private-marker scan, and whitespace check on pull requests and pushes to
`main`. The self-test runs separately under PowerShell 7 and Windows
PowerShell 5.1 on Windows, plus PowerShell 7 on Ubuntu.

For a Git repository, pass the exact repository root. The scanner rejects a
repository subdirectory instead of silently changing scope. A missing or
otherwise unresolvable root returns only the fixed
`scan-root-resolution-failed` code; it never echoes the supplied path or raw
PowerShell error framing. The scanner scans each stage-0 regular file from
both its index blob and existing worktree path with distinct provenance.
Sensitive text candidates include dotenv names
(`.env`, `.env.*`, and `*.env`), PEM/key/config extensions, ordinary source
and documentation extensions, and extensionless files; other extensions are
skipped as binary-safe defaults. Malformed/conflict/intent-to-add/gitlink
entries, symlinks, missing/reparse-point or concurrently changed worktree
paths, path escape, and a tracked `.private-markers.local` fail closed.

Git runs in bounded child processes with cloned, sanitized environments.
Ambient `GIT_*`, user/system config, prompts, hooks, external attributes,
replacement objects, and lazy fetches are disabled. Strict UTF-8 input,
100,000-entry and 8,192 text-entry caps, 4 MiB per-file and 64 MiB total-text
caps, a 16 MiB index-debug cap, stable double worktree snapshots, bounded
pipe completion, process-tree cleanup, and `finally` cleanup limit failure
impact. Non-Git fallback enumerates hidden files but explicitly excludes both
nested `.git` directories and leaf `.git` control files.

Index blobs are read through one bounded `git cat-file --batch` process, so a
Git-backed scan uses at most six Git children: probe, initial stage listing,
initial index-debug listing, optional batch read, final stage listing, and
final index-debug listing. Both the initial/final `ls-files -z --stage` raw
byte streams and the initial/final `ls-files -z --stage --debug` raw byte
streams must match exactly. The stage records must also reconstruct exactly
from each debug listing. This rejects staged add/replacement/deletion and
flags-only mutation during the scan; real `git add -N` entries are detected
from the `CE_INTENT_TO_ADD` flag even though Git uses the nonzero empty-blob
object ID.

Windows selection uses the runtime platform API rather than the ambient `OS`
environment value. Windows creates each child suspended, assigns it to a
kill-on-close Job, limits inherited handles to its three standard streams,
and only then resumes it; POSIX descendant cleanup is best effort. See
[SECURITY.md](SECURITY.md) for the detailed boundary and limits.

Diagnostic paths escape Unicode control/Format characters (including bidi
controls, zero-width characters, and U+2028/U+2029) before output. Findings
are capped at 32 per line, 256 per file/provenance source, and 1,000 per scan;
the complete finding payload—including the failure prefix, TSV header, rows,
and explicit LF separators—is serialized once and capped at 64 KiB of actual
UTF-8 bytes. It is emitted only after the whole bounded representation is
ready.

## Related

- [windows-github-auth-diagnosis](https://github.com/h8nc4y/windows-github-auth-diagnosis)
  — sibling skill in the same Windows-agent-operations series: diagnosing
  GitHub authentication false negatives from sandboxed agent environments
  before touching credentials. Both skills exist because sandboxed git on
  Windows fails in ways that look scarier than they are.

## Contributing

Contributions are welcome when they make the recovery safer, clearer, or
easier to verify. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a
pull request.

Keep all examples synthetic. Do not include tokens, credentials, private
repository names, internal absolute paths, or customer data.

For local-only private markers, create an untracked `.private-markers.local`
file with one literal marker per line, or set
`WINDOWS_GIT_STALE_LOCK_RECOVERY_PRIVATE_MARKERS` with newline-separated
markers. The scanner reads these values but does not print the matched
marker. Each source is capped at 64 KiB, with at most 100 non-comment markers
and 1,024 characters per marker.

## Security

If you find unsafe guidance or accidental private-data exposure, follow
[SECURITY.md](SECURITY.md) and use private reporting for sensitive details.

## License

MIT. See [LICENSE](LICENSE).
