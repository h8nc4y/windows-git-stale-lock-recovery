---
name: windows-git-stale-lock-recovery
description: >-
  Safely recover from stale 0-byte .git/index.lock or .git/config.lock files
  left behind on Windows by sandboxed git processes (agent apps running
  short-lived git status or config reads). Use on symptoms like "fatal:
  Unable to create '.git/index.lock': File exists", "Another git process
  seems to be running in this repository", "error: could not lock config
  file .git/config: File exists", or "warning: unable to unlink
  '.git/index.lock'", when git add / switch / commit / merge or the local
  post-processing after gh pr merge is blocked. Covers a five-point
  pre-delete safety check, TOCTOU-aware bulk cleanup guarded by an mtime
  filter, and prevention with --no-optional-locks.
---

# Recovering Safely from Stale Git Locks on Windows

Procedure for recovering from a stale `.git/index.lock` (or
`.git/config.lock`) on Windows without destroying anyone's in-flight work.
The core is a five-point safety check that must fully pass before the one
destructive step (deleting the lock file), plus a TOCTOU-aware bulk cleanup
and prevention with `--no-optional-locks`.

## When To Use

- `git add` / `git switch` / `git commit` / `git merge` fails with
  `Unable to create '.git/index.lock': File exists`.
- `gh pr merge` succeeded on the GitHub side, but only the local update
  failed or warned about `index.lock` (treat it as harmless
  post-processing).
- `git status` leaves `warning: unable to unlink '.git/index.lock'`.
- The lock file is 0 bytes and its mtime is older than your current work.

Root cause: a sandboxed git process — for example, an agent application
such as the Codex app running a short-lived `git status --porcelain` or a
config/remote read — creates the lock, then exits unable to unlink it from
inside the sandbox, leaving a 0-byte lock behind. This is **not concurrent
work**, so do not keep waiting on the assumption that "another git process
is running." Apply the same procedure to `.git/config.lock` as the same
failure shape (honesty note: the measured records behind this skill are
mostly `index.lock`; the occurrence of `config.lock` itself is
unverified).

## Procedure

1. **Confirm the current state read-only**, using a method that does not
   create new locks.
   - PowerShell: `git -C <repo> --no-optional-locks status`
   - Git Bash / POSIX shells: `GIT_OPTIONAL_LOCKS=0 git -C <repo> status`
2. **Check running git processes and their command lines** (PowerShell).

   ```powershell
   Get-CimInstance Win32_Process -Filter "Name='git.exe'" | Select-Object ProcessId,CommandLine
   ```

   Short-lived `git status` processes from agent applications (for example
   the Codex app) can appear frequently. Confirm that **no** command line
   belongs to an index-writing operation (add / commit / merge / checkout,
   and similar). Treat the raw process listing as local/private evidence:
   command lines can contain private paths or credential-bearing remote
   URLs. Do not paste that raw output into a public or external report.
3. **Inspect the lock file itself.**
   - PowerShell: `Get-Item -LiteralPath '<repo>\.git\index.lock' | Select-Object FullName,Length,LastWriteTime`
   - Git Bash: `ls -l <repo>/.git/index.lock`
4. **Confirm the lock path is under the intended repository.** Only target
   locks directly under the directory reported by
   `git -C <repo> rev-parse --absolute-git-dir`.
5. **Exclusive-open test** (PowerShell). If the file opens without an
   exception, no other process is holding it.

   ```powershell
   $f = [IO.File]::Open('<repo>\.git\index.lock','Open','Read','None'); $f.Close()
   ```

   From Git Bash there is no plain POSIX equivalent of a Windows exclusive
   open; call PowerShell for this one step:

   ```bash
   powershell.exe -NoProfile -Command "[IO.File]::Open('<repo>\.git\index.lock','Open','Read','None').Close()"
   ```

   In this one call, substitute `<repo>` in Windows form — for example
   C:\projects\repo rather than /c/projects/repo — because .NET does not
   resolve Git Bash style paths, and MSYS2 path conversion does not apply
   inside a quoted `-Command` string.

6. **[Destructive] Delete the lock** — only when the five-point check in
   "Safety Conditions" passes in full, and delete only that one lock file.
   - PowerShell: `Remove-Item -LiteralPath '<repo>\.git\index.lock' -Confirm:$false`
   - Git Bash: `rm <repo>/.git/index.lock`
7. **Re-run the blocked git operation.** Serialize git index operations on
   the same repository — running `git add` and `git status` in parallel on
   one repository reproduced the lock collision (field-tested).
8. **If the failure followed `gh pr merge`**: the merge on the GitHub side
   has usually already succeeded. Check the PR state first, then handle the
   lock, then bring the local clone back in line. **Always check the
   current branch before switching to the default branch and
   fast-forwarding** — in this situation you are often still on the feature
   branch, and running the merge while still on it would silently advance
   the feature branch's ref to origin's default branch (no history is
   destroyed, because of `--ff-only`, but the ref move is wrong). Do not
   hardcode the default branch name; it differs per repository (main /
   master / others).

   ```powershell
   gh pr view <pr-number> --json state,mergedAt
   # if MERGED: five-point check -> delete lock -> align local state
   git branch --show-current          # check the current branch (often still the feature branch)
   gh repo view --json defaultBranchRef -q .defaultBranchRef.name   # find the default branch name
   git switch <default>
   git fetch --prune
   git merge --ff-only origin/<default>
   ```

   The same commands work unchanged in POSIX shells.
9. **Bulk cleanup across multiple repositories.** Honesty note: the
   measured record behind this skill is **per-repository individual
   deletion** (path check plus exclusive-open confirmation in each
   repository, then delete); the one-shot bulk command below has not been
   run as-is in live operation (unverified). Example (PowerShell):

   ```powershell
   # Example (this one-shot bulk command itself is unverified; the measured record is per-repo deletion)
   # Every path-bearing line from this block is local/private audit evidence. Sanitize it before external sharing.
   Get-CimInstance Win32_Process -Filter "Name='git.exe'"   # no output = no git right now (start-of-run snapshot)
   Get-ChildItem <workspace-root>\*\.git\index.lock -ErrorAction SilentlyContinue |
     Where-Object { $_.Length -eq 0 -and $_.LastWriteTime -lt (Get-Date).AddMinutes(-10) } |
     ForEach-Object {
       $lock = $_
       try {
         # Condition 5: per-lock exclusive-open test. A lock that cannot be opened is treated as held by another process and skipped.
         $f = [IO.File]::Open($lock.FullName,'Open','Read','None'); $f.Close()
         Remove-Item -LiteralPath $lock.FullName -Confirm:$false
         $lock.FullName   # print each deleted lock for the local/private audit only
       } catch {
         Write-Warning "Skipped (exclusive open or delete failed; no forced delete, no retry): $($lock.FullName)"
       }
     }
   ```

   - Replace `<workspace-root>` with the parent directory that holds your
     repositories (for example C:\projects on Windows).
   - The start-of-run `git.exe` check is only a snapshot; it cannot close
     the window in which a new git process starts mid-sweep (TOCTOU). **The
     mtime filter — only locks older than your current work — is the guard
     that actually matters**: a lock created by a new git process during
     the sweep has a fresh mtime and falls outside the filter. The `-10`
     minutes is a rule of thumb, not a measured threshold (unverified); the
     essence is "delete only locks that predate your current work."
   - The five-point check applies per lock even in bulk cleanup. Condition
     2 (intended repository) is substituted here by the glob pattern
     `<workspace-root>\*\.git\index.lock` (it matches only a `.git`
     directly under each repository root), so list the full paths of the
     deleted locks in the local audit record and state that the substitution
     was used.
   - For bulk cleanup, the full-path output is local/private audit evidence.
     Sanitize every path to a placeholder such as
     `<repo>/.git/index.lock` before public or external sharing.

## Safety Conditions

Perform the deletion (the one destructive operation) only when **all five**
of the following hold:

1. No `git.exe` process is running — or none of the running ones has a
   command line that writes the index.
2. The lock path is under the intended repository's `.git`.
3. The file is 0 bytes.
4. The mtime is old (it predates your current work; no measured fixed
   threshold exists — unverified).
5. An exclusive open succeeds.

Stop / prohibited conditions:

- If even one of the five fails, do not delete. Re-check with a bound (for
  example: retry the blocked git operation at most 2–3 times, redoing the
  five-point check each time; no unbounded waiting, no foreground sleep, no
  "leave it to clear on its own"). If the same failure class does not
  improve after three attempts, stop and report the situation through the
  sanitized boundary below.
- Delete only the lock file itself. Never touch `.git/index`,
  `.git/config`, or anything else inside `.git`.
- Killing processes and disabling the sandbox are out of scope for this
  skill. Even when a kill looks necessary, do not block waiting for a human
  decision; record the situation (process IDs, command lines, and the
  lock's path/size/mtime) as local/private evidence, and continue with
  kill-free alternatives (serialization, bounded rechecks). If that does not
  improve after three attempts, stop and report through the sanitized
  boundary below.
- The five-point check applies per lock even in bulk cleanup. Because the
  process check (condition 1) is only a start-of-run snapshot, the mtime
  filter and the per-lock exclusive open (condition 5) are mandatory; skip
  the lock when the exclusive open or delete fails (no forced deletion, no
  retry). Retain the actual path locally and report only its sanitized
  placeholder and reason. When part of the five-point check is substituted
  by a filter, name the substituted condition in the report.
- As a rule, do not delete locks that are not 0 bytes. A lock the same size
  as the index has been observed left behind after a completed operation
  (field-tested); even then, delete only when the remaining four conditions
  hold and you can confirm that the immediately preceding operation
  completed.
- If the same failure does not improve after three attempts, stop and retain
  the actual lock path, size, mtime, and process-check results as
  local/private evidence. A public or external stop report must use the
  sanitized lock placeholder and process command class described below.

## Completion Checklist

- The blocked git operation (add / switch / commit / merge / local
  fast-forward) succeeded.
- `git --no-optional-locks status` looks as expected (no warnings; only the
  expected diff).
- No new lock remains in the target repository.
- (For post-merge alignment) the local default branch (main / master, etc.
  — it differs per repository) matches `origin/<default>`.

## Reporting

- **Local/private evidence:** retain the target repository, actual lock path,
  size, mtime, and the raw process listing only for the bounded deletion
  decision and a protected audit record. Do not copy credential-bearing
  output into a ticket or chat.
- **Public or external report:** replace repository and lock paths with
  placeholders such as `<repo>/.git/index.lock`. Summarize the process check
  only as a command class (`no git.exe`, `read-only`, or `index-writing`);
  omit PIDs, raw command lines, remote URLs, and environment values.
- Report the result of each five-point check, the deleted/skipped lock
  placeholders and reasons, any condition substituted by a filter, and the
  re-run git operation's result.
- If protected raw evidence is necessary for a security investigation, keep
  it out of public channels and use the repository's private security
  reporting path.
- Mark anything you could not confirm as "unverified." Never assert values
  you did not measure.

## Prevention

- Agent read-only checks should always use `git --no-optional-locks status`
  (or `GIT_OPTIONAL_LOCKS=0`), which avoids creating the optional lock in
  the first place.
- Do not run git index operations on the same repository in parallel
  (serialize them).
- Treat an `index.lock` warning after `gh pr merge` as "sandboxed git could
  not clean up; harmless post-processing," not as concurrent work.

## Provenance

This skill is distilled from repeated real-world agent operations on Windows
development machines where sandboxed agent applications run short-lived git
commands. Except for the three items noted below, every rule above traces
back to an observed failure or a verified recovery, not to speculation;
"field-tested" marks behavior that was actually hit and worked around in
practice. Three items are design-derived and not yet validated in live
operation, and are explicitly kept marked as such:

- `.git/config.lock`: its occurrence has not been directly observed; it is
  included because it is the same failure shape as `index.lock`
  (unverified).
- The one-shot bulk-cleanup command in step 9: the measured record is
  per-repository individual deletion (path check plus exclusive open, then
  delete); the one-shot form itself has not been run as-is (unverified).
- The mtime threshold: no measured fixed value exists; `-10` minutes is a
  rule of thumb, and the real rule is "only locks that predate your current
  work" (unverified).
