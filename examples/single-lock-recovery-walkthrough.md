# Single Lock Recovery — Full Walkthrough

Complete command sequence for one stuck repository, in both PowerShell and
Git Bash. Placeholders: `<repo>` is the repository's working-directory
path. This walkthrough assumes the symptom:

```text
fatal: Unable to create '<repo>/.git/index.lock': File exists.

Another git process seems to be running in this repository, e.g.
an editor opened by 'git commit'. Please make sure all processes
are terminated then try again. If it still fails, a git process
may have crashed in this repository earlier:
remove the file manually to continue.
```

Do **not** follow that last line blindly — run the five-point check first.

## PowerShell

```powershell
# Step 1 — read-only state check (creates no new lock)
git -C <repo> --no-optional-locks status

# Step 2 — running git processes and their command lines
Get-CimInstance Win32_Process -Filter "Name='git.exe'" | Select-Object ProcessId,CommandLine
# PASS when: no output, or only read-only command lines (status / config --get / rev-parse).
# FAIL when: any command line contains add / commit / merge / checkout or similar.

# Step 3 — the lock file itself (size and mtime)
Get-Item -LiteralPath '<repo>\.git\index.lock' | Select-Object FullName,Length,LastWriteTime
# PASS when: Length is 0 AND LastWriteTime predates your current work.

# Step 4 — the lock really belongs to the intended repository
git -C <repo> rev-parse --absolute-git-dir
# PASS when: the lock from step 3 sits directly under this directory.

# Step 5 — exclusive-open test (no exception = nobody holds the file)
$f = [IO.File]::Open('<repo>\.git\index.lock','Open','Read','None'); $f.Close()

# Step 6 — DESTRUCTIVE, only after steps 2-5 all passed: delete that one file
Remove-Item -LiteralPath '<repo>\.git\index.lock' -Confirm:$false

# Step 7 — re-run the blocked operation, then verify clean state
git -C <repo> add <files>
git -C <repo> --no-optional-locks status
Test-Path -LiteralPath '<repo>\.git\index.lock'   # expect False
```

## Git Bash

```bash
# Step 1 — read-only state check (creates no new lock)
GIT_OPTIONAL_LOCKS=0 git -C <repo> status

# Step 2 — running git processes: no plain POSIX equivalent of the
# command-line inspection; call PowerShell for it
powershell.exe -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='git.exe'\" | Select-Object ProcessId,CommandLine"

# Step 3 — the lock file itself (size and mtime in one listing)
ls -l <repo>/.git/index.lock

# Step 4 — the lock really belongs to the intended repository
git -C <repo> rev-parse --absolute-git-dir

# Step 5 — exclusive-open test, via PowerShell (no plain POSIX equivalent).
# Inside the quoted command, substitute <repo> in Windows form (C:\projects\repo style, not /c/...).
powershell.exe -NoProfile -Command "[IO.File]::Open('<repo>\.git\index.lock','Open','Read','None').Close()"

# Step 6 — DESTRUCTIVE, only after steps 2-5 all passed: delete that one file
rm <repo>/.git/index.lock

# Step 7 — re-run the blocked operation, then verify clean state
git -C <repo> add <files>
GIT_OPTIONAL_LOCKS=0 git -C <repo> status
test -e <repo>/.git/index.lock && echo "lock still present" || echo "no lock"
```

## If a step fails

- Step 2 shows an index-writing command line: do not delete. Retry the
  blocked operation after that process exits, at most 2-3 times, redoing
  the whole check each time.
- Step 3 shows a non-zero size or a fresh mtime: do not delete by default —
  a live or just-finished operation may own the lock. See the decision
  table in
  [five-point-check-checklist.md](five-point-check-checklist.md).
- Step 5 throws: treat the lock as held by another process — skip, report,
  and never force-delete. (A FileNotFound-style error usually means a path
  problem instead; re-check the `<repo>` substitution.)
- The same failure class three times in a row: stop and report the lock's
  path, size, mtime, and the process-check output.

## Report template

```text
repo: <repo>
lock: <repo>/.git/index.lock  size=0  mtime=<timestamp>
check 1 (no index-writing git): PASS - only short-lived "git status --porcelain" seen
check 2 (intended repo):        PASS - matches rev-parse --absolute-git-dir
check 3 (0 bytes):              PASS
check 4 (old mtime):            PASS - predates session start
check 5 (exclusive open):       PASS
action: deleted index.lock, re-ran "git add", now clean
unverified: none
```
