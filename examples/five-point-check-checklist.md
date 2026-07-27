# Five-Point Pre-Delete Check — One-Page Checklist

Print-friendly summary of the safety check in [SKILL.md](../SKILL.md).
Delete the stale lock **only when all five rows pass**. One failing row =
no deletion.

| # | Condition | Command (PowerShell) | Pass looks like |
| --- | --- | --- | --- |
| 1 | No index-writing `git.exe` | `Get-CimInstance Win32_Process -Filter "Name='git.exe'" \| Select-Object ProcessId,CommandLine` | No output, or only read-only command lines (`status`, `config --get`, `rev-parse`, ...) |
| 2 | Lock is under the intended repo | `git -C <repo> rev-parse --absolute-git-dir` | The lock's directory equals that git dir |
| 3 | Lock is 0 bytes | `Get-Item -LiteralPath '<repo>\.git\index.lock' \| Select-Object Length` | `Length` is `0` |
| 4 | mtime predates your current work | `Get-Item -LiteralPath '<repo>\.git\index.lock' \| Select-Object LastWriteTime` | Older than anything you started this session (no measured fixed threshold — unverified) |
| 5 | Exclusive open succeeds | `$f = [IO.File]::Open('<repo>\.git\index.lock','Open','Read','None'); $f.Close()` | No exception |

Git Bash equivalents where they exist:

```bash
GIT_OPTIONAL_LOCKS=0 git -C <repo> status        # read-only state check (creates no lock)
ls -l <repo>/.git/index.lock                     # covers rows 3 and 4 (size + mtime)
git -C <repo> rev-parse --absolute-git-dir       # row 2
# Row 5 has no plain POSIX equivalent; call PowerShell for that one step.
# Inside the quoted command, substitute <repo> in Windows form (C:\projects\repo style, not /c/...).
powershell.exe -NoProfile -Command "[IO.File]::Open('<repo>\.git\index.lock','Open','Read','None').Close()"
```

## Decision table

| Situation | Action |
| --- | --- |
| All five pass | Delete **that one lock file only**, then re-run the blocked git operation |
| Row 1 fails (an index-writing git is running) | Do not delete. Wait for that specific process with a bounded recheck (2-3 retries), redoing all five checks each time |
| Row 3 fails (lock is not 0 bytes) | Do not delete by default. Only if the remaining four pass AND the immediately preceding operation verifiably completed, deletion is acceptable (field-tested shape) |
| Row 4 fails (mtime is fresh) | Do not delete — this may be a live operation. Recheck after your current work settles |
| Row 5 fails (open throws) | Do not delete. Treat the lock as held by another process; skip and report. No forced deletion, no retry |
| Same failure class three times in a row | Stop. Keep raw evidence local; a sanitized public report uses `<repo>` for the lock and only the process command class |

## What deletion is allowed to touch

```text
<repo>/.git/index.lock     <- the ONLY deletion target (or config.lock for that shape)
<repo>/.git/index          <- never
<repo>/.git/config         <- never
anything else in .git/     <- never
```

Killing git processes and disabling the sandbox are out of scope — if the
checks cannot pass without that, stop and report instead.
