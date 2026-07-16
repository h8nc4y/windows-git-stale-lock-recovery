# Post-Merge Local Sync — Recipe

`gh pr merge` often succeeds on the GitHub side and then fails only in its
**local** post-processing (branch switch / fast-forward / branch delete)
because a sandboxed git left a stale `index.lock`. The remote merge is
done; only your clone is out of line. This recipe brings it back safely.

Placeholders: `<repo>`, `<pr-number>`, `<default>` (the repository's
default branch — do not assume `main`). The `git` commands below are
location-independent thanks to `-C <repo>`; run the `gh` commands inside
`<repo>`, or name the repository explicitly so they do not depend on the
current directory (`gh pr view <pr-number> --repo <owner>/<name>` /
`gh repo view <owner>/<name>`).

## 1. Confirm the remote side actually merged

```powershell
gh pr view <pr-number> --json state,mergedAt
# expect: "state": "MERGED" with a mergedAt timestamp
```

If the state is not `MERGED`, this is not the post-merge case — stop here
and treat the failure on its own terms.

## 2. Clear the stale lock (five-point check first)

Run the full check from
[five-point-check-checklist.md](five-point-check-checklist.md), then delete
only the lock file:

```powershell
Remove-Item -LiteralPath '<repo>\.git\index.lock' -Confirm:$false
```

## 3. Check which branch you are on — before any fast-forward

```powershell
git -C <repo> branch --show-current
```

**This is the hazard step.** After a failed `gh pr merge`
post-processing, you are usually still on the feature branch. If you run
the fast-forward while still on it, `--ff-only` protects history, but the
command silently advances the *feature branch's* ref to origin's default
branch — the wrong ref moves, and the mistake is easy to miss.

## 4. Find the default branch name (do not hardcode it)

```powershell
gh repo view --json defaultBranchRef -q .defaultBranchRef.name
```

Repositories still commonly use `master` or custom names; hardcoding
`main` breaks the recipe quietly.

## 5. Switch, then fast-forward

```powershell
git -C <repo> switch <default>
git -C <repo> fetch --prune
git -C <repo> merge --ff-only origin/<default>
```

`--ff-only` is deliberate: if the local default branch cannot be
fast-forwarded (unexpected local commits), the command refuses instead of
creating a surprise merge commit — investigate before going further.

## 6. Verify

```powershell
git -C <repo> --no-optional-locks status          # clean, no lock warning
git -C <repo> rev-parse <default> origin/<default> # the two hashes match
Test-Path -LiteralPath '<repo>\.git\index.lock'    # False
```

Git Bash equivalents:

```bash
GIT_OPTIONAL_LOCKS=0 git -C <repo> status
git -C <repo> rev-parse <default> origin/<default>
test -e <repo>/.git/index.lock && echo "lock still present" || echo "no lock"
```

## Why this ordering matters

1. **PR state first**: if the remote merge did not happen, deleting locks
   and fast-forwarding solves nothing and can mask the real failure.
2. **Lock second**: the five-point check needs the lock still in place to
   inspect; and later steps need it gone.
3. **Branch check third**: the wrong-branch fast-forward is the one
   mistake in this flow that moves a ref you did not intend to move.
4. **Default-branch discovery fourth**: hardcoded `main` fails silently on
   `master` repositories.

Treat the `index.lock` warning from `gh pr merge` itself as harmless
post-processing noise from sandboxed git — not as evidence of concurrent
work.
