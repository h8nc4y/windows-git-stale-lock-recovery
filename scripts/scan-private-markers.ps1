[CmdletBinding()]
param(
    [string]$Path = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptRoot)) {
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}

if ([string]::IsNullOrWhiteSpace($Path)) {
    $Path = Split-Path -Parent $scriptRoot
}

$root = (Resolve-Path -LiteralPath $Path).Path
# This repository's own URL plus the public sibling skill repository that
# README.md cross-links in its Related section.
$allowedRepoUrlPattern = '^https://github\.com/h8nc4y/(?:windows-git-stale-lock-recovery|windows-github-auth-diagnosis)(?:\.git)?$'

$rules = New-Object System.Collections.Generic.List[object]

function Add-ScanRule {
    param(
        [string]$Name,
        [string]$Pattern,
        [ValidateSet('literal', 'regex')]
        [string]$Kind,
        # Optional: suppress regex matches whose value is a known-safe placeholder.
        # This keeps documentation examples from becoming noisy findings.
        [string]$Allowlist = ''
    )

    if ([string]::IsNullOrWhiteSpace($Pattern)) {
        return
    }

    $rules.Add([pscustomobject]@{
        Name = $Name
        Pattern = $Pattern
        Kind = $Kind
        Allowlist = $Allowlist
    }) | Out-Null
}

Add-ScanRule -Name 'openai-api-key-prefix' -Pattern '(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{16,}' -Kind 'regex'
Add-ScanRule -Name 'github-classic-token-prefix' -Pattern ('g' + 'hp_') -Kind 'literal'
Add-ScanRule -Name 'github-fine-grained-token-prefix' -Pattern ('github' + '_pat_') -Kind 'literal'
Add-ScanRule -Name 'slack-bot-token-prefix' -Pattern ('xo' + 'xb-') -Kind 'literal'
Add-ScanRule -Name 'bearer-token-header' -Pattern ('Bearer' + ' ') -Kind 'literal'
Add-ScanRule -Name 'private-key-block' -Pattern ('BEGIN ' + 'PRIVATE KEY') -Kind 'literal'
Add-ScanRule -Name 'email-address' -Pattern '\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b' -Kind 'regex'
# windows-absolute-path detects private-looking absolute Windows paths while allowing
# documented placeholders. The regex stops before bracketed placeholder segments and
# can also greedily include trailing prose, so the allowlist suppresses either:
#   (a) values ending at a path separator with only placeholder or parent words, or
#   (b) full placeholder-only paths, with optional trailing prose.
# Real-looking paths with non-placeholder child segments remain findings.
# Keep literal absolute paths out of comments so this script does not flag itself.
$winPathPlaceholderWord = '(?:path|to|repo|you|your|example|placeholder|dir|folder|project|projects)'
$winPathParentWord = '(?:users|user|home|documents|appdata|local|roaming)'
$windowsPathPlaceholderAllowlist = '(?ix)^[A-Za-z]:\\(?:' +
    # (a) Placeholder or parent words only, ending at a separator.
    "(?:(?:$winPathPlaceholderWord|$winPathParentWord)\\)+" +
    '|' +
    # (b) Full placeholder-only paths, optionally followed by prose.
    "(?:$winPathPlaceholderWord\\?)+(?:\s.*)?" +
    ')$'
Add-ScanRule -Name 'windows-absolute-path' -Pattern '\b[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\?){2,}' -Kind 'regex' -Allowlist $windowsPathPlaceholderAllowlist

# Additional cloud / key-block prefixes for higher secret recall.
# Prefixes are split so this scanner does not match its own rule definitions.
Add-ScanRule -Name 'aws-access-key-id' -Pattern ('A' + 'KIA') -Kind 'literal'
Add-ScanRule -Name 'gcp-api-key-prefix' -Pattern ('AIza' + '[0-9A-Za-z_\-]{35}') -Kind 'regex'
Add-ScanRule -Name 'slack-user-token-prefix' -Pattern ('xo' + 'xp-') -Kind 'literal'
Add-ScanRule -Name 'slack-legacy-app-token-prefix' -Pattern ('xo' + 'xa-') -Kind 'literal'
Add-ScanRule -Name 'slack-app-level-token-prefix' -Pattern ('xa' + 'pp-') -Kind 'literal'
Add-ScanRule -Name 'stripe-live-secret-key' -Pattern ('(s' + 'k|rk)_live_[0-9A-Za-z]{16,}') -Kind 'regex'
Add-ScanRule -Name 'pem-private-key-block' -Pattern ('BEGIN ' + '(RSA|EC|OPENSSH|ENCRYPTED) PRIVATE KEY') -Kind 'regex'

$localMarkerIndex = 0

function Add-LocalMarker {
    param([string]$Marker)

    $trimmed = $Marker.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) {
        return
    }

    $script:localMarkerIndex++
    Add-ScanRule -Name "local-private-marker-$script:localMarkerIndex" -Pattern $trimmed -Kind 'literal'
}

$localMarkerFile = Join-Path $root '.private-markers.local'
if (Test-Path -LiteralPath $localMarkerFile -PathType Leaf) {
    foreach ($line in Get-Content -LiteralPath $localMarkerFile) {
        Add-LocalMarker -Marker $line
    }
}

$environmentMarkers = [Environment]::GetEnvironmentVariable('WINDOWS_GIT_STALE_LOCK_RECOVERY_PRIVATE_MARKERS')
if (-not [string]::IsNullOrWhiteSpace($environmentMarkers)) {
    foreach ($line in ($environmentMarkers -split "\r?\n")) {
        Add-LocalMarker -Marker $line
    }
}

$githubUrlPattern = 'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?'
$findings = New-Object System.Collections.Generic.List[object]

# Limit scanning to text files to avoid binary noise and expensive regex work.
# Extensionless text files such as LICENSE are still allowed.
$textExtensions = @(
    '.md', '.markdown', '.txt', '.ps1', '.psm1', '.psd1', '.yml', '.yaml',
    '.json', '.jsonc', '.toml', '.ini', '.cfg', '.conf', '.xml', '.csv',
    '.sh', '.bash', '.bat', '.cmd', '.py', '.js', '.ts', '.css', '.html',
    '.htm', '.editorconfig', '.gitattributes', '.gitignore'
)
$textExtensionSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]$textExtensions, [System.StringComparer]::OrdinalIgnoreCase)

function Test-IsTextFile {
    param([string]$FullPath)

    $extension = [System.IO.Path]::GetExtension($FullPath)
    if ([string]::IsNullOrEmpty($extension)) {
        # Treat extensionless files as text.
        return $true
    }
    return $textExtensionSet.Contains($extension)
}

# Prefer git-tracked files so local scans match CI checkouts. Untracked notes do
# not fail the scan unless they are staged/tracked. Non-git fixture directories
# fall back to the working-tree scan used by the self-tests.
$gitTrackedFiles = $null
$gitExe = Get-Command git -ErrorAction SilentlyContinue
if ($null -ne $gitExe) {
    # Windows PowerShell 5.1 converts native stderr into terminating errors when
    # the stream is redirected while $ErrorActionPreference is 'Stop' (for
    # example "fatal: not a git repository" on non-git scan paths). Scope the
    # probe to 'Continue' and rely on exit codes instead.
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $insideWorkTree = (& $gitExe.Source -C $root rev-parse --is-inside-work-tree 2>$null)
        if ($LASTEXITCODE -eq 0 -and "$insideWorkTree".Trim() -eq 'true') {
            # Read tracked files relative to the repo root and split the NUL list safely.
            $rawList = (& $gitExe.Source -C $root ls-files -z 2>$null)
            if ($LASTEXITCODE -eq 0) {
                $gitTrackedFiles = New-Object System.Collections.Generic.List[object]
                foreach ($entry in ($rawList -split "`0")) {
                    if ([string]::IsNullOrEmpty($entry)) { continue }
                    $fullPath = Join-Path $root ($entry -replace '/', [string][char]92)
                    if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
                        $gitTrackedFiles.Add((Get-Item -LiteralPath $fullPath)) | Out-Null
                    }
                }
            }
        }
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
}

if ($null -ne $gitTrackedFiles) {
    $scanMode = 'git-tracked'
    $files = $gitTrackedFiles | Where-Object {
        $_.Name -ne '.private-markers.local' -and (Test-IsTextFile $_.FullName)
    }
} else {
    $scanMode = 'working-tree'
    $files = Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object {
        $_.FullName -notmatch '\\.git(\\|$)' -and
        $_.FullName -notmatch '\\node_modules(\\|$)' -and
        $_.FullName -notmatch '\\.cache(\\|$)' -and
        $_.Name -ne '.private-markers.local' -and
        (Test-IsTextFile $_.FullName)
    }
}

foreach ($file in $files) {
    $relative = $file.FullName
    if ($relative.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
        $relative = $relative.Substring($root.Length).TrimStart([char]92)
    }
    $relative = $relative.Replace([string][char]92, '/')
    $lineNumber = 0

    foreach ($line in Get-Content -LiteralPath $file.FullName) {
        $lineNumber++

        foreach ($match in [regex]::Matches($line, $githubUrlPattern)) {
            if ($match.Value -notmatch $allowedRepoUrlPattern) {
                $findings.Add([pscustomobject]@{
                    File = $relative
                    Line = $lineNumber
                    Rule = 'non-allowlisted-github-repo-url'
                    Match = '<redacted>'
                }) | Out-Null
            }
        }

        foreach ($rule in $rules) {
            $matched = $false
            if ($rule.Kind -eq 'literal') {
                $matched = $line.Contains($rule.Pattern)
            } elseif ([string]::IsNullOrEmpty($rule.Allowlist)) {
                $matched = [regex]::IsMatch($line, $rule.Pattern, 'IgnoreCase')
            } else {
                # For allowlisted regex rules, inspect each match and suppress the
                # finding only when every match is a known-safe placeholder.
                foreach ($m in [regex]::Matches($line, $rule.Pattern, 'IgnoreCase')) {
                    if (-not [regex]::IsMatch($m.Value, $rule.Allowlist)) {
                        $matched = $true
                        break
                    }
                }
            }

            if ($matched) {
                $findings.Add([pscustomobject]@{
                    File = $relative
                    Line = $lineNumber
                    Rule = $rule.Name
                    Match = '<redacted>'
                }) | Out-Null
            }
        }
    }
}

if ($findings.Count -gt 0) {
    Write-Host "Private marker scan failed (scan target: $scanMode):"
    $findings | Sort-Object File, Line, Rule | Format-Table -AutoSize
    exit 1
}

Write-Host "Private marker scan passed (scan target: $scanMode)."
exit 0
