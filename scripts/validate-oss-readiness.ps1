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
$failures = New-Object System.Collections.Generic.List[string]

function Add-Failure {
    param([string]$Message)
    $failures.Add($Message) | Out-Null
}

function Get-RepoFilePath {
    param([string]$RelativePath)
    return Join-Path $root $RelativePath
}

function Assert-FileExists {
    param([string]$RelativePath)

    $filePath = Get-RepoFilePath -RelativePath $RelativePath
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        Add-Failure "Missing required file: $RelativePath"
    }
}

function Assert-FileContains {
    param(
        [string]$RelativePath,
        [string]$Pattern,
        [string]$Description
    )

    $filePath = Get-RepoFilePath -RelativePath $RelativePath
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        Add-Failure "Cannot inspect missing file: $RelativePath ($Description)"
        return
    }

    $content = Get-Content -LiteralPath $filePath -Raw
    if ($content -notmatch $Pattern) {
        Add-Failure "$RelativePath is missing: $Description"
    }
}

function Assert-Utf8Bom {
    param([string]$RelativePath)

    $filePath = Get-RepoFilePath -RelativePath $RelativePath
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        return
    }
    $bytes = [System.IO.File]::ReadAllBytes($filePath)
    if ($bytes.Length -lt 3 -or
        $bytes[0] -ne 0xEF -or
        $bytes[1] -ne 0xBB -or
        $bytes[2] -ne 0xBF) {
        Add-Failure "$RelativePath must use UTF-8 with BOM for Windows PowerShell 5.1."
    }
}

function Test-SkillFrontmatter {
    $skillPath = Get-RepoFilePath -RelativePath 'SKILL.md'
    if (-not (Test-Path -LiteralPath $skillPath -PathType Leaf)) {
        return
    }

    $lines = Get-Content -LiteralPath $skillPath
    if ($lines.Count -lt 4 -or $lines[0] -ne '---') {
        Add-Failure 'SKILL.md must start with YAML frontmatter.'
        return
    }

    $closingIndex = -1
    for ($index = 1; $index -lt $lines.Count; $index++) {
        if ($lines[$index] -eq '---') {
            $closingIndex = $index
            break
        }
    }

    if ($closingIndex -lt 0) {
        Add-Failure 'SKILL.md frontmatter must be closed with --- before content.'
        return
    }

    $frontmatter = $lines[1..($closingIndex - 1)] -join "`n"
    if ($frontmatter -notmatch '(?m)^name:\s*windows-git-stale-lock-recovery\s*$') {
        Add-Failure 'SKILL.md frontmatter must declare name: windows-git-stale-lock-recovery.'
    }
    if ($frontmatter -notmatch '(?m)^description:\s*\S') {
        Add-Failure 'SKILL.md frontmatter must include a non-empty description.'
    }
    if ($frontmatter.Length -gt 1024) {
        Add-Failure 'SKILL.md frontmatter must stay under 1024 characters.'
    }
}

$requiredFiles = @(
    '.editorconfig',
    '.gitattributes',
    '.gitignore',
    '.github/ISSUE_TEMPLATE/bug_report.yml',
    '.github/ISSUE_TEMPLATE/config.yml',
    '.github/pull_request_template.md',
    '.github/workflows/validate.yml',
    'CHANGELOG.md',
    'CODE_OF_CONDUCT.md',
    'CONTRIBUTING.md',
    'LICENSE',
    'README.md',
    'SECURITY.md',
    'SKILL.md',
    'docs/SKILL.ja.md',
    'examples/five-point-check-checklist.md',
    'examples/single-lock-recovery-walkthrough.md',
    'examples/post-merge-local-sync-recipe.md',
    'scripts/scan-private-markers.ps1',
    'scripts/test-scan-private-markers.ps1',
    'scripts/validate-oss-readiness.ps1'
)

foreach ($requiredFile in $requiredFiles) {
    Assert-FileExists -RelativePath $requiredFile
}

foreach ($powerShellScript in @(
    'scripts/scan-private-markers.ps1',
    'scripts/test-scan-private-markers.ps1',
    'scripts/validate-oss-readiness.ps1'
)) {
    Assert-Utf8Bom -RelativePath $powerShellScript
}

Assert-FileContains -RelativePath 'README.md' -Pattern '(?im)^##\s+Install' -Description 'installation instructions'
Assert-FileContains -RelativePath 'README.md' -Pattern '(?im)^##\s+Validation' -Description 'validation instructions'
Assert-FileContains -RelativePath 'README.md' -Pattern '(?im)^##\s+Contributing' -Description 'contribution guidance'
Assert-FileContains -RelativePath 'README.md' -Pattern '(?im)^##\s+Security' -Description 'security reporting guidance'
Assert-FileContains -RelativePath 'README.md' -Pattern 'CONTRIBUTING\.md' -Description 'link to CONTRIBUTING.md'
Assert-FileContains -RelativePath 'README.md' -Pattern 'SECURITY\.md' -Description 'link to SECURITY.md'
Assert-FileContains -RelativePath 'README.md' -Pattern 'docs/SKILL\.ja\.md' -Description 'link to the Japanese skill version'
Assert-FileContains -RelativePath 'README.md' -Pattern '(?is)index blob.*worktree|worktree.*index blob' -Description 'index/worktree scanner provenance contract'
Assert-FileContains -RelativePath 'README.md' -Pattern '(?is)cat-file --batch.*at most six Git children' -Description 'bounded batch Git child contract'
Assert-FileContains -RelativePath 'README.md' -Pattern '(?is)ls-files -z --stage.*ls-files -z --stage --debug.*match exactly' -Description 'stable raw index and flags snapshot contract'
Assert-FileContains -RelativePath 'README.md' -Pattern '(?is)8,192 text-entry.*16 MiB index-debug' -Description 'bounded index-layer contract'
Assert-FileContains -RelativePath 'README.md' -Pattern '(?is)scan-root-resolution-failed.*never echoes.*PowerShell error framing' -Description 'fixed root-resolution diagnostic contract'
Assert-FileContains -RelativePath 'SECURITY.md' -Pattern '(?is)\.env.*\.pem.*\.key' -Description 'sensitive text candidate contract'
Assert-FileContains -RelativePath 'SECURITY.md' -Pattern '(?is)CE_INTENT_TO_ADD.*empty-blob' -Description 'real intent-to-add flag contract'
Assert-FileContains -RelativePath 'SECURITY.md' -Pattern '(?is)trusted runtime API.*ambient `OS`' -Description 'trusted platform selection contract'
Assert-FileContains -RelativePath 'SECURITY.md' -Pattern '(?is)Unicode control/Format.*per line.*per file.*globally.*64 KiB' -Description 'bounded escaped diagnostic contract'
Assert-FileContains -RelativePath 'SECURITY.md' -Pattern '(?is)failure\s+prefix.*TSV header.*explicit LF.*64 KiB.*actual bytes' -Description 'complete UTF-8 finding payload contract'
Assert-FileContains -RelativePath 'CONTRIBUTING.md' -Pattern '(?is)portable real-Git.*merge-conflict.*full PowerShell 7 suite.*Ubuntu' -Description 'POSIX real-Git self-test contract'
Assert-FileContains -RelativePath '.gitignore' -Pattern '\.private-markers\.local' -Description 'ignore local private marker files'
Assert-FileContains -RelativePath 'CONTRIBUTING.md' -Pattern '(?im)no token|never.*token|secret' -Description 'secret-safe contribution guidance'
Assert-FileContains -RelativePath 'SECURITY.md' -Pattern '(?im)do not.*public|private|security' -Description 'private vulnerability reporting guidance'
Assert-FileContains -RelativePath 'SECURITY.md' -Pattern '(?i)fails? closed' -Description 'fail-closed scanner boundary'
Assert-FileContains -RelativePath '.github/workflows/validate.yml' -Pattern 'validate-oss-readiness\.ps1' -Description 'OSS readiness validation in CI'
Assert-FileContains -RelativePath '.github/workflows/validate.yml' -Pattern '(?m)^    timeout-minutes:\s*10\s*$' -Description 'bounded validate job'
Assert-FileContains -RelativePath '.github/workflows/validate.yml' -Pattern '(?m)^      - name:\s*Test private marker scan\s*\r?\n        shell:\s*pwsh\s*\r?\n        run:\s*\./scripts/test-scan-private-markers\.ps1\s*$' -Description 'PowerShell 7 self-test binding'
Assert-FileContains -RelativePath '.github/workflows/validate.yml' -Pattern '(?m)^      - name:\s*Test private marker scan \(Windows PowerShell 5\.1\)\s*\r?\n        shell:\s*powershell\s*\r?\n        run:\s*\./scripts/test-scan-private-markers\.ps1\s*$' -Description 'Windows PowerShell 5.1 self-test binding'
Assert-FileContains -RelativePath '.github/workflows/validate.yml' -Pattern '(?m)^      - name:\s*Scan for private markers\s*\r?\n        shell:\s*pwsh\s*\r?\n        run:\s*\./scripts/scan-private-markers\.ps1\s*$' -Description 'PowerShell 7 scanner binding'
Assert-FileContains -RelativePath '.github/workflows/validate.yml' -Pattern '(?ms)^  validate-posix:\s*.*?runs-on:\s*ubuntu-latest\s*.*?run:\s*\./scripts/test-scan-private-markers\.ps1\s*$' -Description 'Ubuntu PowerShell full self-test binding'

Test-SkillFrontmatter

if ($failures.Count -gt 0) {
    Write-Host 'OSS readiness validation failed:'
    foreach ($failure in $failures) {
        Write-Host "- $failure"
    }
    exit 1
}

Write-Host "OSS readiness validation passed for $root"
exit 0
