[CmdletBinding()]
param(
    [string]$Path = ''
)

$moduleCacheBootstrapOriginalMarker =
    [Environment]::GetEnvironmentVariable(
        'WINDOWS_GIT_STALE_LOCK_RECOVERY_MODULE_CACHE_ISOLATED')
$moduleCacheBootstrapOriginalPath =
    [Environment]::GetEnvironmentVariable('PSModuleAnalysisCachePath')
$moduleCacheBootstrapSink = if (
    [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
) {
    'NUL'
}
else {
    '/dev/null'
}
$moduleCacheBootstrapAlreadyIsolated = (
    $moduleCacheBootstrapOriginalMarker -ceq '1' -and
    [string]::Equals(
        $moduleCacheBootstrapOriginalPath,
        $moduleCacheBootstrapSink,
        $(if (
                [Environment]::OSVersion.Platform -eq
                    [PlatformID]::Win32NT
            ) {
                [StringComparison]::OrdinalIgnoreCase
            }
            else {
                [StringComparison]::Ordinal
            })))

# readiness親hostの非同期cache writerを最初の処理でnull deviceへ向ける。
[Environment]::SetEnvironmentVariable(
    'PSModuleAnalysisCachePath',
    $moduleCacheBootstrapSink,
    'Process')

$ErrorActionPreference = 'Stop'

# readiness validatorも同じPowerShell entrypointであり、長時間実行時の
# ModuleAnalysisCacheをnull deviceへ無効化してから検証を開始する。
$moduleCacheScriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($moduleCacheScriptRoot)) {
    $moduleCacheScriptRoot = [IO.Path]::GetDirectoryName(
        $MyInvocation.MyCommand.Path)
}
$moduleCacheIsolationPath = [IO.Path]::Combine(
    $moduleCacheScriptRoot,
    'module-analysis-cache-isolation.ps1')
if (-not [IO.File]::Exists($moduleCacheIsolationPath)) {
    [Console]::Error.WriteLine(
        'PowerShell launcher aborted: module-cache-bootstrap-failed')
    exit 1
}
try {
    . $moduleCacheIsolationPath
}
catch {
    [Console]::Error.WriteLine(
        'PowerShell launcher aborted: module-cache-bootstrap-failed')
    exit 1
}
$moduleCacheArguments = @()
if (-not [string]::IsNullOrWhiteSpace($Path)) {
    $moduleCacheArguments += @('-Path', $Path)
}
try {
    Initialize-ModuleAnalysisCacheIsolation `
        -ScriptPath $MyInvocation.MyCommand.Path `
        -ScriptArguments $moduleCacheArguments `
        -BootstrapAlreadyIsolated $moduleCacheBootstrapAlreadyIsolated
}
catch {
    [Console]::Error.WriteLine(
        'PowerShell launcher aborted: module-cache-bootstrap-failed')
    exit 1
}

Set-StrictMode -Version Latest

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

function Assert-FileOmits {
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
    if ($content -match $Pattern) {
        Add-Failure "$RelativePath still contains: $Description"
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

function Assert-SelfTestProgressContract {
    $relativePath = 'scripts/test-scan-private-markers.ps1'
    $filePath = Get-RepoFilePath -RelativePath $relativePath
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        return
    }

    # phase名を動的な値から組み立てられると、CI logへpathや環境値が
    # 混入し得る。function内部を除く全callをASTで列挙し、固定literalと
    # 実行順を公開contractとして固定する。
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $filePath,
        [ref]$tokens,
        [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
        Add-Failure "$relativePath must parse before checking progress markers."
        return
    }

    $progressCalls = @($ast.FindAll({
        param($node)

        if ($node -isnot [System.Management.Automation.Language.CommandAst] -or
            $node.GetCommandName() -ne 'Write-SelfTestProgress') {
            return $false
        }

        $parent = $node.Parent
        while ($null -ne $parent) {
            if ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
                return $false
            }
            $parent = $parent.Parent
        }
        return $true
    }, $true))

    $expectedPhases = @(
        'module-cache-isolation',
        'basic-and-output-bounds',
        'fallback-boundaries',
        'windows-containment',
        'windows-command-budget',
        'windows-mutation-detection',
        'windows-timeout-containment',
        'portable-real-git',
        'git-object-boundaries',
        'final-cleanup',
        'complete'
    )
    $actualPhases = New-Object System.Collections.Generic.List[string]

    foreach ($call in $progressCalls) {
        $elements = @($call.CommandElements)
        if ($elements.Count -ne 3 -or
            $elements[1] -isnot [System.Management.Automation.Language.CommandParameterAst] -or
            $elements[1].ParameterName -ne 'Phase' -or
            $elements[2] -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) {
            Add-Failure "$relativePath progress calls must use one fixed -Phase literal."
            return
        }
        $actualPhases.Add($elements[2].Value) | Out-Null
    }

    if ($actualPhases.Count -ne $expectedPhases.Count) {
        Add-Failure "$relativePath must declare exactly $($expectedPhases.Count) top-level progress phases."
        return
    }
    for ($index = 0; $index -lt $expectedPhases.Count; $index++) {
        if ($actualPhases[$index] -ne $expectedPhases[$index]) {
            Add-Failure "$relativePath progress phase $index must be '$($expectedPhases[$index])'."
        }
    }

    # final-cleanupは削除処理が停滞する前に出し、completeはcleanup完了かつ
    # failure=0の成功経路だけで出す。末尾構造も固定して誤診を防ぐ。
    $source = Get-Content -LiteralPath $filePath -Raw
    $terminalPattern = (
        '(?ms)finally\s*\{\s*' +
        'Write-SelfTestProgress\s+-Phase\s+''final-cleanup''\s*' +
        '.*?\}\s*if\s*\(\$failures\.Count\s+-gt\s+0\)\s*\{' +
        '.*?exit\s+1\s*\}\s*' +
        'Write-SelfTestProgress\s+-Phase\s+''complete''\s*' +
        'Write-Host\s+''Private marker scan self-test passed\.''')
    if ($source -notmatch $terminalPattern) {
        Add-Failure "$relativePath must mark final cleanup before cleanup and complete only on success."
    }
}

function Assert-TextMatchCount {
    param(
        [string]$Text,
        [string]$Pattern,
        [int]$ExpectedCount,
        [string]$Description
    )

    $actualCount = [regex]::Matches($Text, $Pattern).Count
    if ($actualCount -ne $ExpectedCount) {
        Add-Failure "$Description has $actualCount matches, expected $ExpectedCount."
    }
}

function Assert-WorkflowJobShape {
    param(
        [string]$Block,
        [string]$JobName,
        [int]$ExpectedStepCount,
        [int]$ExpectedShellCount,
        [int]$ExpectedRunCount,
        [int]$ExpectedEnvCount
    )

    # expected行だけを数えると、重複keyや無名stepを追加しても見逃す。
    # YAMLのindent別に全key/全list itemを数え、許可したshape以外を拒否する。
    Assert-TextMatchCount -Text $Block -Pattern '(?m)^    name:\s*' -ExpectedCount 1 -Description "$JobName name key"
    Assert-TextMatchCount -Text $Block -Pattern '(?m)^    timeout-minutes:\s*' -ExpectedCount 1 -Description "$JobName timeout key"
    Assert-TextMatchCount -Text $Block -Pattern '(?m)^    runs-on:\s*' -ExpectedCount 1 -Description "$JobName runs-on key"
    Assert-TextMatchCount -Text $Block -Pattern '(?m)^    steps:\s*' -ExpectedCount 1 -Description "$JobName steps key"
    Assert-TextMatchCount -Text $Block -Pattern '(?m)^    (?![ #\r\n]).+$' -ExpectedCount 4 -Description "$JobName total job-level entries"
    Assert-TextMatchCount -Text $Block -Pattern '(?m)^      -\s+' -ExpectedCount $ExpectedStepCount -Description "$JobName total step items"
    Assert-TextMatchCount -Text $Block -Pattern '(?m)^      - name:\s*' -ExpectedCount $ExpectedStepCount -Description "$JobName named step items"
    Assert-TextMatchCount -Text $Block -Pattern '(?m)^        uses:\s*' -ExpectedCount 1 -Description "$JobName total uses keys"
    Assert-TextMatchCount -Text $Block -Pattern '(?m)^        shell:\s*' -ExpectedCount $ExpectedShellCount -Description "$JobName total shell keys"
    Assert-TextMatchCount -Text $Block -Pattern '(?m)^        run:\s*' -ExpectedCount $ExpectedRunCount -Description "$JobName total run keys"
    Assert-TextMatchCount -Text $Block -Pattern '(?m)^        env:\s*' -ExpectedCount $ExpectedEnvCount -Description "$JobName total env keys"
    $expectedStepPropertyCount = (
        1 +
        $ExpectedShellCount +
        $ExpectedRunCount +
        $ExpectedEnvCount)
    Assert-TextMatchCount -Text $Block -Pattern '(?m)^        (?![ #\r\n]).+$' -ExpectedCount $expectedStepPropertyCount -Description "$JobName total step-level entries"
}

function Assert-WorkflowContracts {
    $relativePath = '.github/workflows/validate.yml'
    $filePath = Get-RepoFilePath -RelativePath $relativePath
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        return
    }

    # file全体の件数だけでは、stepを別jobへ移しても合格し得る。jobs配下を
    # 2-space job境界で分割し、runner/deadline/action/shell/runの所有者を固定する。
    $source = Get-Content -LiteralPath $filePath -Raw
    $jobsMatch = [regex]::Match(
        $source,
        '(?ms)^jobs:\s*\r?\n(?<jobs>.*)\z')
    if (-not $jobsMatch.Success) {
        Add-Failure "$relativePath must contain a terminal jobs mapping."
        return
    }

    $jobMatches = [regex]::Matches(
        $jobsMatch.Groups['jobs'].Value,
        '(?ms)^  (?<name>[A-Za-z0-9_-]+):\s*\r?\n' +
        '(?<body>.*?)(?=^  [A-Za-z0-9_-]+:\s*(?:\r?\n|\z)|\z)')
    $expectedJobNames = @(
        'validate',
        'validate-windows-powershell',
        'validate-posix'
    )
    $workflowShapeValid = $true
    if ($jobMatches.Count -ne $expectedJobNames.Count) {
        Add-Failure "$relativePath must declare exactly three validation jobs."
        $workflowShapeValid = $false
    }

    $jobBlocks = @{}
    foreach ($jobMatch in $jobMatches) {
        $jobName = $jobMatch.Groups['name'].Value
        if ($jobBlocks.ContainsKey($jobName)) {
            Add-Failure "$relativePath declares duplicate job: $jobName"
            $workflowShapeValid = $false
            continue
        }
        $jobBlocks[$jobName] = $jobMatch.Value
    }
    foreach ($expectedJobName in $expectedJobNames) {
        if (-not $jobBlocks.ContainsKey($expectedJobName)) {
            Add-Failure "$relativePath is missing validation job: $expectedJobName"
            $workflowShapeValid = $false
        }
    }
    if (-not $workflowShapeValid) {
        return
    }

    $checkoutPattern = (
        '(?m)^        uses:\s*actions/checkout@' +
        'fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09' +
        '(?:\s+#.*)?\s*$')
    $pwshReadinessPattern = (
        '(?m)^      - name:\s*Validate OSS readiness\s*\r?\n' +
        '        shell:\s*pwsh\s*\r?\n' +
        '        run:\s*\./scripts/validate-oss-readiness\.ps1\s*$')
    $pwshSelfTestPattern = (
        '(?m)^      - name:\s*Test private marker scan\s*\r?\n' +
        '        shell:\s*pwsh\s*\r?\n' +
        '        run:\s*\./scripts/test-scan-private-markers\.ps1\s*$')
    $pwshScannerPattern = (
        '(?m)^      - name:\s*Scan for private markers\s*\r?\n' +
        '        shell:\s*pwsh\s*\r?\n' +
        '        run:\s*\./scripts/scan-private-markers\.ps1\s*$')
    $pwshWhitespacePattern = (
        '(?ms)^      - name:\s*Check whitespace\s*\r?\n' +
        '(?:(?!^      - name:).)*?' +
        '^        shell:\s*pwsh\s*\r?\n' +
        '(?:(?!^      - name:).)*?' +
        '^        run:\s*git diff-tree --check ' +
        '4b825dc642cb6eb9a060e54bf8d69288fbee4904 HEAD\s*$')

    foreach ($jobName in @('validate', 'validate-posix')) {
        $block = $jobBlocks[$jobName]
        $runner = if ($jobName -eq 'validate') {
            'windows-latest'
        }
        else {
            'ubuntu-latest'
        }
        Assert-TextMatchCount -Text $block -Pattern '(?m)^    timeout-minutes:\s*10\s*$' -ExpectedCount 1 -Description "$jobName 10-minute deadline"
        Assert-TextMatchCount -Text $block -Pattern "(?m)^    runs-on:\s*$([regex]::Escape($runner))\s*$" -ExpectedCount 1 -Description "$jobName runner"
        Assert-TextMatchCount -Text $block -Pattern $checkoutPattern -ExpectedCount 1 -Description "$jobName immutable checkout"
        Assert-TextMatchCount -Text $block -Pattern $pwshReadinessPattern -ExpectedCount 1 -Description "$jobName readiness step"
        Assert-TextMatchCount -Text $block -Pattern $pwshSelfTestPattern -ExpectedCount 1 -Description "$jobName self-test step"
        Assert-TextMatchCount -Text $block -Pattern $pwshScannerPattern -ExpectedCount 1 -Description "$jobName scanner step"
        Assert-TextMatchCount -Text $block -Pattern $pwshWhitespacePattern -ExpectedCount 1 -Description "$jobName whitespace step"
        Assert-TextMatchCount -Text $block -Pattern '(?m)^        shell:\s*pwsh\s*$' -ExpectedCount 4 -Description "$jobName pwsh shell ownership"
        Assert-WorkflowJobShape -Block $block -JobName $jobName -ExpectedStepCount 5 -ExpectedShellCount 4 -ExpectedRunCount 4 -ExpectedEnvCount 0
    }

    $windowsPowerShellBlock = $jobBlocks['validate-windows-powershell']
    Assert-TextMatchCount -Text $windowsPowerShellBlock -Pattern '(?m)^    timeout-minutes:\s*35\s*$' -ExpectedCount 1 -Description 'Windows PowerShell 5.1 deadline'
    Assert-TextMatchCount -Text $windowsPowerShellBlock -Pattern '(?m)^    runs-on:\s*windows-latest\s*$' -ExpectedCount 1 -Description 'Windows PowerShell 5.1 runner'
    Assert-TextMatchCount -Text $windowsPowerShellBlock -Pattern $checkoutPattern -ExpectedCount 1 -Description 'Windows PowerShell 5.1 immutable checkout'
    Assert-TextMatchCount -Text $windowsPowerShellBlock -Pattern '(?m)^      - name:\s*Validate OSS readiness\s*\r?\n        shell:\s*powershell\s*\r?\n        run:\s*\./scripts/validate-oss-readiness\.ps1\s*$' -ExpectedCount 1 -Description 'Windows PowerShell 5.1 readiness step'
    Assert-TextMatchCount -Text $windowsPowerShellBlock -Pattern '(?m)^      - name:\s*Test private marker scan \(Windows PowerShell 5\.1\)\s*\r?\n        shell:\s*powershell\s*\r?\n        env:\s*\r?\n          PRIVATE_MARKER_SELFTEST_PROGRESS:\s*''1''\s*\r?\n        run:\s*\./scripts/test-scan-private-markers\.ps1\s*$' -ExpectedCount 1 -Description 'Windows PowerShell 5.1 self-test step'
    Assert-TextMatchCount -Text $windowsPowerShellBlock -Pattern '(?m)^      - name:\s*Scan for private markers\s*\r?\n        shell:\s*powershell\s*\r?\n        run:\s*\./scripts/scan-private-markers\.ps1\s*$' -ExpectedCount 1 -Description 'Windows PowerShell 5.1 scanner step'
    Assert-TextMatchCount -Text $windowsPowerShellBlock -Pattern '(?m)^        shell:\s*powershell\s*$' -ExpectedCount 3 -Description 'Windows PowerShell 5.1 shell ownership'
    Assert-WorkflowJobShape -Block $windowsPowerShellBlock -JobName 'Windows PowerShell 5.1' -ExpectedStepCount 4 -ExpectedShellCount 3 -ExpectedRunCount 3 -ExpectedEnvCount 1
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
    'docs/module-analysis-cache-isolation.md',
    'examples/five-point-check-checklist.md',
    'examples/single-lock-recovery-walkthrough.md',
    'examples/post-merge-local-sync-recipe.md',
    'scripts/module-analysis-cache-isolation.ps1',
    'scripts/scan-private-markers.ps1',
    'scripts/test-scan-private-markers.ps1',
    'scripts/validate-oss-readiness.ps1'
)

foreach ($requiredFile in $requiredFiles) {
    Assert-FileExists -RelativePath $requiredFile
}

foreach ($powerShellScript in @(
    'scripts/module-analysis-cache-isolation.ps1',
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
Assert-FileContains -RelativePath 'README.md' -Pattern 'docs/module-analysis-cache-isolation\.md' -Description 'module cache isolation maintenance record'
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
Assert-FileContains -RelativePath 'scripts/module-analysis-cache-isolation.ps1' -Pattern "(?is)return 'NUL'.*return '/dev/null'.*PSModuleAnalysisCachePath" -Description 'official platform null-device module cache sink'
Assert-FileContains -RelativePath 'scripts/module-analysis-cache-isolation.ps1' -Pattern '(?is)ProcessStartInfo.*CreateNoWindow\s*=\s*\$false.*RedirectStandardOutput\s*=\s*\$false.*RedirectStandardError\s*=\s*\$false.*WaitForExit\(\).*ExitCode' -Description 'same-host raw stream and exit-code preserving launcher'
Assert-FileOmits -RelativePath 'scripts/module-analysis-cache-isolation.ps1' -Pattern '(?i)Remove-Item|File\]::Delete|Directory\]::Delete|CreateDirectory|GetTempPath' -Description 'temporary filesystem creation or cleanup API'
foreach ($entryScript in @(
    'scripts/scan-private-markers.ps1',
    'scripts/test-scan-private-markers.ps1',
    'scripts/validate-oss-readiness.ps1'
)) {
    Assert-FileContains `
        -RelativePath $entryScript `
        -Pattern '(?is)OriginalMarker.*OriginalPath.*AlreadyIsolated.*SetEnvironmentVariable.*module-analysis-cache-isolation\.ps1.*module-cache-bootstrap-failed.*Initialize-ModuleAnalysisCacheIsolation.*BootstrapAlreadyIsolated' `
        -Description 'pre-overwrite marker/sink capture and fail-closed null-device bootstrap'
}
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern '(?is)module-cache-isolation.*OriginalMarker.*AlreadyIsolated.*0\.\.255.*255\.\.0.*Test-ModuleCacheProbeContract.*missing-helper.*explicit-target.*Junction.*SymbolicLink' -Description 'module cache marker-only, raw stream, bootstrap, explicit-target, and physical-alias regression fixtures'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern '(?is)function\s+Test-ModuleCacheProbeContract\s*\{.*?return\s*\(.*?-not\s+\$Result\.TimedOut.*?\)\s*\}' -Description 'module cache probe contract rejects timeout'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern '(?is)\$cacheProbeResult\s*=\s*Invoke-BoundedProcess.*?-TimeoutSeconds\s+120.*?\$cacheProbeContractSatisfied\s*=\s*Test-ModuleCacheProbeContract.*?-Result\s+\$cacheProbeResult.*?if\s*\(-not\s+\$cacheProbeContractSatisfied\)\s*\{.*?Add-Failure' -Description 'hosted module cache probe deadline and actual-result contract wiring'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern '(?is)\$syntheticTimedOutProbe.*?TimedOut\s*=\s*\$true.*?if\s*\(Test-ModuleCacheProbeContract.*?-Result\s+\$syntheticTimedOutProbe.*?\)\s*\{.*?Expected module cache probe timeout to fail the contract' -Description 'synthetic module cache timeout failure contract'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern '(?is)foreach\s*\(\$entrypointName.*?\$bootstrapResult\s*=\s*Invoke-BoundedProcess.*?-TimeoutSeconds\s+10.*?foreach\s*\(\$explicitTempValue.*?\$explicitResult\s*=\s*Invoke-Scanner.*?-TimeoutSeconds\s+40' -Description 'module cache child fixture individual deadlines'
Assert-FileContains -RelativePath 'CONTRIBUTING.md' -Pattern '(?is)portable real-Git.*merge-conflict.*full PowerShell 7 suite.*Ubuntu' -Description 'POSIX real-Git self-test contract'
Assert-FileContains -RelativePath '.gitignore' -Pattern '\.private-markers\.local' -Description 'ignore local private marker files'
Assert-FileContains -RelativePath 'CONTRIBUTING.md' -Pattern '(?im)no token|never.*token|secret' -Description 'secret-safe contribution guidance'
Assert-FileContains -RelativePath 'SECURITY.md' -Pattern '(?im)do not.*public|private|security' -Description 'private vulnerability reporting guidance'
Assert-FileContains -RelativePath 'SECURITY.md' -Pattern '(?i)fails? closed' -Description 'fail-closed scanner boundary'

Test-SkillFrontmatter
Assert-SelfTestProgressContract
Assert-WorkflowContracts

if ($failures.Count -gt 0) {
    Write-Host 'OSS readiness validation failed:'
    foreach ($failure in $failures) {
        Write-Host "- $failure"
    }
    exit 1
}

Write-Host "OSS readiness validation passed for $root"
exit 0
