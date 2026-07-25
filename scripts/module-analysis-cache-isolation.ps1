# PowerShell entrypoint が長く動く前に、module analysis cache を OS の null
# device へ向けた同一 host child へ処理を移す。Microsoft の公式手順どおり
# cache 自体を無効化するため、一時 file の所有判定や危険な cleanup は不要になる。

$script:ModuleCacheIsolationName =
    'WINDOWS_GIT_STALE_LOCK_RECOVERY_MODULE_CACHE_ISOLATED'
$script:LegacyModuleCacheTokenName =
    'WINDOWS_GIT_STALE_LOCK_RECOVERY_MODULE_CACHE_TOKEN'
$script:LegacyModuleCacheRootName =
    'WINDOWS_GIT_STALE_LOCK_RECOVERY_MODULE_CACHE_ROOT'

function Test-ModuleCacheWindowsRuntime {
    return (
        [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
}

function Get-ModuleAnalysisCacheSink {
    # PowerShell 5.1/7 の公式仕様が示す無効化先を固定する。Windows の NUL は
    # filesystem path ではなく予約 device、非 Windows は絶対 /dev/null である。
    if (Test-ModuleCacheWindowsRuntime) {
        return 'NUL'
    }
    return '/dev/null'
}

function Test-ModuleAnalysisCacheIsolationActive {
    param([string]$ExpectedSink)

    $isolationValue = [Environment]::GetEnvironmentVariable(
        $script:ModuleCacheIsolationName)
    $cacheValue = [Environment]::GetEnvironmentVariable(
        'PSModuleAnalysisCachePath')
    if ($isolationValue -cne '1') {
        return $false
    }

    if (Test-ModuleCacheWindowsRuntime) {
        return [string]::Equals(
            $cacheValue,
            $ExpectedSink,
            [StringComparison]::OrdinalIgnoreCase)
    }
    return [string]::Equals(
        $cacheValue,
        $ExpectedSink,
        [StringComparison]::Ordinal)
}

function ConvertTo-ModuleCacheNativeArgument {
    param([AllowEmptyString()][string]$Argument)

    if ($Argument.Length -eq 0) {
        return '""'
    }
    if ($Argument -notmatch '[\s"]') {
        return $Argument
    }

    # Windows PowerShell 5.1 には ProcessStartInfo.ArgumentList がないため、
    # CommandLineToArgvW と互換の backslash/quote 規則で1引数ずつ組み立てる。
    $builder = [Activator]::CreateInstance([Text.StringBuilder])
    [void]$builder.Append('"')
    $backslashCount = 0
    foreach ($character in $Argument.ToCharArray()) {
        if ($character -eq [char]92) {
            $backslashCount++
            continue
        }
        if ($character -eq [char]34) {
            [void]$builder.Append(('\' * (($backslashCount * 2) + 1)))
            [void]$builder.Append('"')
            $backslashCount = 0
            continue
        }
        if ($backslashCount -gt 0) {
            [void]$builder.Append(('\' * $backslashCount))
            $backslashCount = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashCount -gt 0) {
        [void]$builder.Append(('\' * ($backslashCount * 2)))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Get-CurrentPowerShellExecutable {
    $currentProcess = [Diagnostics.Process]::GetCurrentProcess()
    try {
        $executable = $currentProcess.MainModule.FileName
    }
    finally {
        $currentProcess.Dispose()
    }

    # ISE、埋込み host、dotnet pwsh.dll を CLI と誤認すると同じ script を
    # 再実行できない。side effect より前に通常の powershell/pwsh だけへ限定する。
    if ([string]::IsNullOrWhiteSpace($executable) -or
        -not [IO.Path]::IsPathRooted($executable) -or
        -not [IO.File]::Exists($executable) -or
        [IO.Path]::GetFileName($executable) -notmatch
            '^(?i:powershell|pwsh)(?:\.exe)?$') {
        throw 'module-cache-host-unsupported'
    }
    return [IO.Path]::GetFullPath($executable)
}

function New-IsolatedPowerShellStartInfo {
    param(
        [string]$PowerShellExecutable,
        [string[]]$Arguments
    )

    $startInfo = [Activator]::CreateInstance(
        [Diagnostics.ProcessStartInfo])
    $startInfo.FileName = $PowerShellExecutable
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $false

    # stdout/stderr/stdin を redirect しないことが重要である。child は親の OS
    # handle へ直接書き、PS5.1 の text pipeline による再encodingやCRLF化を避ける。
    $startInfo.RedirectStandardInput = $false
    $startInfo.RedirectStandardOutput = $false
    $startInfo.RedirectStandardError = $false

    $argumentListProperty = $startInfo.GetType().GetProperty('ArgumentList')
    if ($null -ne $argumentListProperty) {
        foreach ($argument in $Arguments) {
            [void]$startInfo.ArgumentList.Add($argument)
        }
    }
    else {
        $quotedArguments = @(
            foreach ($argument in $Arguments) {
                ConvertTo-ModuleCacheNativeArgument -Argument $argument
            })
        $startInfo.Arguments = $quotedArguments -join ' '
    }
    return $startInfo
}

function Initialize-ModuleAnalysisCacheIsolation {
    param(
        [string]$ScriptPath,
        [string[]]$ScriptArguments = @(),
        [bool]$BootstrapAlreadyIsolated = $false
    )

    $sink = Get-ModuleAnalysisCacheSink
    if ($BootstrapAlreadyIsolated -and
        (Test-ModuleAnalysisCacheIsolationActive -ExpectedSink $sink)) {
        return
    }

    try {
        # この設定より前に cmdlet / module discovery を追加してはならない。
        # 初回analysis前なら、起動済み親hostの遅延writerにもnull sinkが有効になる。
        [Environment]::SetEnvironmentVariable(
            'PSModuleAnalysisCachePath',
            $sink,
            'Process')

        # host と全引数を先に検証する。ここまで filesystem への作成・削除も、
        # cache object の作成も行わないため、失敗時にorphanは生じない。
        $powerShellExecutable = Get-CurrentPowerShellExecutable
        $hostArguments = @('-NoLogo', '-NoProfile')
        if ([IO.Path]::GetFileName($powerShellExecutable) -like 'powershell*') {
            $hostArguments += @('-ExecutionPolicy', 'Bypass')
        }
        $hostArguments += @('-File', [IO.Path]::GetFullPath($ScriptPath))
        $hostArguments += $ScriptArguments
        $startInfo = New-IsolatedPowerShellStartInfo `
            -PowerShellExecutable $powerShellExecutable `
            -Arguments $hostArguments

        # marker はnull sink設定とは分離し、childだけがbootstrap済みと判定する。
        [Environment]::SetEnvironmentVariable(
            $script:ModuleCacheIsolationName,
            '1',
            'Process')
        foreach ($legacyName in @(
                $script:LegacyModuleCacheTokenName,
                $script:LegacyModuleCacheRootName)) {
            [Environment]::SetEnvironmentVariable(
                $legacyName,
                $null,
                'Process')
        }
    }
    catch {
        [Console]::Error.WriteLine(
            'PowerShell launcher aborted: module-cache-setup-failed')
        exit 1
    }

    $child = $null
    try {
        # launcher は stream に触れず、同一 executable の終了だけを待つ。
        $child = [Activator]::CreateInstance([Diagnostics.Process])
        $child.StartInfo = $startInfo
        if (-not $child.Start()) {
            throw 'isolated-child-start-failed'
        }
        $child.WaitForExit()
        $childExitCode = $child.ExitCode
    }
    catch {
        [Console]::Error.WriteLine(
            'PowerShell launcher aborted: isolated-child-start-failed')
        exit 1
    }
    finally {
        if ($null -ne $child) {
            $child.Dispose()
        }
    }

    exit $childExitCode
}
