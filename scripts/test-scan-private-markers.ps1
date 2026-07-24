[CmdletBinding()]
param(
    [string]$Path = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:isWindowsRuntime = (
    [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)

$scriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptRoot)) {
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}

if ([string]::IsNullOrWhiteSpace($Path)) {
    $Path = Split-Path -Parent $scriptRoot
}

$root = (Resolve-Path -LiteralPath $Path).Path
$scanner = Join-Path $root 'scripts/scan-private-markers.ps1'
if (-not (Test-Path -LiteralPath $scanner -PathType Leaf)) {
    throw "Missing scanner script: $scanner"
}

$powerShellExecutable = (Get-Process -Id $PID).Path
$gitCommand = Get-Command git -CommandType Application -ErrorAction Stop |
    Select-Object -First 1

$failures = New-Object System.Collections.Generic.List[string]

function Add-Failure {
    param([string]$Message)
    $failures.Add($Message) | Out-Null
}

$script:selfTestProgressEnabled = (
    [Environment]::GetEnvironmentVariable(
        'PRIVATE_MARKER_SELFTEST_PROGRESS') -eq '1')

function Write-SelfTestProgress {
    param([string]$Phase)

    if ($script:selfTestProgressEnabled) {
        # Hosted runner の長時間fixtureを匿名phase codeだけで診断する。
        [Console]::Out.WriteLine("SELFTEST_PROGRESS:$Phase")
    }
}

# scanner が親 process の Env: を直接変更せず、未知 GIT_* も child clone
# から除外する境界を source invariant として固定する。
$scannerSource = Get-Content -LiteralPath $scanner -Raw
if ($scannerSource -match '\[Environment\]::SetEnvironmentVariable' -or
    $scannerSource -match '(?im)(?:Set-Item|Remove-Item)\s+(?:-LiteralPath\s+)?Env:' -or
    $scannerSource -match '(?im)\$env:GIT_[A-Z0-9_]*\s*=') {
    Add-Failure 'Scanner must not mutate the parent process environment.'
}
if ($scannerSource -match '\$env:OS' -or
    $scannerSource -notmatch '\[Environment\]::OSVersion\.Platform') {
    Add-Failure 'Scanner platform selection must use a trusted runtime API rather than ambient OS.'
}
if ($scannerSource -notmatch "\`$name\s+-match\s+'\^GIT_'") {
    Add-Failure 'Scanner must remove all ambient GIT_* names before applying its safe child allowlist.'
}
if ($scannerSource -notmatch 'function\s+Test-HasGitControlEntryAtOrAbove' -or
    $scannerSource -notmatch 'Get-ChildItem\s+-LiteralPath\s+\$cursor\s+-Force') {
    Add-Failure 'Scanner must inspect .git control entries at the scan root and its ancestors.'
}
$assignCallIndex = $scannerSource.IndexOf(
    'if (!AssignProcessToJobObject(job, processInformation.hProcess))')
$resumeCallIndex = $scannerSource.IndexOf(
    'if (ResumeThread(processInformation.hThread) == ResumeFailed)')
if ($scannerSource -notmatch 'CreateSuspended' -or
    $scannerSource -notmatch 'STARTUPINFOEX' -or
    $scannerSource -notmatch 'ProcThreadAttributeHandleList' -or
    $scannerSource -notmatch 'UpdateProcThreadAttribute' -or
    $assignCallIndex -lt 0 -or
    $resumeCallIndex -lt 0 -or
    $assignCallIndex -gt $resumeCallIndex) {
    Add-Failure 'Windows Git children must be created suspended, assigned to a Job, and resumed with an explicit inherited-handle list.'
}
if ($scannerSource -notmatch "cat-file', '--batch" -or
    $scannerSource -notmatch 'git-index-changed-during-scan' -or
    $scannerSource -notmatch 'StructuralEqualityComparer') {
    Add-Failure 'Scanner must batch index blob reads and compare the final raw index enumeration.'
}
if ($scannerSource -match '\[regex\]::Matches' -or
    $scannerSource -notmatch 'System\.IO\.StringReader' -or
    $scannerSource -notmatch '\.NextMatch\(\)') {
    Add-Failure 'Scanner must evaluate lines and repeated regex matches incrementally.'
}
if ($scannerSource -notmatch '\$maxTextEntries\s*=\s*8192' -or
    $scannerSource -notmatch 'git-index-text-entry-limit') {
    Add-Failure 'Scanner must cap the number of Git index text entries before blob batching.'
}
if ($scannerSource -notmatch "ls-files', '-z', '--stage', '--debug" -or
    $scannerSource -notmatch 'git-index-debug-changed-during-scan' -or
    $scannerSource -notmatch '20000000') {
    Add-Failure 'Scanner must compare raw index debug flags and reject CE_INTENT_TO_ADD.'
}
if ($scannerSource -notmatch
    'Get-ChildItem\s+-LiteralPath\s+\$fallbackRoot\s+-Recurse\s+-File\s+-Force') {
    Add-Failure 'Non-Git fallback must enumerate hidden files before explicitly excluding nested .git paths.'
}

function ConvertTo-NativeArgument {
    param([AllowEmptyString()][string]$Argument)

    if ($Argument.Length -eq 0) {
        return '""'
    }
    if ($Argument -notmatch '[\s"]') {
        return $Argument
    }

    # Windows PowerShell 5.1 lacks ProcessStartInfo.ArgumentList. Build one
    # argument with the standard Windows command-line backslash/quote rules.
    $builder = New-Object System.Text.StringBuilder
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

function Get-ProcessEnvironmentClone {
    $clone = @{}
    foreach ($entry in [Environment]::GetEnvironmentVariables('Process').GetEnumerator()) {
        $clone[[string]$entry.Key] = [string]$entry.Value
    }
    return $clone
}

function New-ChildEnvironment {
    param(
        [hashtable]$BaseEnvironment,
        [hashtable]$Overrides = @{},
        [string[]]$RemoveNames = @(),
        [string]$RemovePattern = ''
    )

    $child = @{}
    foreach ($entry in $BaseEnvironment.GetEnumerator()) {
        $name = [string]$entry.Key
        if ($RemoveNames -contains $name) {
            continue
        }
        if (-not [string]::IsNullOrEmpty($RemovePattern) -and $name -match $RemovePattern) {
            continue
        }
        $child[$name] = [string]$entry.Value
    }
    foreach ($entry in $Overrides.GetEnumerator()) {
        $child[[string]$entry.Key] = [string]$entry.Value
    }
    return $child
}

function Stop-ProcessTreeBounded {
    param([System.Diagnostics.Process]$Process)

    if ($Process.HasExited) {
        return
    }

    # PowerShell 7 exposes Kill(true), which recursively terminates descendants.
    $killTreeMethod = [System.Diagnostics.Process].GetMethods() |
        Where-Object {
            $_.Name -eq 'Kill' -and
            $_.GetParameters().Count -eq 1 -and
            $_.GetParameters()[0].ParameterType -eq [bool]
        } |
        Select-Object -First 1
    if ($null -ne $killTreeMethod) {
        [void]$killTreeMethod.Invoke($Process, @($true))
        return
    }

    if ($script:isWindowsRuntime) {
        # Windows PowerShell 5.1 fallback: taskkill /T is itself bounded.
        $taskkillPath = Join-Path $env:SystemRoot 'System32\taskkill.exe'
        $taskkillInfo = New-Object System.Diagnostics.ProcessStartInfo
        $taskkillInfo.FileName = $taskkillPath
        $taskkillInfo.Arguments = "/PID $($Process.Id) /T /F"
        $taskkillInfo.UseShellExecute = $false
        $taskkillInfo.CreateNoWindow = $true
        $taskkillInfo.RedirectStandardOutput = $true
        $taskkillInfo.RedirectStandardError = $true
        $taskkill = New-Object System.Diagnostics.Process
        $taskkill.StartInfo = $taskkillInfo
        try {
            [void]$taskkill.Start()
            if (-not $taskkill.WaitForExit(5000)) {
                $taskkill.Kill()
                if (-not $taskkill.WaitForExit(2000)) {
                    throw 'taskkill did not exit after bounded termination.'
                }
            }
        }
        finally {
            $taskkill.Dispose()
        }
        return
    }

    # Windows PowerShell 5.1 is Windows-only. This fallback covers unusual
    # runtimes that lack Kill(true), where no portable tree API is available.
    $Process.Kill()
}

function ConvertFrom-Utf8 {
    param([byte[]]$Bytes)

    if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
        return ''
    }
    $utf8 = New-Object System.Text.UTF8Encoding($false, $false)
    return $utf8.GetString($Bytes)
}

function Complete-BoundedProcessStreams {
    param(
        [System.Diagnostics.Process]$Process,
        [System.Threading.Tasks.Task[]]$Tasks,
        [int]$WaitMilliseconds = 1000
    )

    # self-test runner 自身も未完了 ReadAsync を残さない。まず EOF を待ち、
    # 必要な場合だけ parent endpoint を閉じて、完了状態を再確認する。
    $pending = @($Tasks | Where-Object {
        $null -ne $_ -and -not $_.IsCompleted
    })
    if ($pending.Count -gt 0) {
        try {
            [void][System.Threading.Tasks.Task]::WaitAll(
                [System.Threading.Tasks.Task[]]$pending,
                $WaitMilliseconds)
        }
        catch {
            # fault/cancel も完了なので、下の IsCompleted で判定する。
        }
    }

    $pending = @($Tasks | Where-Object {
        $null -ne $_ -and -not $_.IsCompleted
    })
    if ($pending.Count -gt 0) {
        $Process.StandardOutput.Dispose()
        $Process.StandardError.Dispose()
        try {
            [void][System.Threading.Tasks.Task]::WaitAll(
                [System.Threading.Tasks.Task[]]$pending,
                $WaitMilliseconds)
        }
        catch {
            # endpoint close に伴う fault/cancel は許容し、未完了だけ拒否する。
        }
    }

    if (@($Tasks | Where-Object {
            $null -ne $_ -and -not $_.IsCompleted
        }).Count -gt 0) {
        throw 'Child process pipe cleanup did not complete after bounded disposal.'
    }
}

function Invoke-BoundedProcess {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList,
        [hashtable]$Environment,
        [int]$TimeoutSeconds = 20,
        [int]$MaxStandardOutputBytes = (8 * 1024 * 1024),
        [int]$MaxStandardErrorBytes = (1024 * 1024)
    )

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    if ($null -ne $startInfo.PSObject.Properties['ArgumentList']) {
        foreach ($argument in $ArgumentList) {
            $startInfo.ArgumentList.Add([string]$argument)
        }
    } else {
        $startInfo.Arguments = (($ArgumentList | ForEach-Object {
            ConvertTo-NativeArgument -Argument ([string]$_)
        }) -join ' ')
    }
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.EnvironmentVariables.Clear()
    foreach ($entry in $Environment.GetEnumerator()) {
        $startInfo.EnvironmentVariables[[string]$entry.Key] = [string]$entry.Value
    }

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    $stdoutBuffer = New-Object System.IO.MemoryStream
    $stderrBuffer = New-Object System.IO.MemoryStream
    $processStarted = $false
    $stdoutTask = $null
    $stderrTask = $null
    try {
        [void]$process.Start()
        $processStarted = $true
        $stdoutChunk = New-Object byte[] 8192
        $stderrChunk = New-Object byte[] 8192
        $stdoutTask = $process.StandardOutput.BaseStream.ReadAsync(
            $stdoutChunk, 0, $stdoutChunk.Length)
        $stderrTask = $process.StandardError.BaseStream.ReadAsync(
            $stderrChunk, 0, $stderrChunk.Length)
        $stdoutClosed = $false
        $stderrClosed = $false
        $limitExceeded = ''
        $deadline = $TimeoutSeconds * 1000
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        while ((-not $stdoutClosed -or -not $stderrClosed) -and
            [string]::IsNullOrEmpty($limitExceeded) -and
            $stopwatch.ElapsedMilliseconds -lt $deadline) {
            $pendingTasks = New-Object System.Collections.Generic.List[System.Threading.Tasks.Task]
            if (-not $stdoutClosed) {
                $pendingTasks.Add($stdoutTask)
            }
            if (-not $stderrClosed) {
                $pendingTasks.Add($stderrTask)
            }
            $remaining = [Math]::Max(
                0,
                $deadline - [int]$stopwatch.ElapsedMilliseconds)
            [void][System.Threading.Tasks.Task]::WaitAny(
                $pendingTasks.ToArray(),
                [Math]::Min(100, $remaining))

            if (-not $stdoutClosed -and $stdoutTask.IsCompleted) {
                try {
                    $count = $stdoutTask.GetAwaiter().GetResult()
                }
                catch {
                    throw 'Child process stdout read failed.'
                }
                if ($count -eq 0) {
                    $stdoutClosed = $true
                } elseif (($stdoutBuffer.Length + $count) -gt $MaxStandardOutputBytes) {
                    $limitExceeded = 'stdout'
                } else {
                    $stdoutBuffer.Write($stdoutChunk, 0, $count)
                    $stdoutTask = $process.StandardOutput.BaseStream.ReadAsync(
                        $stdoutChunk, 0, $stdoutChunk.Length)
                }
            }

            if (-not $stderrClosed -and $stderrTask.IsCompleted) {
                try {
                    $count = $stderrTask.GetAwaiter().GetResult()
                }
                catch {
                    throw 'Child process stderr read failed.'
                }
                if ($count -eq 0) {
                    $stderrClosed = $true
                } elseif (($stderrBuffer.Length + $count) -gt $MaxStandardErrorBytes) {
                    $limitExceeded = 'stderr'
                } else {
                    $stderrBuffer.Write($stderrChunk, 0, $count)
                    $stderrTask = $process.StandardError.BaseStream.ReadAsync(
                        $stderrChunk, 0, $stderrChunk.Length)
                }
            }
        }

        $remaining = [Math]::Max(
            0,
            $deadline - [int]$stopwatch.ElapsedMilliseconds)
        $streamsCompleted = $stdoutClosed -and $stderrClosed
        $processExited = $false
        if ($streamsCompleted -and [string]::IsNullOrEmpty($limitExceeded)) {
            $processExited = $process.WaitForExit($remaining)
        }
        $timedOut = (
            [string]::IsNullOrEmpty($limitExceeded) -and
            -not ($streamsCompleted -and $processExited))
        if ($timedOut -or -not [string]::IsNullOrEmpty($limitExceeded)) {
            Stop-ProcessTreeBounded -Process $process
            if (-not $process.HasExited -and -not $process.WaitForExit(5000)) {
                throw "Child process did not exit after bounded tree termination: $FilePath"
            }
            Complete-BoundedProcessStreams `
                -Process $process `
                -Tasks @($stdoutTask, $stderrTask)
        }

        [byte[]]$stdoutBytes = @()
        [byte[]]$stderrBytes = @()
        if (-not $timedOut -and [string]::IsNullOrEmpty($limitExceeded)) {
            $stdoutBytes = $stdoutBuffer.ToArray()
            $stderrBytes = $stderrBuffer.ToArray()
        }
        return [pscustomobject]@{
            ExitCode = if ($timedOut -or -not [string]::IsNullOrEmpty($limitExceeded)) {
                -1
            } else {
                $process.ExitCode
            }
            StandardOutputBytes = $stdoutBytes
            StandardErrorBytes = $stderrBytes
            Output = (
                (ConvertFrom-Utf8 -Bytes $stdoutBytes) +
                (ConvertFrom-Utf8 -Bytes $stderrBytes))
            TimedOut = $timedOut
            OutputLimitExceeded = $limitExceeded
        }
    }
    catch {
        $originalFailure = $_
        $cleanupFailure = $null
        if ($processStarted) {
            try {
                if (-not $process.HasExited) {
                    Stop-ProcessTreeBounded -Process $process
                    if (-not $process.HasExited -and -not $process.WaitForExit(5000)) {
                        throw "Child process did not exit after bounded tree termination: $FilePath"
                    }
                }
                Complete-BoundedProcessStreams `
                    -Process $process `
                    -Tasks @($stdoutTask, $stderrTask)
            }
            catch {
                $cleanupFailure = $_
            }
        }
        if ($null -ne $cleanupFailure) {
            throw $cleanupFailure
        }
        throw $originalFailure
    }
    finally {
        $stdoutBuffer.Dispose()
        $stderrBuffer.Dispose()
        $process.Dispose()
    }
}

function Assert-EnvironmentUnchanged {
    param(
        [hashtable]$Before,
        [hashtable]$After,
        [string]$Phase
    )

    foreach ($name in @($Before.Keys + $After.Keys | Sort-Object -Unique)) {
        if ($Before.ContainsKey($name) -ne $After.ContainsKey($name)) {
            Add-Failure "Process environment variable existence changed after $Phase`: $name"
            continue
        }
        if ($Before.ContainsKey($name) -and $Before[$name] -cne $After[$name]) {
            Add-Failure "Process environment variable value changed after $Phase`: $name"
        }
    }
}

function Invoke-Scanner {
    param(
        [string]$ScanPath,
        [hashtable]$EnvironmentOverrides = @{},
        [string[]]$RemoveEnvironmentNames = @(),
        [int]$TimeoutSeconds = 40,
        [int]$GitCommandTimeoutSeconds = 5,
        [int]$MaxStandardOutputBytes = (8 * 1024 * 1024),
        [int]$MaxStandardErrorBytes = (1024 * 1024)
    )

    $arguments = @('-NoProfile')
    $commandName = Split-Path -Leaf $powerShellExecutable
    if ($commandName -like 'powershell*') {
        $arguments += @('-ExecutionPolicy', 'Bypass')
    }
    $arguments += @(
        '-File', $scanner,
        '-Path', $ScanPath,
        '-GitCommandTimeoutSeconds', [string]$GitCommandTimeoutSeconds)
    $environment = New-ChildEnvironment `
        -BaseEnvironment (Get-ProcessEnvironmentClone) `
        -Overrides $EnvironmentOverrides `
        -RemoveNames $RemoveEnvironmentNames
    # Windows PowerShell 5.1 の module analysis cache も fixture 内へ閉じ込める。
    $environment['PSModuleAnalysisCachePath'] = Join-Path $tempRoot 'module-analysis-cache'
    return Invoke-BoundedProcess `
        -FilePath $powerShellExecutable `
        -ArgumentList $arguments `
        -Environment $environment `
        -TimeoutSeconds $TimeoutSeconds `
        -MaxStandardOutputBytes $MaxStandardOutputBytes `
        -MaxStandardErrorBytes $MaxStandardErrorBytes
}

function Invoke-FixtureGit {
    param(
        [string]$WorkingTree,
        [string[]]$Arguments,
        [string]$IsolatedHome,
        [switch]$AllowFailure
    )

    $environment = New-ChildEnvironment `
        -BaseEnvironment (Get-ProcessEnvironmentClone) `
        -RemoveNames @('HOME', 'USERPROFILE', 'XDG_CONFIG_HOME') `
        -RemovePattern '^GIT_' `
        -Overrides @{
            HOME = $IsolatedHome
            USERPROFILE = $IsolatedHome
            XDG_CONFIG_HOME = $IsolatedHome
            GIT_CONFIG_NOSYSTEM = '1'
            GIT_TERMINAL_PROMPT = '0'
        }
    $result = Invoke-BoundedProcess `
        -FilePath $gitCommand.Source `
        -ArgumentList (@('-C', $WorkingTree) + $Arguments) `
        -Environment $environment
    if ($result.ExitCode -ne 0 -and -not $AllowFailure) {
        throw "Synthetic fixture git command failed: $($result.Output.Trim())"
    }
    return $result
}

function New-GitProbeWrapper {
    param([string]$OutputPath)

    if (-not $script:isWindowsRuntime) {
        throw 'Synthetic native Git wrapper is Windows-only.'
    }

    $source = @'
using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public static class GitProbeWrapper
{
    private const uint CreateNoWindow = 0x08000000;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsProcessInJob(
        IntPtr processHandle,
        IntPtr jobHandle,
        [MarshalAs(UnmanagedType.Bool)] out bool result);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessW(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref STARTUPINFO startupInfo,
        out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    private static string Quote(string value)
    {
        if (value.Length == 0) return "\"\"";
        if (value.IndexOfAny(new[] { ' ', '\t', '"' }) < 0) return value;
        var result = new StringBuilder("\"");
        var slashes = 0;
        foreach (var c in value)
        {
            if (c == '\\')
            {
                slashes++;
                continue;
            }
            if (c == '"')
            {
                result.Append('\\', (slashes * 2) + 1);
                result.Append('"');
                slashes = 0;
                continue;
            }
            result.Append('\\', slashes);
            slashes = 0;
            result.Append(c);
        }
        result.Append('\\', slashes * 2);
        result.Append('"');
        return result.ToString();
    }

    private static bool HasArgument(string[] args, string expected)
    {
        foreach (var arg in args)
        {
            if (String.Equals(arg, expected, StringComparison.Ordinal)) return true;
        }
        return false;
    }

    private static string InvocationKind(string[] args)
    {
        if (HasArgument(args, "rev-parse")) return "probe";
        if (HasArgument(args, "ls-files") &&
            HasArgument(args, "--debug"))
            return "debug";
        if (HasArgument(args, "ls-files")) return "index";
        if (HasArgument(args, "cat-file") && HasArgument(args, "--batch"))
            return "batch";
        return "other";
    }

    private static void RecordInvocation(string[] args)
    {
        var path = Environment.GetEnvironmentVariable(
            "SCANNER_TEST_INVOCATION_REPORT");
        if (String.IsNullOrEmpty(path)) return;
        File.AppendAllText(
            path,
            InvocationKind(args) + Environment.NewLine,
            new UTF8Encoding(false));
    }

    private static int IncrementCounter(string path)
    {
        using (var stream = new FileStream(
            path,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None))
        {
            if (stream.Length > 16) throw new InvalidDataException();
            var bytes = new byte[(int)stream.Length];
            if (bytes.Length > 0 && stream.Read(bytes, 0, bytes.Length) != bytes.Length)
                throw new EndOfStreamException();
            var text = Encoding.ASCII.GetString(bytes);
            var value = 0;
            if (text.Length > 0 && !Int32.TryParse(text, out value))
                throw new InvalidDataException();
            value++;
            var encoded = Encoding.ASCII.GetBytes(value.ToString());
            stream.Position = 0;
            stream.SetLength(0);
            stream.Write(encoded, 0, encoded.Length);
            stream.Flush(true);
            return value;
        }
    }

    private static int RunCapturedProcess(
        string filePath,
        string[] arguments,
        int timeoutMilliseconds)
    {
        var startInfo = new ProcessStartInfo();
        startInfo.FileName = filePath;
        var quoted = new string[arguments.Length];
        for (var index = 0; index < arguments.Length; index++)
            quoted[index] = Quote(arguments[index]);
        startInfo.Arguments = String.Join(" ", quoted);
        startInfo.UseShellExecute = false;
        startInfo.CreateNoWindow = true;
        startInfo.RedirectStandardOutput = true;
        startInfo.RedirectStandardError = true;
        using (var process = Process.Start(startInfo))
        {
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(timeoutMilliseconds))
            {
                process.Kill();
                process.WaitForExit(5000);
                return 96;
            }
            if (!Task.WaitAll(new Task[] { stdout, stderr }, 5000))
                return 97;
            return process.ExitCode;
        }
    }

    private static bool SpawnImmediateContainedDescendant()
    {
        var processReport = Environment.GetEnvironmentVariable(
            "SCANNER_TEST_PROCESS_REPORT");
        if (String.IsNullOrEmpty(processReport)) return false;

        bool inJob;
        var querySucceeded = IsProcessInJob(
            Process.GetCurrentProcess().Handle,
            IntPtr.Zero,
            out inJob);
        var executable = Process.GetCurrentProcess().MainModule.FileName;
        var startupInfo = new STARTUPINFO();
        startupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
        PROCESS_INFORMATION processInformation = new PROCESS_INFORMATION();
        var childId = 0;
        try
        {
            // bInheritHandles=false の native immediate spawn により、sleeper
            // は scanner pipe を一切持たず、親 wrapper の Job だけを継承する。
            if (!CreateProcessW(
                    executable,
                    new StringBuilder(
                        Quote(executable) + " --detached-grandchild"),
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    CreateNoWindow,
                    IntPtr.Zero,
                    null,
                    ref startupInfo,
                    out processInformation))
                return false;
            childId = processInformation.dwProcessId;
        }
        finally
        {
            if (processInformation.hThread != IntPtr.Zero)
                CloseHandle(processInformation.hThread);
            if (processInformation.hProcess != IntPtr.Zero)
                CloseHandle(processInformation.hProcess);
        }
        File.AppendAllText(
            processReport,
            "parent-pid=" + Process.GetCurrentProcess().Id +
            ";child-pid=" + childId +
            ";parent-in-job=" + (
                querySucceeded && inJob ? "true" : "false") +
            Environment.NewLine,
            new UTF8Encoding(false));
        return querySucceeded && inJob;
    }

    private static void RecordEnvironment(string reportPath)
    {
        var environment = Environment.GetEnvironmentVariables();
        var line = String.Join(";", new[] {
            "unknown-empty=" + (environment.Contains("GIT_FUTURE_SYNTHETIC") ? "present" : "absent"),
            "unknown-nonempty=" + (environment.Contains("GIT_FUTURE_NONEMPTY") ? "present" : "absent"),
            "git-dir=" + (environment.Contains("GIT_DIR") ? "present" : "absent"),
            "config-count=" + (environment.Contains("GIT_CONFIG_COUNT") ? "present" : "absent"),
            "trace=" + (environment.Contains("GIT_TRACE") ? "present" : "absent"),
            "no-lazy-fetch=" + (
                String.Equals(Environment.GetEnvironmentVariable("GIT_NO_LAZY_FETCH"), "1", StringComparison.Ordinal)
                    ? "enabled"
                    : "disabled"),
            "no-replace=" + (
                String.Equals(Environment.GetEnvironmentVariable("GIT_NO_REPLACE_OBJECTS"), "1", StringComparison.Ordinal)
                    ? "enabled"
                    : "disabled"),
            "safe-config=" + (environment.Contains("GIT_CONFIG_NOSYSTEM") ? "present" : "absent")
        });
        File.AppendAllText(reportPath, line + Environment.NewLine, new UTF8Encoding(false));
    }

    public static int Main(string[] args)
    {
        var reportPath = Environment.GetEnvironmentVariable("SCANNER_TEST_REPORT");
        if (String.IsNullOrEmpty(reportPath)) return 91;

        if (args.Length == 1 && args[0] == "--detached-grandchild")
        {
            Thread.Sleep(60000);
            return 0;
        }

        if (args.Length == 1 && args[0] == "--pipe-grandchild")
        {
            File.AppendAllText(
                reportPath,
                "grandchild-pid=" + Process.GetCurrentProcess().Id + Environment.NewLine,
                new UTF8Encoding(false));
            Thread.Sleep(60000);
            return 0;
        }

        if (args.Length == 1 && args[0] == "--hold-pipe-direct")
        {
            var childInfo = new ProcessStartInfo(
                Process.GetCurrentProcess().MainModule.FileName,
                "--pipe-grandchild");
            childInfo.UseShellExecute = false;
            var child = Process.Start(childInfo);
            File.AppendAllText(
                reportPath,
                "parent-pid=" + Process.GetCurrentProcess().Id +
                ";child-pid=" + child.Id + Environment.NewLine,
                new UTF8Encoding(false));
            Thread.Sleep(60000);
            return 0;
        }

        var mode = Environment.GetEnvironmentVariable("SCANNER_TEST_MODE") ?? "delegate";
        RecordInvocation(args);
        if (mode == "immediate-spawn" &&
            !SpawnImmediateContainedDescendant())
            return 95;
        RecordEnvironment(reportPath);
        if (mode == "environment-only") return 0;
        if (mode == "probe-failure" && HasArgument(args, "rev-parse")) return 65;
        if (mode == "malformed" && HasArgument(args, "rev-parse"))
        {
            Console.OpenStandardOutput().Write(
                Encoding.UTF8.GetBytes("only-one-line\n"),
                0,
                Encoding.UTF8.GetByteCount("only-one-line\n"));
            return 0;
        }
        if (mode == "path-escape" && HasArgument(args, "ls-files"))
        {
            var record = "100644 " + new String('1', 40) + " 0\t../escape.txt\0";
            var bytes = Encoding.UTF8.GetBytes(record);
            Console.OpenStandardOutput().Write(bytes, 0, bytes.Length);
            return 0;
        }
        if (mode == "conflict-stage" && HasArgument(args, "ls-files"))
        {
            var record = "100644 " + new String('1', 40) + " 1\tconflict.txt\0";
            var bytes = Encoding.UTF8.GetBytes(record);
            Console.OpenStandardOutput().Write(bytes, 0, bytes.Length);
            return 0;
        }
        if (mode == "intent-to-add" && HasArgument(args, "ls-files"))
        {
            var record = "100644 " + new String('0', 40) + " 0\tintent.txt\0";
            var bytes = Encoding.UTF8.GetBytes(record);
            Console.OpenStandardOutput().Write(bytes, 0, bytes.Length);
            return 0;
        }
        if (mode == "gitlink" && HasArgument(args, "ls-files"))
        {
            var record = "160000 " + new String('1', 40) + " 0\tsubmodule\0";
            var bytes = Encoding.UTF8.GetBytes(record);
            Console.OpenStandardOutput().Write(bytes, 0, bytes.Length);
            return 0;
        }
        if (mode == "malformed-index" && HasArgument(args, "ls-files"))
        {
            var bytes = Encoding.UTF8.GetBytes("malformed-index-record\0");
            Console.OpenStandardOutput().Write(bytes, 0, bytes.Length);
            return 0;
        }
        if (mode == "invalid-utf8" && HasArgument(args, "ls-files"))
        {
            var bytes = new byte[] { 0xff, 0x00 };
            Console.OpenStandardOutput().Write(bytes, 0, bytes.Length);
            return 0;
        }
        if (mode == "zero-text-entries" &&
            HasArgument(args, "ls-files") &&
            !HasArgument(args, "--debug"))
        {
            // 実fileを8193件作らず、stage-0 text recordを逐次生成する。
            // scannerはworktree validationやbatch前にtext-entry capで止まる。
            var output = Console.OpenStandardOutput();
            var objectId = new String('1', 40);
            for (var index = 0; index < 8193; index++)
            {
                var record =
                    "100644 " + objectId + " 0\tentry-" +
                    index.ToString("D4") + ".txt\0";
                var bytes = Encoding.UTF8.GetBytes(record);
                output.Write(bytes, 0, bytes.Length);
            }
            return 0;
        }
        if (mode == "huge-index" && HasArgument(args, "ls-files"))
        {
            var output = Console.OpenStandardOutput();
            var chunk = new byte[8192];
            for (var index = 0; index < 640; index++) output.Write(chunk, 0, chunk.Length);
            return 0;
        }
        if (mode == "nul-index" && HasArgument(args, "ls-files"))
        {
            var bytes = new byte[65536];
            Console.OpenStandardOutput().Write(bytes, 0, bytes.Length);
            return 0;
        }
        if (mode == "batch-malformed" &&
            HasArgument(args, "cat-file") &&
            HasArgument(args, "--batch"))
        {
            var bytes = Encoding.ASCII.GetBytes("malformed-batch-header\n");
            Console.OpenStandardOutput().Write(bytes, 0, bytes.Length);
            return 0;
        }
        if ((mode == "hold-pipe" || mode == "orphan-pipe") &&
            HasArgument(args, "rev-parse"))
        {
            var childInfo = new ProcessStartInfo(
                Process.GetCurrentProcess().MainModule.FileName,
                "--pipe-grandchild");
            childInfo.UseShellExecute = false;
            var child = Process.Start(childInfo);
            File.AppendAllText(
                reportPath,
                "parent-pid=" + Process.GetCurrentProcess().Id +
                ";child-pid=" + child.Id + Environment.NewLine,
                new UTF8Encoding(false));
            if (mode == "hold-pipe") Thread.Sleep(60000);
            return 0;
        }

        var realGit = Environment.GetEnvironmentVariable("SCANNER_TEST_REAL_GIT");
        if (String.IsNullOrEmpty(realGit)) return 92;
        if (mode == "index-mutation" &&
            HasArgument(args, "ls-files") &&
            !HasArgument(args, "--debug"))
        {
            var counterPath = Environment.GetEnvironmentVariable(
                "SCANNER_TEST_MUTATION_COUNTER");
            var repository = Environment.GetEnvironmentVariable(
                "SCANNER_TEST_MUTATION_REPO");
            var replacement = Environment.GetEnvironmentVariable(
                "SCANNER_TEST_MUTATION_REPLACEMENT");
            var addition = Environment.GetEnvironmentVariable(
                "SCANNER_TEST_MUTATION_ADDITION");
            var sentinel = Environment.GetEnvironmentVariable(
                "SCANNER_TEST_MUTATION_SENTINEL");
            if (String.IsNullOrEmpty(counterPath) ||
                String.IsNullOrEmpty(repository) ||
                String.IsNullOrEmpty(replacement) ||
                String.IsNullOrEmpty(addition) ||
                String.IsNullOrEmpty(sentinel))
                return 93;
            if (IncrementCounter(counterPath) == 2)
            {
                var mutationExit = RunCapturedProcess(
                    realGit,
                    new[] {
                        "-C", repository, "add", "--", replacement, addition
                    },
                    10000);
                if (mutationExit != 0) return mutationExit;
                File.WriteAllText(
                    sentinel,
                    "mutated",
                    new UTF8Encoding(false));
            }
        }
        if (mode == "flags-mutation" &&
            HasArgument(args, "ls-files") &&
            HasArgument(args, "--debug"))
        {
            var counterPath = Environment.GetEnvironmentVariable(
                "SCANNER_TEST_FLAGS_COUNTER");
            var repository = Environment.GetEnvironmentVariable(
                "SCANNER_TEST_FLAGS_REPO");
            var target = Environment.GetEnvironmentVariable(
                "SCANNER_TEST_FLAGS_TARGET");
            var sentinel = Environment.GetEnvironmentVariable(
                "SCANNER_TEST_FLAGS_SENTINEL");
            if (String.IsNullOrEmpty(counterPath) ||
                String.IsNullOrEmpty(repository) ||
                String.IsNullOrEmpty(target) ||
                String.IsNullOrEmpty(sentinel))
                return 94;
            if (IncrementCounter(counterPath) == 2)
            {
                var removeExit = RunCapturedProcess(
                    realGit,
                    new[] {
                        "-C", repository, "rm", "--cached", "--force",
                        "--quiet", "--", target
                    },
                    10000);
                if (removeExit != 0) return removeExit;
                var intentExit = RunCapturedProcess(
                    realGit,
                    new[] {
                        "-C", repository, "add", "-N", "--", target
                    },
                    10000);
                if (intentExit != 0) return intentExit;
                File.WriteAllText(
                    sentinel,
                    "flags-mutated",
                    new UTF8Encoding(false));
            }
        }
        var startInfo = new ProcessStartInfo();
        startInfo.FileName = realGit;
        var quoted = new string[args.Length];
        for (var index = 0; index < args.Length; index++) quoted[index] = Quote(args[index]);
        startInfo.Arguments = String.Join(" ", quoted);
        startInfo.UseShellExecute = false;
        var process = Process.Start(startInfo);
        if (!process.WaitForExit(15000))
        {
            process.Kill();
            if (!process.WaitForExit(5000)) return 98;
            return 99;
        }
        var exitCode = process.ExitCode;
        process.Dispose();
        return exitCode;
    }
}
'@

    # PowerShell 7 Add-Type は ConsoleApplication 出力を作れないため、
    # Windows 同梱の .NET Framework csc を bounded child として使う。
    $sourcePath = "$OutputPath.cs"
    [System.IO.File]::WriteAllText(
        $sourcePath,
        $source,
        (New-Object System.Text.UTF8Encoding($false)))
    $compilerCandidates = @(
        (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
        (Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
    )
    $compilerPath = $compilerCandidates |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
    if ([string]::IsNullOrEmpty($compilerPath)) {
        throw 'Synthetic Git wrapper compiler is unavailable.'
    }
    $compilerResult = Invoke-BoundedProcess `
        -FilePath $compilerPath `
        -ArgumentList @('/nologo', '/target:exe', "/out:$OutputPath", $sourcePath) `
        -Environment (Get-ProcessEnvironmentClone) `
        -TimeoutSeconds 30
    if ($compilerResult.ExitCode -ne 0) {
        throw "Synthetic Git wrapper compilation failed: $($compilerResult.Output.Trim())"
    }
}

function Assert-RecordedProcessesExited {
    param(
        [string]$ReportPath,
        [string]$Phase
    )

    if (-not (Test-Path -LiteralPath $ReportPath -PathType Leaf)) {
        Add-Failure "Expected process cleanup evidence after $Phase, but no PID report was created."
        return
    }

    $recordedIds = New-Object System.Collections.Generic.HashSet[int]
    foreach ($line in (Get-Content -LiteralPath $ReportPath -ErrorAction SilentlyContinue)) {
        foreach ($match in [regex]::Matches($line, '(?:parent|child|grandchild)-pid=(\d+)')) {
            [void]$recordedIds.Add([int]$match.Groups[1].Value)
        }
    }
    if ($recordedIds.Count -eq 0) {
        Add-Failure "Expected process cleanup evidence after $Phase, but no PID was recorded."
        return
    }

    foreach ($recordedId in $recordedIds) {
        $remaining = $null
        for ($attempt = 0; $attempt -lt 20; $attempt++) {
            $remaining = Get-Process -Id $recordedId -ErrorAction SilentlyContinue
            if ($null -eq $remaining) {
                break
            }
            Start-Sleep -Milliseconds 100
        }
        if ($null -ne $remaining) {
            Add-Failure "Expected bounded process-tree cleanup after $Phase, but PID $recordedId remains."
        }
    }
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("windows-git-stale-lock-recovery-scan-test-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot | Out-Null

try {
    Write-SelfTestProgress -Phase 'basic-and-output-bounds'

    # 存在しないhostile pathでも生pathやPowerShell error framingを返さず、
    # 小さいraw stdoutだけへ固定codeを1行出力する。
    $hostileMissingPath = Join-Path $tempRoot (
        'missing-' +
        [char]0x202e +
        'bidi-' +
        [char]0x200b +
        'format-' +
        [char]0x2028 +
        'line')
    $missingRootResult = Invoke-Scanner `
        -ScanPath $hostileMissingPath `
        -MaxStandardOutputBytes 128 `
        -MaxStandardErrorBytes 128
    [byte[]]$expectedMissingRootBytes =
        [System.Text.Encoding]::UTF8.GetBytes(
            'Private marker scan aborted: scan-root-resolution-failed' +
            [char]10)
    if ($missingRootResult.ExitCode -eq 0 -or
        $missingRootResult.TimedOut -or
        -not [string]::IsNullOrEmpty(
            $missingRootResult.OutputLimitExceeded) -or
        -not [System.Collections.StructuralComparisons]::StructuralEqualityComparer.Equals(
            $missingRootResult.StandardOutputBytes,
            $expectedMissingRootBytes) -or
        $missingRootResult.StandardErrorBytes.Length -ne 0 -or
        ($missingRootResult.StandardOutputBytes.Length +
            $missingRootResult.StandardErrorBytes.Length) -gt 128) {
        Add-Failure (
            'Expected hostile missing root to return only the bounded fixed ' +
            'scan-root-resolution-failed diagnostic.')
    }

    $cleanRoot = Join-Path $tempRoot 'clean'
    New-Item -ItemType Directory -Path $cleanRoot | Out-Null
    Set-Content -LiteralPath (Join-Path $cleanRoot 'README.md') -Value @(
        '# Clean synthetic fixture'
        'A completion notice is a claim, not evidence. Verify artifacts first.'
    ) -Encoding UTF8

    $cleanResult = Invoke-Scanner -ScanPath $cleanRoot
    if ($cleanResult.ExitCode -ne 0) {
        Add-Failure "Expected clean fixture to pass, but scanner exited $($cleanResult.ExitCode): $($cleanResult.Output.Trim())"
    }

    $markerRoot = Join-Path $tempRoot 'marker'
    New-Item -ItemType Directory -Path $markerRoot | Out-Null
    $syntheticMarker = ('g' + 'hp_') + 'synthetic_placeholder_only'
    Set-Content -LiteralPath (Join-Path $markerRoot 'leak.txt') -Value "synthetic marker: $syntheticMarker" -Encoding UTF8

    $markerResult = Invoke-Scanner -ScanPath $markerRoot
    if ($markerResult.ExitCode -eq 0) {
        Add-Failure 'Expected synthetic marker fixture to fail, but scanner exited 0.'
    }
    if ($markerResult.Output -notmatch 'github-classic-token-prefix') {
        Add-Failure "Expected synthetic marker output to name github-classic-token-prefix. Output: $($markerResult.Output.Trim())"
    }

    # Higher-recall cloud / PEM prefixes, with one redaction regression each.
    # Fixtures are synthetic placeholders only; no real secrets are used.
    $prefixCases = @(
        @{ Rule = 'openai-api-key-prefix';            Marker = ('s' + 'k-') + 'SyntheticOpenAI000000000000' }
        @{ Rule = 'aws-access-key-id';                Marker = ('A' + 'KIA') + 'EXAMPLE0000000000000' }
        @{ Rule = 'gcp-api-key-prefix';               Marker = ('AIza') + 'Synthetic0000000000000000000000000000' }
        @{ Rule = 'slack-user-token-prefix';          Marker = ('xo' + 'xp-') + 'synthetic-placeholder' }
        @{ Rule = 'slack-legacy-app-token-prefix';    Marker = ('xo' + 'xa-') + 'synthetic-placeholder' }
        @{ Rule = 'slack-app-level-token-prefix';     Marker = ('xa' + 'pp-') + 'synthetic-placeholder' }
        @{ Rule = 'stripe-live-secret-key';           Marker = ('s' + 'k') + '_live_SyntheticPlaceholder0000' }
        @{ Rule = 'pem-private-key-block';            Marker = '-----' + ('BEGIN ' + 'OPENSSH PRIVATE KEY') + '-----' }
    )

    foreach ($case in $prefixCases) {
        $prefixRoot = Join-Path $tempRoot ('prefix-' + $case.Rule)
        New-Item -ItemType Directory -Path $prefixRoot | Out-Null
        Set-Content -LiteralPath (Join-Path $prefixRoot 'leak.txt') -Value "synthetic marker: $($case.Marker)" -Encoding UTF8

        $prefixResult = Invoke-Scanner -ScanPath $prefixRoot
        if ($prefixResult.ExitCode -eq 0) {
            Add-Failure "Expected $($case.Rule) fixture to fail, but scanner exited 0."
        }
        if ($prefixResult.Output -notmatch [regex]::Escape($case.Rule)) {
            Add-Failure "Expected output to name $($case.Rule). Output: $($prefixResult.Output.Trim())"
        }
        # Preserve redaction: the raw marker value must never appear in output.
        if ($prefixResult.Output.Contains($case.Marker)) {
            Add-Failure "Expected $($case.Rule) finding to be redacted, but the raw marker leaked into output."
        }
        if ($prefixResult.Output -notmatch '<redacted>') {
            Add-Failure "Expected $($case.Rule) finding to report '<redacted>'. Output: $($prefixResult.Output.Trim())"
        }
    }

    # windows-absolute-path: private-looking paths should be findings.
    # Split the literal so this test file does not make the scanner flag itself.
    $winPathRealRoot = Join-Path $tempRoot 'winpath-real'
    New-Item -ItemType Directory -Path $winPathRealRoot | Out-Null
    $realWinPath = 'C' + ':\Users\realperson\Secrets\config'
    Set-Content -LiteralPath (Join-Path $winPathRealRoot 'doc.md') -Value "See $realWinPath for details." -Encoding UTF8
    $winPathRealResult = Invoke-Scanner -ScanPath $winPathRealRoot
    if ($winPathRealResult.ExitCode -eq 0) {
        Add-Failure 'Expected real-looking Windows path fixture to fail, but scanner exited 0.'
    }
    if ($winPathRealResult.Output -notmatch 'windows-absolute-path') {
        Add-Failure "Expected real Windows path output to name windows-absolute-path. Output: $($winPathRealResult.Output.Trim())"
    }

    # windows-absolute-path: documented placeholders should not be findings.
    $winPathDocRoot = Join-Path $tempRoot 'winpath-doc'
    New-Item -ItemType Directory -Path $winPathDocRoot | Out-Null
    Set-Content -LiteralPath (Join-Path $winPathDocRoot 'doc.md') -Value @'
Use a placeholder path such as C:\path\to\repo in examples.
You can also write C:\Users\<name>\project to describe a user directory.
'@ -Encoding UTF8
    $winPathDocResult = Invoke-Scanner -ScanPath $winPathDocRoot
    if ($winPathDocResult.ExitCode -ne 0) {
        Add-Failure "Expected placeholder Windows path doc to pass, but scanner exited $($winPathDocResult.ExitCode): $($winPathDocResult.Output.Trim())"
    }

    # 許可済みpathが1行へ大量反復してもMatchCollectionを全件保持せず、
    # Match/NextMatchの逐次評価でclean resultへ到達する。
    $allowlistFloodRoot = Join-Path $tempRoot 'allowlist-flood'
    New-Item -ItemType Directory -Path $allowlistFloodRoot | Out-Null
    $allowlistFloodWriter = New-Object System.IO.StreamWriter(
        (Join-Path $allowlistFloodRoot 'allowed.txt'),
        $false,
        (New-Object System.Text.UTF8Encoding($false)))
    try {
        $placeholderPath = 'C' + ':\path\to\repo'
        for ($index = 0; $index -lt 10000; $index++) {
            $allowlistFloodWriter.Write($placeholderPath)
            $allowlistFloodWriter.Write(' ')
        }
        $allowlistFloodWriter.WriteLine()
    }
    finally {
        $allowlistFloodWriter.Dispose()
    }
    $allowlistFloodResult = Invoke-Scanner -ScanPath $allowlistFloodRoot
    if ($allowlistFloodResult.ExitCode -ne 0) {
        Add-Failure "Expected repeated allowlisted paths to pass incrementally. Output: $($allowlistFloodResult.Output.Trim())"
    }

    $localMarkerRoot = Join-Path $tempRoot 'local-marker'
    New-Item -ItemType Directory -Path $localMarkerRoot | Out-Null
    Set-Content -LiteralPath (Join-Path $localMarkerRoot '.private-markers.local') -Value 'local-only-marker' -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $localMarkerRoot 'leak.txt') -Value 'synthetic local-only-marker fixture' -Encoding UTF8

    $localMarkerResult = Invoke-Scanner -ScanPath $localMarkerRoot
    if ($localMarkerResult.ExitCode -eq 0) {
        Add-Failure 'Expected local marker fixture to fail, but scanner exited 0.'
    }
    if ($localMarkerResult.Output -notmatch 'local-private-marker-1') {
        Add-Failure "Expected local marker output to name local-private-marker-1. Output: $($localMarkerResult.Output.Trim())"
    }

    # bidi / zero-width Format / Unicode line separator は可視 escape に変換し、
    # terminal 上で file/rule 列や後続行を偽装できないことを固定する。
    $unsafeDiagnosticRoot = Join-Path $tempRoot 'unsafe-diagnostic-path'
    New-Item -ItemType Directory -Path $unsafeDiagnosticRoot | Out-Null
    $unsafeDiagnosticName = (
        'visible' +
        [char]0x202e +
        'bidi' +
        [char]0x200b +
        'format' +
        [char]0x2028 +
        'line.txt')
    Set-Content `
        -LiteralPath (Join-Path $unsafeDiagnosticRoot $unsafeDiagnosticName) `
        -Value $syntheticMarker `
        -Encoding UTF8
    $unsafeDiagnosticResult = Invoke-Scanner -ScanPath $unsafeDiagnosticRoot
    if ($unsafeDiagnosticResult.ExitCode -eq 0 -or
        -not $unsafeDiagnosticResult.Output.Contains('\u202E') -or
        -not $unsafeDiagnosticResult.Output.Contains('\u200B') -or
        -not $unsafeDiagnosticResult.Output.Contains('\u2028') -or
        $unsafeDiagnosticResult.Output.Contains([string][char]0x202e) -or
        $unsafeDiagnosticResult.Output.Contains([string][char]0x200b) -or
        $unsafeDiagnosticResult.Output.Contains([string][char]0x2028)) {
        Add-Failure "Expected unsafe Unicode diagnostic characters to be escaped. Output: $($unsafeDiagnosticResult.Output.Trim())"
    }

    # 1行内 URL match の反復は per-line cap で止める。
    $foreignUrl = 'https://github' + '.com/example/private'
    $lineFindingRoot = Join-Path $tempRoot 'line-finding-cap'
    New-Item -ItemType Directory -Path $lineFindingRoot | Out-Null
    Set-Content `
        -LiteralPath (Join-Path $lineFindingRoot 'line.txt') `
        -Value ((1..33 | ForEach-Object { $foreignUrl }) -join ' ') `
        -Encoding UTF8
    $lineFindingResult = Invoke-Scanner -ScanPath $lineFindingRoot
    if ($lineFindingResult.ExitCode -eq 0 -or
        $lineFindingResult.Output -notmatch 'scan-line-finding-limit') {
        Add-Failure "Expected repeated same-line URLs to fail at the per-line finding cap. Output: $($lineFindingResult.Output.Trim())"
    }

    # 1file内の finding 反復は global cap より先に per-file cap で止める。
    $fileFindingRoot = Join-Path $tempRoot 'file-finding-cap'
    New-Item -ItemType Directory -Path $fileFindingRoot | Out-Null
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $fileFindingWriter = New-Object System.IO.StreamWriter(
        (Join-Path $fileFindingRoot 'file.txt'),
        $false,
        $utf8NoBom)
    try {
        for ($index = 0; $index -le 256; $index++) {
            $fileFindingWriter.WriteLine($syntheticMarker)
        }
    }
    finally {
        $fileFindingWriter.Dispose()
    }
    $fileFindingResult = Invoke-Scanner -ScanPath $fileFindingRoot
    if ($fileFindingResult.ExitCode -eq 0 -or
        $fileFindingResult.Output -notmatch 'scan-file-finding-limit') {
        Add-Failure "Expected repeated file markers to fail at the per-file finding cap. Output: $($fileFindingResult.Output.Trim())"
    }

    # per-file cap 未満の5fileへ分散し、scan全体1,000件 capを実際に超える。
    $findingFloodRoot = Join-Path $tempRoot 'finding-flood'
    New-Item -ItemType Directory -Path $findingFloodRoot | Out-Null
    for ($fileIndex = 0; $fileIndex -lt 5; $fileIndex++) {
        $findingWriter = New-Object System.IO.StreamWriter(
            (Join-Path $findingFloodRoot "flood-$fileIndex.txt"),
            $false,
            $utf8NoBom)
        try {
            for ($index = 0; $index -lt 201; $index++) {
                $findingWriter.WriteLine($syntheticMarker)
            }
        }
        finally {
            $findingWriter.Dispose()
        }
    }
    $findingFloodResult = Invoke-Scanner -ScanPath $findingFloodRoot
    if ($findingFloodResult.ExitCode -eq 0 -or
        $findingFloodResult.Output -notmatch 'scan-finding-limit') {
        Add-Failure "Expected repeated markers to fail at the finding cap. Output: $($findingFloodResult.Output.Trim())"
    }

    # prefix/header/row/LFを含むexpected payload byte数をfixture側でも計算する。
    # ASCIIだけで65,536/65,537 byteを隣接生成し、platform改行差を排除する。
    $findingPayloadByteCount = {
        param([object[]]$Specs)

        $plannedBytes = [System.Text.Encoding]::UTF8.GetByteCount(
            "Private marker scan failed (scan target: working-tree):`n" +
            "File`tSource`tLine`tRule`tMatch`n")
        foreach ($spec in $Specs) {
            for ($line = 1; $line -le $spec.Count; $line++) {
                $plannedBytes += [System.Text.Encoding]::UTF8.GetByteCount(
                    "$($spec.Name)`tworktree`t$line`t" +
                    "github-classic-token-prefix`t<redacted>`n")
            }
        }
        return $plannedBytes
    }
    $writeFindingPayloadFixture = {
        param(
            [string]$FixtureRoot,
            [object[]]$Specs
        )

        New-Item -ItemType Directory -Path $FixtureRoot | Out-Null
        foreach ($spec in $Specs) {
            $writer = New-Object System.IO.StreamWriter(
                (Join-Path $FixtureRoot $spec.Name),
                $false,
                $utf8NoBom)
            try {
                for ($index = 0; $index -lt $spec.Count; $index++) {
                    $writer.WriteLine($syntheticMarker)
                }
            }
            finally {
                $writer.Dispose()
            }
        }
    }

    # finding数は上限内でもactual payloadが65,537 bytesなら、
    # partial tableを表示せずgeneric output cap codeだけを返す。
    $findingOutputRoot = Join-Path $tempRoot 'finding-output-cap'
    $findingOutputSpecs = @(
        [pscustomobject]@{
            Name = 'a-' + ('x' * 161) + '.txt'
            Count = 131
        },
        [pscustomobject]@{
            Name = 'b-' + ('y' * 62) + '.txt'
            Count = 132
        },
        [pscustomobject]@{
            Name = 'c-' + ('z' * 20) + '.txt'
            Count = 133
        },
        [pscustomobject]@{
            Name = 'd-' + ('w' * 20) + '.txt'
            Count = 134
        })
    if ((& $findingPayloadByteCount $findingOutputSpecs) -ne 65537) {
        Add-Failure 'Expected over-limit fixture plan to equal exactly 65,537 UTF-8 bytes.'
    }
    & $writeFindingPayloadFixture $findingOutputRoot $findingOutputSpecs
    $findingOutputResult = Invoke-Scanner -ScanPath $findingOutputRoot
    if ($findingOutputResult.ExitCode -eq 0 -or
        $findingOutputResult.Output -notmatch 'scan-diagnostic-output-limit' -or
        $findingOutputResult.Output -match '<redacted>') {
        Add-Failure "Expected bounded diagnostic output without a partial finding table. Output: $($findingOutputResult.Output.Trim())"
    }

    # 1 byteだけ小さい65,536-byte payloadは全体を一度だけ出力する。
    # raw境界なのでWindowsでもCRLF換算誤差を許さない。
    $findingBoundaryRoot = Join-Path $tempRoot 'finding-output-boundary'
    $findingBoundarySpecs = @(
        [pscustomobject]@{
            Name = 'a-' + ('x' * 162) + '.txt'
            Count = 131
        },
        [pscustomobject]@{
            Name = 'b-' + ('y' * 61) + '.txt'
            Count = 132
        },
        [pscustomobject]@{
            Name = 'c-' + ('z' * 20) + '.txt'
            Count = 133
        },
        [pscustomobject]@{
            Name = 'd-' + ('w' * 20) + '.txt'
            Count = 134
        })
    if ((& $findingPayloadByteCount $findingBoundarySpecs) -ne 65536) {
        Add-Failure 'Expected accepted fixture plan to equal exactly 65,536 UTF-8 bytes.'
    }
    & $writeFindingPayloadFixture $findingBoundaryRoot $findingBoundarySpecs
    $findingBoundaryResult = Invoke-Scanner -ScanPath $findingBoundaryRoot
    if ($findingBoundaryResult.ExitCode -eq 0 -or
        $findingBoundaryResult.Output -match 'scan-diagnostic-output-limit' -or
        $findingBoundaryResult.StandardErrorBytes.Length -ne 0 -or
        $findingBoundaryResult.StandardOutputBytes.Length -ne (64 * 1024) -or
        $findingBoundaryResult.StandardOutputBytes -contains [byte]13 -or
        $findingBoundaryResult.StandardOutputBytes -notcontains [byte]10) {
        Add-Failure (
            'Expected one exact 65,536-byte explicit-LF UTF-8 finding ' +
            'payload with no stderr or CR bytes.')
    }

    # clean な短行でも全scan 100,000行を超えたら generic code で打ち切る。
    $lineFloodRoot = Join-Path $tempRoot 'line-flood'
    New-Item -ItemType Directory -Path $lineFloodRoot | Out-Null
    $lineFloodPath = Join-Path $lineFloodRoot 'flood.txt'
    $lineWriter = New-Object System.IO.StreamWriter(
        $lineFloodPath,
        $false,
        $utf8NoBom)
    try {
        for ($index = 0; $index -le 100000; $index++) {
            $lineWriter.WriteLine('clean')
        }
    }
    finally {
        $lineWriter.Dispose()
    }
    $lineFloodResult = Invoke-Scanner -ScanPath $lineFloodRoot
    if ($lineFloodResult.ExitCode -eq 0 -or
        $lineFloodResult.Output -notmatch 'scan-text-line-limit') {
        Add-Failure "Expected repeated clean lines to fail at the line cap. Output: $($lineFloodResult.Output.Trim())"
    }

    # local marker source 自体にも byte/rule 上限を適用する。
    $localMarkerCapRoot = Join-Path $tempRoot 'local-marker-cap'
    New-Item -ItemType Directory -Path $localMarkerCapRoot | Out-Null
    $environmentMarkerLines = @(
        for ($index = 0; $index -le 100; $index++) {
            "fixture-marker-$index"
        }
    ) -join "`n"
    $localMarkerCapResult = Invoke-Scanner `
        -ScanPath $localMarkerCapRoot `
        -EnvironmentOverrides @{
            WINDOWS_GIT_STALE_LOCK_RECOVERY_PRIVATE_MARKERS = $environmentMarkerLines
        }
    if ($localMarkerCapResult.ExitCode -eq 0 -or
        $localMarkerCapResult.Output -notmatch 'local-marker-count-limit') {
        Add-Failure "Expected environment marker rules to fail at the count cap. Output: $($localMarkerCapResult.Output.Trim())"
    }

    $localMarkerByteRoot = Join-Path $tempRoot 'local-marker-byte-cap'
    New-Item -ItemType Directory -Path $localMarkerByteRoot | Out-Null
    [System.IO.File]::WriteAllBytes(
        (Join-Path $localMarkerByteRoot '.private-markers.local'),
        (New-Object byte[] ((64 * 1024) + 1)))
    $localMarkerByteResult = Invoke-Scanner -ScanPath $localMarkerByteRoot
    if ($localMarkerByteResult.ExitCode -eq 0 -or
        $localMarkerByteResult.Output -notmatch 'local-marker-byte-limit') {
        Add-Failure "Expected local marker file to fail at the byte cap. Output: $($localMarkerByteResult.Output.Trim())"
    }

    # 非Git fallback も strict UTF-8 と per-file cap を共有する。
    $invalidUtf8Root = Join-Path $tempRoot 'invalid-utf8-worktree'
    New-Item -ItemType Directory -Path $invalidUtf8Root | Out-Null
    [System.IO.File]::WriteAllBytes(
        (Join-Path $invalidUtf8Root 'invalid.txt'),
        [byte[]]@(0xff))
    $invalidUtf8Result = Invoke-Scanner -ScanPath $invalidUtf8Root
    if ($invalidUtf8Result.ExitCode -eq 0 -or
        $invalidUtf8Result.Output -notmatch 'invalid UTF-8') {
        Add-Failure "Expected non-Git invalid UTF-8 to fail closed. Output: $($invalidUtf8Result.Output.Trim())"
    }

    $oversizedTextRoot = Join-Path $tempRoot 'oversized-worktree'
    New-Item -ItemType Directory -Path $oversizedTextRoot | Out-Null
    [System.IO.File]::WriteAllBytes(
        (Join-Path $oversizedTextRoot 'oversized.txt'),
        (New-Object byte[] ((4 * 1024 * 1024) + 1)))
    $oversizedTextResult = Invoke-Scanner -ScanPath $oversizedTextRoot
    if ($oversizedTextResult.ExitCode -eq 0 -or
        $oversizedTextResult.Output -notmatch 'tracked-worktree-file-size-limit') {
        Add-Failure "Expected non-Git text file to fail at the byte cap. Output: $($oversizedTextResult.Output.Trim())"
    }

    Write-SelfTestProgress -Phase 'fallback-boundaries'

    # non-Git fallback配下のnested `.git` directoryとleaf `.git` fileは、
    # markerを含んでもGit control metadataとして明示的に除外する。
    $nestedGitRoot = Join-Path $tempRoot 'nested-git-fallback'
    $nestedGitDirectoryParent = Join-Path $nestedGitRoot 'directory-case'
    $nestedGitLeafParent = Join-Path $nestedGitRoot 'leaf-case'
    $nestedGitDirectory = Join-Path $nestedGitDirectoryParent '.git'
    New-Item `
        -ItemType Directory `
        -Path $nestedGitDirectory, $nestedGitLeafParent |
        Out-Null
    Set-Content `
        -LiteralPath (Join-Path $nestedGitDirectory 'config') `
        -Value $syntheticMarker `
        -Encoding UTF8
    Set-Content `
        -LiteralPath (Join-Path $nestedGitLeafParent '.git') `
        -Value $syntheticMarker `
        -Encoding UTF8
    Set-Content `
        -LiteralPath (Join-Path $nestedGitRoot 'clean.txt') `
        -Value 'clean fallback fixture' `
        -Encoding UTF8
    $nestedGitResult = Invoke-Scanner -ScanPath $nestedGitRoot
    if ($nestedGitResult.ExitCode -ne 0) {
        Add-Failure "Expected nested directory and leaf .git controls to be excluded. Output: $($nestedGitResult.Output.Trim())"
    }

    if ($script:isWindowsRuntime) {
        Write-SelfTestProgress -Phase 'windows-containment'

        # native C# wrapperはWindows containment/env/mutation専用。POSIXでは
        # 後段のportable real-Git fixturesだけを実行し、cscへ依存しない。
        # 敵対的 GIT_* があっても requested repo の tracked 列挙を維持し、
        # trace/filter/hook artifact を fixture 外へ残さないことを同時に検証する。
        # test process 自体は変更せず、hostile 値は scanner child だけへ渡す。
        $adversarialRoot = Join-Path $tempRoot 'adversarial fixture'
    $targetRepo = Join-Path $adversarialRoot 'target'
    $alternateRepo = Join-Path $adversarialRoot 'alternate'
    $isolatedHome = Join-Path $adversarialRoot 'home'
    $processTemp = Join-Path $adversarialRoot 'process-temp'
    $artifactRoot = Join-Path $adversarialRoot 'artifacts'
    foreach ($directory in @($targetRepo, $alternateRepo, $isolatedHome, $processTemp, $artifactRoot)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }
    $wrapperDirectory = Join-Path $adversarialRoot 'wrapper'
    New-Item -ItemType Directory -Path $wrapperDirectory | Out-Null
    $wrapperPath = Join-Path $wrapperDirectory 'git.exe'
    $wrapperReport = Join-Path $artifactRoot 'wrapper-report.txt'
    New-GitProbeWrapper -OutputPath $wrapperPath

    [void](Invoke-FixtureGit -WorkingTree $targetRepo -Arguments @('init', '--quiet') -IsolatedHome $isolatedHome)
    [void](Invoke-FixtureGit -WorkingTree $alternateRepo -Arguments @('init', '--quiet') -IsolatedHome $isolatedHome)
    $syntheticTrackedMarker = ('g' + 'hp_') + 'tracked_fixture_placeholder'
    Set-Content -LiteralPath (Join-Path $targetRepo 'must-find.txt') -Value $syntheticTrackedMarker -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $alternateRepo 'clean.txt') -Value 'clean alternate repository' -Encoding UTF8
    [void](Invoke-FixtureGit -WorkingTree $targetRepo -Arguments @('add', '--', 'must-find.txt') -IsolatedHome $isolatedHome)
    [void](Invoke-FixtureGit -WorkingTree $alternateRepo -Arguments @('add', '--', 'clean.txt') -IsolatedHome $isolatedHome)

    $emptyConfig = Join-Path $adversarialRoot 'hostile.gitconfig'
    Set-Content -LiteralPath $emptyConfig -Value @(
        '[core]'
        "    hooksPath = $(Join-Path $artifactRoot 'hooks')"
        "    attributesFile = $(Join-Path $artifactRoot 'attributes')"
        "    excludesFile = $(Join-Path $artifactRoot 'excludes')"
        '[init]'
        "    templateDir = $(Join-Path $artifactRoot 'template')"
        '[filter "synthetic"]'
        "    clean = powershell -NoProfile -Command Set-Content -LiteralPath '$(Join-Path $artifactRoot 'filter-ran.txt')' -Value ran"
    ) -Encoding UTF8

    $hostileEnvironment = @{
        GIT_INDEX_FILE = (Join-Path $alternateRepo '.git/index')
        GIT_DIR = (Join-Path $alternateRepo '.git')
        GIT_WORK_TREE = $alternateRepo
        GIT_OBJECT_DIRECTORY = (Join-Path $alternateRepo '.git/objects')
        GIT_ALTERNATE_OBJECT_DIRECTORIES = (Join-Path $targetRepo '.git/objects')
        GIT_CONFIG_GLOBAL = $emptyConfig
        GIT_CONFIG_SYSTEM = $emptyConfig
        GIT_CONFIG_COUNT = '1'
        GIT_CONFIG_KEY_0 = 'core.worktree'
        GIT_CONFIG_VALUE_0 = $alternateRepo
        GIT_TRACE = (Join-Path $artifactRoot 'git-trace.log')
        GIT_FUTURE_SYNTHETIC = ''
        GIT_FUTURE_NONEMPTY = 'must-be-removed'
        HOME = $isolatedHome
        USERPROFILE = $isolatedHome
        XDG_CONFIG_HOME = $isolatedHome
        TEMP = $processTemp
        TMP = $processTemp
        TMPDIR = $processTemp
        PATH = ($wrapperDirectory + [System.IO.Path]::PathSeparator + $env:PATH)
        SCANNER_TEST_REAL_GIT = $gitCommand.Source
        SCANNER_TEST_REPORT = $wrapperReport
        SCANNER_TEST_MODE = 'delegate'
    }

    # sanitize 前の child へ present-empty GIT_* が実際に届くことを先に証明する。
    # この control がなければ「scanner 後に absent」だけでは伝播失敗を見逃す。
    $inputEnvironmentReport = Join-Path $artifactRoot 'input-environment-report.txt'
    $inputEnvironment = $hostileEnvironment.Clone()
    $inputEnvironment['SCANNER_TEST_REPORT'] = $inputEnvironmentReport
    $inputEnvironment['SCANNER_TEST_MODE'] = 'environment-only'
    $inputEnvironmentResult = Invoke-BoundedProcess `
        -FilePath $wrapperPath `
        -ArgumentList @() `
        -Environment $inputEnvironment
    if ($inputEnvironmentResult.ExitCode -ne 0 -or
        -not (Test-Path -LiteralPath $inputEnvironmentReport -PathType Leaf)) {
        Add-Failure 'Expected direct wrapper evidence for the hostile input environment.'
    } else {
        $inputEvidence = @(Get-Content -LiteralPath $inputEnvironmentReport)
        if ($inputEvidence.Count -ne 1 -or
            $inputEvidence[0] -notmatch '^unknown-empty=present;unknown-nonempty=present;git-dir=present;config-count=present;trace=present;no-lazy-fetch=disabled;no-replace=disabled;safe-config=absent$') {
            Add-Failure "Direct wrapper did not observe the hostile present-empty input environment: $($inputEvidence -join ';')"
        }
    }
    Remove-Item -LiteralPath $inputEnvironmentReport -ErrorAction SilentlyContinue

    # Job containment を確立できない場合はGit wrapperを一度も起動せず、
    # platform errorを匿名codeへ畳んでfail closedにする。
    if ($script:isWindowsRuntime) {
        $containmentFailureReport = Join-Path $artifactRoot 'containment-failure-report.txt'
        $containmentFailureEnvironment = $hostileEnvironment.Clone()
        $containmentFailureEnvironment['SCANNER_TEST_REPORT'] = $containmentFailureReport
        $containmentFailureEnvironment['SCANNER_TEST_FORCE_CONTAINMENT_FAILURE'] = '1'
        $containmentFailureResult = Invoke-Scanner `
            -ScanPath $targetRepo `
            -EnvironmentOverrides $containmentFailureEnvironment
        if ($containmentFailureResult.ExitCode -eq 0 -or
            $containmentFailureResult.Output -notmatch 'git-process-containment-unavailable') {
            Add-Failure "Expected unavailable Job containment to fail closed. Output: $($containmentFailureResult.Output.Trim())"
        }
        if (Test-Path -LiteralPath $containmentFailureReport) {
            Add-Failure 'Git wrapper started before process containment was established.'
            Remove-Item -LiteralPath $containmentFailureReport -Force
        }
    }

    $environmentBeforeFailure = Get-ProcessEnvironmentClone
    $adversarialFailure = Invoke-Scanner -ScanPath $targetRepo -EnvironmentOverrides $hostileEnvironment
    Assert-EnvironmentUnchanged `
        -Before $environmentBeforeFailure `
        -After (Get-ProcessEnvironmentClone) `
        -Phase 'adversarial failure scan'
    if ($adversarialFailure.TimedOut) {
        Add-Failure 'Expected adversarial failure scan to finish before its timeout.'
    }
    if ($adversarialFailure.ExitCode -eq 0) {
        Add-Failure 'Expected adversarial tracked marker fixture to fail, but scanner exited 0.'
    }
    if ($adversarialFailure.Output -notmatch 'must-find\.txt' -or
        $adversarialFailure.Output -notmatch 'github-classic-token-prefix') {
        Add-Failure "Expected adversarial scan to inspect the requested repository. Output: $($adversarialFailure.Output.Trim())"
    }
    if ($adversarialFailure.Output -notmatch 'scan target: git-index\+worktree') {
        Add-Failure "Expected adversarial failure scan to preserve index/worktree mode. Output: $($adversarialFailure.Output.Trim())"
    }

    Set-Content -LiteralPath (Join-Path $targetRepo 'must-find.txt') -Value 'clean tracked fixture' -Encoding UTF8
    [void](Invoke-FixtureGit -WorkingTree $targetRepo -Arguments @('add', '--', 'must-find.txt') -IsolatedHome $isolatedHome)
    $environmentBeforeSuccess = Get-ProcessEnvironmentClone
    $adversarialSuccess = Invoke-Scanner -ScanPath $targetRepo -EnvironmentOverrides $hostileEnvironment
    Assert-EnvironmentUnchanged `
        -Before $environmentBeforeSuccess `
        -After (Get-ProcessEnvironmentClone) `
        -Phase 'adversarial success scan'
    if ($adversarialSuccess.TimedOut) {
        Add-Failure 'Expected adversarial success scan to finish before its timeout.'
    }
    if ($adversarialSuccess.ExitCode -ne 0) {
        Add-Failure "Expected clean adversarial fixture to pass, but scanner exited $($adversarialSuccess.ExitCode): $($adversarialSuccess.Output.Trim())"
    }
    if ($adversarialSuccess.Output -notmatch 'scan target: git-index\+worktree') {
        Add-Failure "Expected adversarial success scan to preserve index/worktree mode. Output: $($adversarialSuccess.Output.Trim())"
    }

    # wrapper が実際に受け取った child Env で、present-empty の未知 GIT_*
    # まで absent になり、安全 allowlist だけが再投入されたことを証明する。
    if (-not (Test-Path -LiteralPath $wrapperReport -PathType Leaf)) {
        Add-Failure "Expected behavioral Git wrapper evidence. Failure scan: $($adversarialFailure.Output.Trim()) Success scan: $($adversarialSuccess.Output.Trim())"
    } else {
        $wrapperEvidence = @(Get-Content -LiteralPath $wrapperReport)
        if ($wrapperEvidence.Count -lt 4) {
            Add-Failure 'Expected the behavioral Git wrapper to observe multiple sanitized child invocations.'
        }
        foreach ($evidenceLine in $wrapperEvidence) {
            if ($evidenceLine -notmatch '^unknown-empty=absent;unknown-nonempty=absent;git-dir=absent;config-count=absent;trace=absent;no-lazy-fetch=enabled;no-replace=enabled;safe-config=present$') {
                Add-Failure "Behavioral Git wrapper observed an unsanitized child environment: $evidenceLine"
            }
        }
        Remove-Item -LiteralPath $wrapperReport
    }

    Write-SelfTestProgress -Phase 'windows-command-budget'

    # text file 数を増やしても Git child は probe/list/debug/batch/
    # final-list/final-debug の6回だけであることを実 invocation 列で固定する。
    $boundedInvocationRepo = Join-Path $adversarialRoot 'bounded-invocations'
    $boundedInvocationHome = Join-Path $adversarialRoot 'bounded-invocations-home'
    New-Item `
        -ItemType Directory `
        -Path $boundedInvocationRepo, $boundedInvocationHome |
        Out-Null
    [void](Invoke-FixtureGit `
        -WorkingTree $boundedInvocationRepo `
        -Arguments @('init', '--quiet') `
        -IsolatedHome $boundedInvocationHome)
    for ($fixtureIndex = 0; $fixtureIndex -lt 256; $fixtureIndex++) {
        Set-Content `
            -LiteralPath (Join-Path $boundedInvocationRepo (
                'bounded-{0:D3}.txt' -f $fixtureIndex)) `
            -Value "clean bounded fixture $fixtureIndex" `
            -Encoding UTF8
    }
    [void](Invoke-FixtureGit `
        -WorkingTree $boundedInvocationRepo `
        -Arguments @('add', '--', '.') `
        -IsolatedHome $boundedInvocationHome)
    $boundedInvocationReport = Join-Path $artifactRoot 'bounded-invocations.txt'
    $boundedEnvironmentReport = Join-Path $artifactRoot 'bounded-environment.txt'
    $boundedEnvironment = $hostileEnvironment.Clone()
    $boundedEnvironment['SCANNER_TEST_REPORT'] = $boundedEnvironmentReport
    $boundedEnvironment['SCANNER_TEST_INVOCATION_REPORT'] = $boundedInvocationReport
    $boundedEnvironment['SCANNER_TEST_MODE'] = 'delegate'
    $boundedResult = Invoke-Scanner `
        -ScanPath $boundedInvocationRepo `
        -EnvironmentOverrides $boundedEnvironment
    if ($boundedResult.TimedOut -or $boundedResult.ExitCode -ne 0) {
        Add-Failure "Expected 256-file batch fixture to pass within its bound. Output: $($boundedResult.Output.Trim())"
    }
    $boundedInvocations = @(
        Get-Content -LiteralPath $boundedInvocationReport -ErrorAction SilentlyContinue)
    if (($boundedInvocations -join ',') -cne
        'probe,index,debug,batch,index,debug') {
        Add-Failure "Expected exactly six bounded Git invocations, got: $($boundedInvocations -join ',')"
    }
    Remove-Item `
        -LiteralPath $boundedInvocationReport, $boundedEnvironmentReport `
        -ErrorAction SilentlyContinue

    if ($script:isWindowsRuntime) {
        # ambient OS をunset/偽装しても trusted runtime判定は変わらない。
        # 各caseで6 commandが即時sleeperをJob継承し、close後に累積しないことを確認する。
        $platformCases = @(
            [pscustomobject]@{
                Name = 'os-unset'
                RemoveNames = @('OS')
                OverrideValue = $null
            },
            [pscustomobject]@{
                Name = 'os-spoofed'
                RemoveNames = @()
                OverrideValue = 'synthetic-posix'
            })
        foreach ($platformCase in $platformCases) {
            $immediateProcessReport = Join-Path $artifactRoot (
                "$($platformCase.Name)-processes.txt")
            $immediateInvocationReport = Join-Path $artifactRoot (
                "$($platformCase.Name)-invocations.txt")
            $immediateEnvironmentReport = Join-Path $artifactRoot (
                "$($platformCase.Name)-environment.txt")
            $immediateEnvironment = $hostileEnvironment.Clone()
            if ($null -ne $platformCase.OverrideValue) {
                $immediateEnvironment['OS'] = $platformCase.OverrideValue
            }
            $immediateEnvironment['SCANNER_TEST_REPORT'] =
                $immediateEnvironmentReport
            $immediateEnvironment['SCANNER_TEST_INVOCATION_REPORT'] =
                $immediateInvocationReport
            $immediateEnvironment['SCANNER_TEST_PROCESS_REPORT'] =
                $immediateProcessReport
            $immediateEnvironment['SCANNER_TEST_MODE'] = 'immediate-spawn'
            $immediateResult = Invoke-Scanner `
                -ScanPath $boundedInvocationRepo `
                -EnvironmentOverrides $immediateEnvironment `
                -RemoveEnvironmentNames $platformCase.RemoveNames
            if ($immediateResult.TimedOut -or $immediateResult.ExitCode -ne 0) {
                Add-Failure "Expected atomic immediate-spawn fixture ($($platformCase.Name)) to pass. Output: $($immediateResult.Output.Trim())"
            }
            $immediateInvocations = @(
                Get-Content `
                    -LiteralPath $immediateInvocationReport `
                    -ErrorAction SilentlyContinue)
            if (($immediateInvocations -join ',') -cne
                'probe,index,debug,batch,index,debug') {
                Add-Failure "Expected six immediate-spawn commands ($($platformCase.Name)), got: $($immediateInvocations -join ',')"
            }
            $immediateProcessEvidence = @(
                Get-Content `
                    -LiteralPath $immediateProcessReport `
                    -ErrorAction SilentlyContinue)
            if ($immediateProcessEvidence.Count -ne 6 -or
                @($immediateProcessEvidence | Where-Object {
                    $_ -notmatch ';parent-in-job=true$'
                }).Count -gt 0) {
                Add-Failure "Expected every immediate-spawn wrapper ($($platformCase.Name)) to observe itself inside a Job."
            }
            Assert-RecordedProcessesExited `
                -ReportPath $immediateProcessReport `
                -Phase "atomic immediate-spawn commands ($($platformCase.Name))"
            Remove-Item `
                -LiteralPath @(
                    $immediateProcessReport,
                    $immediateInvocationReport,
                    $immediateEnvironmentReport) `
                -ErrorAction SilentlyContinue
        }
    }

    Write-SelfTestProgress -Phase 'windows-mutation-detection'

    # 2回目の ls-files 直前に wrapper が実際の index へ add と OID replace
    # を行う。最終 raw snapshot が初回と違えば、結果を返さず fail closed にする。
    $mutationRepo = Join-Path $adversarialRoot 'index-mutation'
    $mutationHome = Join-Path $adversarialRoot 'index-mutation-home'
    New-Item -ItemType Directory -Path $mutationRepo, $mutationHome | Out-Null
    [void](Invoke-FixtureGit `
        -WorkingTree $mutationRepo `
        -Arguments @('init', '--quiet') `
        -IsolatedHome $mutationHome)
    Set-Content `
        -LiteralPath (Join-Path $mutationRepo 'replace.txt') `
        -Value 'clean old index content' `
        -Encoding UTF8
    [void](Invoke-FixtureGit `
        -WorkingTree $mutationRepo `
        -Arguments @('add', '--', 'replace.txt') `
        -IsolatedHome $mutationHome)
    $oldMutationMetadata = Invoke-FixtureGit `
        -WorkingTree $mutationRepo `
        -Arguments @('ls-files', '--stage', '--', 'replace.txt') `
        -IsolatedHome $mutationHome
    $oldMutationObject = ($oldMutationMetadata.Output.Trim() -split '\s+')[1]
    Set-Content `
        -LiteralPath (Join-Path $mutationRepo 'replace.txt') `
        -Value 'clean replacement worktree content' `
        -Encoding UTF8
    Set-Content `
        -LiteralPath (Join-Path $mutationRepo 'addition.txt') `
        -Value 'clean added worktree content' `
        -Encoding UTF8
    $mutationCounter = Join-Path $artifactRoot 'mutation-counter.txt'
    $mutationSentinel = Join-Path $artifactRoot 'mutation-complete.txt'
    $mutationEnvironmentReport = Join-Path $artifactRoot 'mutation-environment.txt'
    $mutationEnvironment = $hostileEnvironment.Clone()
    $mutationEnvironment['SCANNER_TEST_REPORT'] = $mutationEnvironmentReport
    $mutationEnvironment['SCANNER_TEST_MODE'] = 'index-mutation'
    $mutationEnvironment['SCANNER_TEST_MUTATION_COUNTER'] = $mutationCounter
    $mutationEnvironment['SCANNER_TEST_MUTATION_SENTINEL'] = $mutationSentinel
    $mutationEnvironment['SCANNER_TEST_MUTATION_REPO'] = $mutationRepo
    $mutationEnvironment['SCANNER_TEST_MUTATION_REPLACEMENT'] = 'replace.txt'
    $mutationEnvironment['SCANNER_TEST_MUTATION_ADDITION'] = 'addition.txt'
    $mutationResult = Invoke-Scanner `
        -ScanPath $mutationRepo `
        -EnvironmentOverrides $mutationEnvironment
    if ($mutationResult.TimedOut -or
        $mutationResult.ExitCode -eq 0 -or
        $mutationResult.Output -notmatch 'git-index-changed-during-scan') {
        Add-Failure "Expected actual staged add/replace during scan to fail closed. Output: $($mutationResult.Output.Trim())"
    }
    $mutationCount = if (Test-Path -LiteralPath $mutationCounter) {
        (Get-Content -LiteralPath $mutationCounter -Raw).Trim()
    } else {
        ''
    }
    if ($mutationCount -cne '2' -or
        -not (Test-Path -LiteralPath $mutationSentinel -PathType Leaf)) {
        Add-Failure 'Expected mutation wrapper to run exactly on the second index enumeration.'
    }
    $newMutationMetadata = Invoke-FixtureGit `
        -WorkingTree $mutationRepo `
        -Arguments @('ls-files', '--stage', '--', 'replace.txt', 'addition.txt') `
        -IsolatedHome $mutationHome
    $newMutationLines = @($newMutationMetadata.Output -split "\r?\n" |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $replacementMetadataLine = $newMutationLines |
        Where-Object { $_ -match "`treplace\.txt$" } |
        Select-Object -First 1
    $additionMetadataLine = $newMutationLines |
        Where-Object { $_ -match "`taddition\.txt$" } |
        Select-Object -First 1
    $newMutationObject = if ($null -ne $replacementMetadataLine) {
        ($replacementMetadataLine -split '\s+')[1]
    } else {
        ''
    }
    if ([string]::IsNullOrEmpty($additionMetadataLine) -or
        [string]::IsNullOrEmpty($newMutationObject) -or
        $newMutationObject -ceq $oldMutationObject) {
        Add-Failure 'Expected mutation fixture to prove a real staged addition and OID replacement.'
    }
    Remove-Item `
        -LiteralPath @(
            $mutationCounter,
            $mutationSentinel,
            $mutationEnvironmentReport) `
        -ErrorAction SilentlyContinue

    # mode/OID/pathを同一に保ったまま、2回目debug直前に通常のempty blob
    # entryをITAへ差し替える。stage rawだけでは見えないflags-only変化を拒否する。
    $flagsRepo = Join-Path $adversarialRoot 'flags-mutation'
    $flagsHome = Join-Path $adversarialRoot 'flags-mutation-home'
    New-Item -ItemType Directory -Path $flagsRepo, $flagsHome | Out-Null
    [void](Invoke-FixtureGit `
        -WorkingTree $flagsRepo `
        -Arguments @('init', '--quiet') `
        -IsolatedHome $flagsHome)
    [System.IO.File]::WriteAllBytes(
        (Join-Path $flagsRepo 'flag.txt'),
        (New-Object byte[] 0))
    [void](Invoke-FixtureGit `
        -WorkingTree $flagsRepo `
        -Arguments @('add', '--', 'flag.txt') `
        -IsolatedHome $flagsHome)
    $flagsMetadataBefore = Invoke-FixtureGit `
        -WorkingTree $flagsRepo `
        -Arguments @('ls-files', '--stage', '--', 'flag.txt') `
        -IsolatedHome $flagsHome
    $flagsCounter = Join-Path $artifactRoot 'flags-counter.txt'
    $flagsSentinel = Join-Path $artifactRoot 'flags-complete.txt'
    $flagsEnvironmentReport = Join-Path $artifactRoot 'flags-environment.txt'
    $flagsEnvironment = $hostileEnvironment.Clone()
    $flagsEnvironment['SCANNER_TEST_REPORT'] = $flagsEnvironmentReport
    $flagsEnvironment['SCANNER_TEST_MODE'] = 'flags-mutation'
    $flagsEnvironment['SCANNER_TEST_FLAGS_COUNTER'] = $flagsCounter
    $flagsEnvironment['SCANNER_TEST_FLAGS_SENTINEL'] = $flagsSentinel
    $flagsEnvironment['SCANNER_TEST_FLAGS_REPO'] = $flagsRepo
    $flagsEnvironment['SCANNER_TEST_FLAGS_TARGET'] = 'flag.txt'
    $flagsResult = Invoke-Scanner `
        -ScanPath $flagsRepo `
        -EnvironmentOverrides $flagsEnvironment
    if ($flagsResult.TimedOut -or
        $flagsResult.ExitCode -eq 0 -or
        $flagsResult.Output -notmatch 'git-index-debug-changed-during-scan') {
        Add-Failure "Expected flags-only ITA mutation to fail raw debug comparison. Output: $($flagsResult.Output.Trim())"
    }
    $flagsCount = if (Test-Path -LiteralPath $flagsCounter) {
        (Get-Content -LiteralPath $flagsCounter -Raw).Trim()
    } else {
        ''
    }
    $flagsMetadataAfter = Invoke-FixtureGit `
        -WorkingTree $flagsRepo `
        -Arguments @('ls-files', '--stage', '--', 'flag.txt') `
        -IsolatedHome $flagsHome
    if ($flagsCount -cne '2' -or
        -not (Test-Path -LiteralPath $flagsSentinel -PathType Leaf) -or
        $flagsMetadataBefore.Output.Trim() -cne
            $flagsMetadataAfter.Output.Trim()) {
        Add-Failure 'Expected flags-only fixture to preserve mode/OID/path while changing CE_INTENT_TO_ADD.'
    }
    Remove-Item `
        -LiteralPath @(
            $flagsCounter,
            $flagsSentinel,
            $flagsEnvironmentReport) `
        -ErrorAction SilentlyContinue

    # exit 0 でも malformed probe / repo 外 index path は fallback せず拒否する。
    $malformedReport = Join-Path $artifactRoot 'malformed-report.txt'
    $malformedEnvironment = $hostileEnvironment.Clone()
    $malformedEnvironment['SCANNER_TEST_REPORT'] = $malformedReport
    $malformedEnvironment['SCANNER_TEST_MODE'] = 'malformed'
    $malformedResult = Invoke-Scanner `
        -ScanPath $targetRepo `
        -EnvironmentOverrides $malformedEnvironment
    if ($malformedResult.ExitCode -eq 0 -or $malformedResult.Output -notmatch 'malformed-git-probe') {
        Add-Failure "Expected malformed successful Git probe to fail closed. Output: $($malformedResult.Output.Trim())"
    }
    Remove-Item -LiteralPath $malformedReport -ErrorAction SilentlyContinue

    # Git probe 自体が失敗しても、祖先に .git がある subdirectory を non-Git
    # working-tree scan へ縮退させない。
    $probeFailureDirectory = Join-Path $targetRepo 'probe-failure-subdirectory'
    New-Item -ItemType Directory -Path $probeFailureDirectory | Out-Null
    Set-Content `
        -LiteralPath (Join-Path $probeFailureDirectory 'clean.txt') `
        -Value 'clean fixture' `
        -Encoding UTF8
    $probeFailureReport = Join-Path $artifactRoot 'probe-failure-report.txt'
    $probeFailureEnvironment = $hostileEnvironment.Clone()
    $probeFailureEnvironment['SCANNER_TEST_REPORT'] = $probeFailureReport
    $probeFailureEnvironment['SCANNER_TEST_MODE'] = 'probe-failure'
    $probeFailureResult = Invoke-Scanner `
        -ScanPath $probeFailureDirectory `
        -EnvironmentOverrides $probeFailureEnvironment
    if ($probeFailureResult.ExitCode -eq 0 -or
        $probeFailureResult.Output -notmatch 'git-repository-probe-failed') {
        Add-Failure "Expected failed Git probe below a repository root to fail closed. Output: $($probeFailureResult.Output.Trim())"
    }
    Remove-Item -LiteralPath $probeFailureReport -ErrorAction SilentlyContinue

    $escapeReport = Join-Path $artifactRoot 'escape-report.txt'
    $escapeEnvironment = $hostileEnvironment.Clone()
    $escapeEnvironment['SCANNER_TEST_REPORT'] = $escapeReport
    $escapeEnvironment['SCANNER_TEST_MODE'] = 'path-escape'
    $escapeResult = Invoke-Scanner `
        -ScanPath $targetRepo `
        -EnvironmentOverrides $escapeEnvironment
    if ($escapeResult.ExitCode -eq 0 -or $escapeResult.Output -notmatch 'tracked-path-escape') {
        Add-Failure "Expected repository-escaping index path to fail closed. Output: $($escapeResult.Output.Trim())"
    }
    Remove-Item -LiteralPath $escapeReport -ErrorAction SilentlyContinue

    $indexFailureCases = @(
        @{ Mode = 'conflict-stage'; Expected = 'tracked-entry-conflict-stage' }
        @{ Mode = 'intent-to-add'; Expected = 'tracked-entry-intent-to-add' }
        @{ Mode = 'gitlink'; Expected = 'tracked-entry-gitlink' }
        @{ Mode = 'malformed-index'; Expected = 'malformed-git-index-entry' }
        @{ Mode = 'invalid-utf8'; Expected = 'Child process emitted invalid UTF-8' }
        @{ Mode = 'zero-text-entries'; Expected = 'git-index-text-entry-limit' }
        @{ Mode = 'huge-index'; Expected = 'git-index-output-limit' }
        @{ Mode = 'nul-index'; Expected = 'malformed-git-index-entry' }
        @{ Mode = 'batch-malformed'; Expected = 'git-index-blob-read-failed' }
    )
    foreach ($indexFailureCase in $indexFailureCases) {
        $caseReport = Join-Path $artifactRoot ($indexFailureCase.Mode + '-report.txt')
        $caseEnvironment = $hostileEnvironment.Clone()
        $caseEnvironment['SCANNER_TEST_REPORT'] = $caseReport
        $caseEnvironment['SCANNER_TEST_MODE'] = $indexFailureCase.Mode
        $caseResult = Invoke-Scanner `
            -ScanPath $targetRepo `
            -EnvironmentOverrides $caseEnvironment
        if ($caseResult.ExitCode -eq 0 -or
            $caseResult.Output -notmatch [regex]::Escape($indexFailureCase.Expected)) {
            Add-Failure "Expected $($indexFailureCase.Mode) index metadata to fail closed as $($indexFailureCase.Expected). Output: $($caseResult.Output.Trim())"
        }
        Remove-Item -LiteralPath $caseReport -ErrorAction SilentlyContinue
    }

    Write-SelfTestProgress -Phase 'windows-timeout-containment'

    # scanner 内部の Git child が孫に pipe を保持させても、15秒 deadline
    # で tree kill し、外側 self-test timeout には到達しない。
    $pipeReport = Join-Path $artifactRoot 'pipe-report.txt'
    $pipeEnvironment = $hostileEnvironment.Clone()
    $pipeEnvironment['SCANNER_TEST_REPORT'] = $pipeReport
    $pipeEnvironment['SCANNER_TEST_MODE'] = 'hold-pipe'
    $pipeResult = Invoke-Scanner `
        -ScanPath $targetRepo `
        -EnvironmentOverrides $pipeEnvironment `
        -TimeoutSeconds 40
    if ($pipeResult.TimedOut -or
        $pipeResult.ExitCode -eq 0 -or
        $pipeResult.Output -notmatch 'git-repository-probe-timeout') {
        Add-Failure "Expected scanner-owned descendant pipe timeout to fail closed within the outer bound. Output: $($pipeResult.Output.Trim())"
    }
    Assert-RecordedProcessesExited -ReportPath $pipeReport -Phase 'scanner descendant-pipe timeout'
    Remove-Item -LiteralPath $pipeReport -ErrorAction SilentlyContinue

    # launcher が即exitし、孫だけがpipeを保持する分岐も固定する。
    # Windowsではscanner自身のkill-on-close Jobが終了時にorphanを回収する。
    if ($script:isWindowsRuntime) {
        $orphanPipeReport = Join-Path $artifactRoot 'orphan-pipe-report.txt'
        $orphanPipeEnvironment = $hostileEnvironment.Clone()
        $orphanPipeEnvironment['SCANNER_TEST_REPORT'] = $orphanPipeReport
        $orphanPipeEnvironment['SCANNER_TEST_MODE'] = 'orphan-pipe'
        $orphanPipeResult = Invoke-Scanner `
            -ScanPath $targetRepo `
            -EnvironmentOverrides $orphanPipeEnvironment `
            -TimeoutSeconds 40
        if ($orphanPipeResult.TimedOut -or
            $orphanPipeResult.ExitCode -eq 0 -or
            $orphanPipeResult.Output -notmatch 'git-repository-probe-timeout') {
            Add-Failure "Expected orphan descendant pipe timeout to fail closed within the outer bound. Output: $($orphanPipeResult.Output.Trim())"
        }
        Assert-RecordedProcessesExited `
            -ReportPath $orphanPipeReport `
            -Phase 'scanner orphan-pipe timeout'
        Remove-Item -LiteralPath $orphanPipeReport -ErrorAction SilentlyContinue
    }

    # self-test helper 自身も同じ pipe 条件を有限時間で回収する。
    $helperPipeReport = Join-Path $artifactRoot 'helper-pipe-report.txt'
    $helperEnvironment = New-ChildEnvironment `
        -BaseEnvironment (Get-ProcessEnvironmentClone) `
        -Overrides @{
            SCANNER_TEST_REPORT = $helperPipeReport
        }
    $helperStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $helperPipeResult = Invoke-BoundedProcess `
        -FilePath $wrapperPath `
        -ArgumentList @('--hold-pipe-direct') `
        -Environment $helperEnvironment `
        -TimeoutSeconds 2
    if (-not $helperPipeResult.TimedOut -or $helperStopwatch.Elapsed.TotalSeconds -gt 12) {
        Add-Failure 'Expected self-test helper descendant pipe to time out and clean up within 12 seconds.'
    }
    Assert-RecordedProcessesExited -ReportPath $helperPipeReport -Phase 'self-test descendant-pipe timeout'
    Remove-Item -LiteralPath $helperPipeReport -ErrorAction SilentlyContinue

    $unexpectedArtifacts = @(Get-ChildItem -LiteralPath $artifactRoot -Recurse -Force -ErrorAction SilentlyContinue)
    if ($unexpectedArtifacts.Count -gt 0) {
        Add-Failure 'Expected no trace, hook, attribute, exclude, template, or filter artifact outside the scan target.'
    }
        $tempArtifacts = @(Get-ChildItem -LiteralPath $processTemp -Recurse -Force -ErrorAction SilentlyContinue)
        if ($tempArtifacts.Count -gt 0) {
            Add-Failure 'Expected scanner child temporary artifacts to be removed in finally cleanup.'
        }
    }

    Write-SelfTestProgress -Phase 'portable-real-git'

    # repo 内 subdir は曖昧な partial scan にせず、root contract 違反として拒否する。
    $subdirectoryResult = Invoke-Scanner -ScanPath (Join-Path $root 'scripts')
    if ($subdirectoryResult.ExitCode -eq 0 -or
        $subdirectoryResult.Output -notmatch 'scan-root-must-be-repository-root') {
        Add-Failure "Expected a repository subdirectory scan to fail closed with the root contract. Output: $($subdirectoryResult.Output.Trim())"
    }
    if ($subdirectoryResult.Output.Contains($root)) {
        Add-Failure 'Repository subdirectory rejection must not print the local absolute root.'
    }

    $brokenGitRoot = Join-Path $tempRoot 'broken-git-control'
    New-Item -ItemType Directory -Path $brokenGitRoot | Out-Null
    Set-Content -LiteralPath (Join-Path $brokenGitRoot '.git') -Value 'gitdir: missing-control-directory' -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $brokenGitRoot 'clean.txt') -Value 'clean fixture' -Encoding UTF8
    $brokenGitResult = Invoke-Scanner -ScanPath $brokenGitRoot
    if ($brokenGitResult.ExitCode -eq 0 -or
        $brokenGitResult.Output -notmatch 'git-repository-probe-failed') {
        Add-Failure "Expected a present but broken .git control entry to fail closed. Output: $($brokenGitResult.Output.Trim())"
    }

    # `.private-markers.local` は untracked 専用。force-add されても marker 値を
    # 表示せず、index に存在する事実だけで fail closed にする。
    $trackedLocalMarkerRepo = Join-Path $tempRoot 'tracked-local-marker'
    $trackedLocalMarkerHome = Join-Path $tempRoot 'tracked-local-marker-home'
    New-Item `
        -ItemType Directory `
        -Path $trackedLocalMarkerRepo, $trackedLocalMarkerHome |
        Out-Null
    [void](Invoke-FixtureGit `
        -WorkingTree $trackedLocalMarkerRepo `
        -Arguments @('init', '--quiet') `
        -IsolatedHome $trackedLocalMarkerHome)
    Set-Content `
        -LiteralPath (Join-Path $trackedLocalMarkerRepo '.private-markers.local') `
        -Value 'local-marker-contract-fixture' `
        -Encoding UTF8
    [void](Invoke-FixtureGit `
        -WorkingTree $trackedLocalMarkerRepo `
        -Arguments @('add', '-f', '--', '.private-markers.local') `
        -IsolatedHome $trackedLocalMarkerHome)
    $trackedLocalMarkerResult = Invoke-Scanner -ScanPath $trackedLocalMarkerRepo
    if ($trackedLocalMarkerResult.ExitCode -eq 0 -or
        $trackedLocalMarkerResult.Output -notmatch 'tracked-local-marker-file') {
        Add-Failure "Expected tracked local marker file to fail closed. Output: $($trackedLocalMarkerResult.Output.Trim())"
    }
    if ($trackedLocalMarkerResult.Output -match 'local-marker-contract-fixture') {
        Add-Failure 'Tracked local marker failure must not print the marker value.'
    }

    # 実Gitの `add -N` はOID全0ではなくempty-blob OIDをstage 0へ置く。
    # worktreeの有無に依存せず、`ls-files --debug` のCE_INTENT_TO_ADD flagで拒否する。
    $realIntentRepo = Join-Path $tempRoot 'real-intent-to-add'
    $realIntentHome = Join-Path $tempRoot 'real-intent-home'
    New-Item -ItemType Directory -Path $realIntentRepo, $realIntentHome | Out-Null
    [void](Invoke-FixtureGit `
        -WorkingTree $realIntentRepo `
        -Arguments @('init', '--quiet') `
        -IsolatedHome $realIntentHome)
    Set-Content `
        -LiteralPath (Join-Path $realIntentRepo 'intent.md') `
        -Value 'clean intent fixture' `
        -Encoding UTF8
    [void](Invoke-FixtureGit `
        -WorkingTree $realIntentRepo `
        -Arguments @('add', '-N', '--', 'intent.md') `
        -IsolatedHome $realIntentHome)
    $realIntentMetadata = Invoke-FixtureGit `
        -WorkingTree $realIntentRepo `
        -Arguments @('ls-files', '--stage', '--', 'intent.md') `
        -IsolatedHome $realIntentHome
    $realIntentObject = ($realIntentMetadata.Output.Trim() -split '\s+')[1]
    if ([string]::IsNullOrEmpty($realIntentObject) -or
        $realIntentObject -match '^0+$') {
        Add-Failure 'Expected real add -N fixture to use a nonzero placeholder object ID.'
    }
    $realIntentPresentResult = Invoke-Scanner -ScanPath $realIntentRepo
    if ($realIntentPresentResult.ExitCode -eq 0 -or
        $realIntentPresentResult.Output -notmatch 'tracked-entry-intent-to-add') {
        Add-Failure "Expected real present add -N entry to fail closed. Output: $($realIntentPresentResult.Output.Trim())"
    }
    Remove-Item -LiteralPath (Join-Path $realIntentRepo 'intent.md')
    $realIntentDeletedResult = Invoke-Scanner -ScanPath $realIntentRepo
    if ($realIntentDeletedResult.ExitCode -eq 0 -or
        $realIntentDeletedResult.Output -notmatch 'tracked-entry-intent-to-add') {
        Add-Failure "Expected deleted add -N placeholder to fail closed via raw index flags. Output: $($realIntentDeletedResult.Output.Trim())"
    }

    # portableな実Git merge conflictを作り、POSIXでもsynthetic wrapperなしに
    # stage 1/2/3 entryのfail-closed contractを検証する。
    $conflictRepo = Join-Path $tempRoot 'real-conflict-stage'
    $conflictHome = Join-Path $tempRoot 'real-conflict-home'
    New-Item -ItemType Directory -Path $conflictRepo, $conflictHome | Out-Null
    [void](Invoke-FixtureGit `
        -WorkingTree $conflictRepo `
        -Arguments @('init', '--quiet') `
        -IsolatedHome $conflictHome)
    Set-Content `
        -LiteralPath (Join-Path $conflictRepo 'conflict.txt') `
        -Value 'base fixture' `
        -Encoding UTF8
    [void](Invoke-FixtureGit `
        -WorkingTree $conflictRepo `
        -Arguments @('add', '--', 'conflict.txt') `
        -IsolatedHome $conflictHome)
    [void](Invoke-FixtureGit `
        -WorkingTree $conflictRepo `
        -Arguments @(
            '-c', 'user.name=Scanner Fixture',
            '-c', ('user.email=scanner' + '@' + 'example.invalid'),
            'commit', '--quiet', '-m', 'base fixture'
        ) `
        -IsolatedHome $conflictHome)
    [void](Invoke-FixtureGit `
        -WorkingTree $conflictRepo `
        -Arguments @('checkout', '-q', '-b', 'fixture-left') `
        -IsolatedHome $conflictHome)
    Set-Content `
        -LiteralPath (Join-Path $conflictRepo 'conflict.txt') `
        -Value 'left fixture' `
        -Encoding UTF8
    [void](Invoke-FixtureGit `
        -WorkingTree $conflictRepo `
        -Arguments @('add', '--', 'conflict.txt') `
        -IsolatedHome $conflictHome)
    [void](Invoke-FixtureGit `
        -WorkingTree $conflictRepo `
        -Arguments @(
            '-c', 'user.name=Scanner Fixture',
            '-c', ('user.email=scanner' + '@' + 'example.invalid'),
            'commit', '--quiet', '-m', 'left fixture'
        ) `
        -IsolatedHome $conflictHome)
    [void](Invoke-FixtureGit `
        -WorkingTree $conflictRepo `
        -Arguments @('checkout', '-q', '-b', 'fixture-right', 'HEAD~1') `
        -IsolatedHome $conflictHome)
    Set-Content `
        -LiteralPath (Join-Path $conflictRepo 'conflict.txt') `
        -Value 'right fixture' `
        -Encoding UTF8
    [void](Invoke-FixtureGit `
        -WorkingTree $conflictRepo `
        -Arguments @('add', '--', 'conflict.txt') `
        -IsolatedHome $conflictHome)
    [void](Invoke-FixtureGit `
        -WorkingTree $conflictRepo `
        -Arguments @(
            '-c', 'user.name=Scanner Fixture',
            '-c', ('user.email=scanner' + '@' + 'example.invalid'),
            'commit', '--quiet', '-m', 'right fixture'
        ) `
        -IsolatedHome $conflictHome)
    $mergeConflictResult = Invoke-FixtureGit `
        -WorkingTree $conflictRepo `
        -Arguments @(
            '-c', 'user.name=Scanner Fixture',
            '-c', ('user.email=scanner' + '@' + 'example.invalid'),
            'merge', '--no-edit', 'fixture-left'
        ) `
        -IsolatedHome $conflictHome `
        -AllowFailure
    $unmergedConflictResult = Invoke-FixtureGit `
        -WorkingTree $conflictRepo `
        -Arguments @('ls-files', '--unmerged', '--', 'conflict.txt') `
        -IsolatedHome $conflictHome
    if ($mergeConflictResult.ExitCode -eq 0 -or
        $unmergedConflictResult.Output -notmatch '\s[123]\s+conflict\.txt') {
        Add-Failure 'Expected portable real-Git fixture to create unmerged stage entries.'
    }
    $realConflictScanResult = Invoke-Scanner -ScanPath $conflictRepo
    if ($realConflictScanResult.ExitCode -eq 0 -or
        $realConflictScanResult.Output -notmatch 'tracked-entry-conflict-stage') {
        Add-Failure "Expected real conflict stages to fail closed. Output: $($realConflictScanResult.Output.Trim())"
    }

    # index と worktree の union: staged marker を worktree で消しても index 側で検出する。
    $indexUnionRepo = Join-Path $tempRoot 'index-union'
    $indexUnionHome = Join-Path $tempRoot 'index-union-home'
    New-Item -ItemType Directory -Path $indexUnionRepo, $indexUnionHome | Out-Null
    [void](Invoke-FixtureGit -WorkingTree $indexUnionRepo -Arguments @('init', '--quiet') -IsolatedHome $indexUnionHome)
    $indexOnlyMarker = ('g' + 'hp_') + 'index_only_placeholder'
    Set-Content -LiteralPath (Join-Path $indexUnionRepo 'staged.txt') -Value $indexOnlyMarker -Encoding UTF8
    [void](Invoke-FixtureGit -WorkingTree $indexUnionRepo -Arguments @('add', '--', 'staged.txt') -IsolatedHome $indexUnionHome)
    Set-Content -LiteralPath (Join-Path $indexUnionRepo 'staged.txt') -Value 'clean worktree content' -Encoding UTF8
    $indexUnionResult = Invoke-Scanner -ScanPath $indexUnionRepo
    if ($indexUnionResult.ExitCode -eq 0 -or
        $indexUnionResult.Output -notmatch 'github-classic-token-prefix' -or
        $indexUnionResult.Output -notmatch 'staged\.txt\s+index\s+1') {
        Add-Failure "Expected staged marker to be reported with index provenance. Output: $($indexUnionResult.Output.Trim())"
    }

    # refs/replace で index OID を clean blob へ差し替えても、
    # --no-replace-objects / GIT_NO_REPLACE_OBJECTS により marker を読む。
    $stageMetadata = Invoke-FixtureGit `
        -WorkingTree $indexUnionRepo `
        -Arguments @('ls-files', '--stage', '--', 'staged.txt') `
        -IsolatedHome $indexUnionHome
    $markerObjectId = ($stageMetadata.Output.Trim() -split '\s+')[1]
    Set-Content -LiteralPath (Join-Path $indexUnionRepo 'replacement.txt') -Value 'clean replacement blob' -Encoding UTF8
    $replacementBlob = Invoke-FixtureGit `
        -WorkingTree $indexUnionRepo `
        -Arguments @('hash-object', '-w', '--', 'replacement.txt') `
        -IsolatedHome $indexUnionHome
    [void](Invoke-FixtureGit `
        -WorkingTree $indexUnionRepo `
        -Arguments @('replace', $markerObjectId, $replacementBlob.Output.Trim()) `
        -IsolatedHome $indexUnionHome)
    $replaceResult = Invoke-Scanner -ScanPath $indexUnionRepo
    if ($replaceResult.ExitCode -eq 0 -or
        $replaceResult.Output -notmatch 'staged\.txt\s+index\s+1') {
        Add-Failure "Expected index scan to ignore refs/replace. Output: $($replaceResult.Output.Trim())"
    }
    [void](Invoke-FixtureGit `
        -WorkingTree $indexUnionRepo `
        -Arguments @('replace', '-d', $markerObjectId) `
        -IsolatedHome $indexUnionHome)

    Write-SelfTestProgress -Phase 'git-object-boundaries'

    # partial clone の欠損 blob はローカル promisor remote にだけ残す。
    # scanner が lazy fetch しなければ generic read failure のまま object は復元されず、
    # 誤って fetch すれば marker 検出と loose object の再生成で回帰を観測できる。
    $promisorRepo = Join-Path $tempRoot 'promisor-no-lazy-fetch'
    $promisorRemote = Join-Path $tempRoot 'promisor-remote.git'
    $promisorHome = Join-Path $tempRoot 'promisor-home'
    New-Item -ItemType Directory -Path $promisorRepo, $promisorHome | Out-Null
    [void](Invoke-FixtureGit `
        -WorkingTree $promisorRepo `
        -Arguments @('init', '--quiet') `
        -IsolatedHome $promisorHome)
    Set-Content `
        -LiteralPath (Join-Path $promisorRepo 'promised.txt') `
        -Value $indexOnlyMarker `
        -Encoding UTF8
    [void](Invoke-FixtureGit `
        -WorkingTree $promisorRepo `
        -Arguments @('add', '--', 'promised.txt') `
        -IsolatedHome $promisorHome)
    $promisorMetadata = Invoke-FixtureGit `
        -WorkingTree $promisorRepo `
        -Arguments @('ls-files', '--stage', '--', 'promised.txt') `
        -IsolatedHome $promisorHome
    $promisorObjectId = ($promisorMetadata.Output.Trim() -split '\s+')[1]
    [void](Invoke-FixtureGit `
        -WorkingTree $promisorRepo `
        -Arguments @(
            '-c', 'user.name=Scanner Fixture',
            '-c', ('user.email=scanner' + '@' + 'example.invalid'),
            'commit', '--quiet', '-m', 'promisor fixture'
        ) `
        -IsolatedHome $promisorHome)
    [void](Invoke-FixtureGit `
        -WorkingTree $tempRoot `
        -Arguments @(
            'clone', '--bare', '--quiet', '--no-hardlinks',
            '--', $promisorRepo, $promisorRemote
        ) `
        -IsolatedHome $promisorHome)
    [void](Invoke-FixtureGit `
        -WorkingTree $promisorRepo `
        -Arguments @('remote', 'add', 'origin', $promisorRemote) `
        -IsolatedHome $promisorHome)
    foreach ($configPair in @(
        @('core.repositoryformatversion', '1'),
        @('extensions.partialClone', 'origin'),
        @('remote.origin.promisor', 'true'),
        @('remote.origin.partialclonefilter', 'blob:none')
    )) {
        [void](Invoke-FixtureGit `
            -WorkingTree $promisorRepo `
            -Arguments @('config', $configPair[0], $configPair[1]) `
            -IsolatedHome $promisorHome)
    }
    Set-Content `
        -LiteralPath (Join-Path $promisorRepo 'promised.txt') `
        -Value 'clean worktree content' `
        -Encoding UTF8
    $promisorObjectDirectory = Join-Path `
        (Join-Path (Join-Path $promisorRepo '.git') 'objects') `
        $promisorObjectId.Substring(0, 2)
    $promisorObjectPath = Join-Path `
        $promisorObjectDirectory `
        $promisorObjectId.Substring(2)
    if (-not (Test-Path -LiteralPath $promisorObjectPath -PathType Leaf)) {
        Add-Failure 'Expected the synthetic promisor blob to start as a loose local object.'
    } else {
        Remove-Item -LiteralPath $promisorObjectPath -Force
        $promisorResult = Invoke-Scanner -ScanPath $promisorRepo
        if ($promisorResult.ExitCode -eq 0 -or
            $promisorResult.Output -notmatch 'git-index-blob-read-failed') {
            Add-Failure "Expected missing promisor blob to fail without lazy fetch. Output: $($promisorResult.Output.Trim())"
        }
        if (Test-Path -LiteralPath $promisorObjectPath) {
            Add-Failure 'Scanner lazy-fetched the synthetic promisor blob into the local object store.'
        }
    }

    # 逆向きも固定する: index は clean、worktree だけ marker の場合は
    # worktree provenance で検出する。
    Set-Content -LiteralPath (Join-Path $indexUnionRepo 'staged.txt') -Value 'clean index content' -Encoding UTF8
    [void](Invoke-FixtureGit -WorkingTree $indexUnionRepo -Arguments @('add', '--', 'staged.txt') -IsolatedHome $indexUnionHome)
    Set-Content -LiteralPath (Join-Path $indexUnionRepo 'staged.txt') -Value $indexOnlyMarker -Encoding UTF8
    $worktreeUnionResult = Invoke-Scanner -ScanPath $indexUnionRepo
    if ($worktreeUnionResult.ExitCode -eq 0 -or
        $worktreeUnionResult.Output -notmatch 'staged\.txt\s+worktree\s+1') {
        Add-Failure "Expected unstaged marker to be reported with worktree provenance. Output: $($worktreeUnionResult.Output.Trim())"
    }

    # dotenv / *.env / PEM / key は機密テキスト候補として index/worktree の
    # 両方向を走査する。一方、未登録 binary 拡張子は内容をdecodeせず安全にskipする。
    $sensitiveRepo = Join-Path $tempRoot 'sensitive-text-candidates'
    $sensitiveHome = Join-Path $tempRoot 'sensitive-text-home'
    New-Item -ItemType Directory -Path $sensitiveRepo, $sensitiveHome | Out-Null
    [void](Invoke-FixtureGit `
        -WorkingTree $sensitiveRepo `
        -Arguments @('init', '--quiet') `
        -IsolatedHome $sensitiveHome)
    $sensitiveMarker = ('g' + 'hp_') + 'sensitive_extension_placeholder'
    foreach ($indexCandidate in @('.env', '.env.local', 'certificate.pem')) {
        Set-Content `
            -LiteralPath (Join-Path $sensitiveRepo $indexCandidate) `
            -Value $sensitiveMarker `
            -Encoding UTF8
    }
    foreach ($worktreeCandidate in @('service.env', 'signing.key')) {
        Set-Content `
            -LiteralPath (Join-Path $sensitiveRepo $worktreeCandidate) `
            -Value 'clean staged content' `
            -Encoding UTF8
    }
    [System.IO.File]::WriteAllBytes(
        (Join-Path $sensitiveRepo 'opaque.bin'),
        [byte[]](
            [System.Text.Encoding]::ASCII.GetBytes($sensitiveMarker) +
            @(0xff, 0xfe, 0x00)))
    [void](Invoke-FixtureGit `
        -WorkingTree $sensitiveRepo `
        -Arguments @('add', '-f', '--', '.') `
        -IsolatedHome $sensitiveHome)
    foreach ($indexCandidate in @('.env', '.env.local', 'certificate.pem')) {
        Set-Content `
            -LiteralPath (Join-Path $sensitiveRepo $indexCandidate) `
            -Value 'clean worktree content' `
            -Encoding UTF8
    }
    foreach ($worktreeCandidate in @('service.env', 'signing.key')) {
        Set-Content `
            -LiteralPath (Join-Path $sensitiveRepo $worktreeCandidate) `
            -Value $sensitiveMarker `
            -Encoding UTF8
    }
    $sensitiveResult = Invoke-Scanner -ScanPath $sensitiveRepo
    if ($sensitiveResult.ExitCode -eq 0) {
        Add-Failure 'Expected sensitive text candidate fixture to report synthetic markers.'
    }
    foreach ($expectedEvidence in @(
        '\.env\s+index\s+1',
        '\.env\.local\s+index\s+1',
        'certificate\.pem\s+index\s+1',
        'service\.env\s+worktree\s+1',
        'signing\.key\s+worktree\s+1'
    )) {
        if ($sensitiveResult.Output -notmatch $expectedEvidence) {
            Add-Failure "Expected sensitive candidate evidence '$expectedEvidence'. Output: $($sensitiveResult.Output.Trim())"
        }
    }
    if ($sensitiveResult.Output -match 'opaque\.bin') {
        Add-Failure 'Binary safe-skip fixture must not be decoded or reported.'
    }

    # tracked file の unstaged delete は index blob だけを silently scan せず fail closed。
    $missingRepo = Join-Path $tempRoot 'missing-worktree'
    $missingHome = Join-Path $tempRoot 'missing-home'
    New-Item -ItemType Directory -Path $missingRepo, $missingHome | Out-Null
    [void](Invoke-FixtureGit -WorkingTree $missingRepo -Arguments @('init', '--quiet') -IsolatedHome $missingHome)
    Set-Content -LiteralPath (Join-Path $missingRepo 'missing.txt') -Value 'clean tracked content' -Encoding UTF8
    [void](Invoke-FixtureGit -WorkingTree $missingRepo -Arguments @('add', '--', 'missing.txt') -IsolatedHome $missingHome)
    Remove-Item -LiteralPath (Join-Path $missingRepo 'missing.txt')
    $missingResult = Invoke-Scanner -ScanPath $missingRepo
    if ($missingResult.ExitCode -eq 0 -or $missingResult.Output -notmatch 'tracked-worktree-missing') {
        Add-Failure "Expected unstaged tracked deletion to fail closed. Output: $($missingResult.Output.Trim())"
    }

    # OS symlink を作らず index mode 120000 を合成し、外部 target を追わず拒否する。
    $symlinkRepo = Join-Path $tempRoot 'tracked-symlink'
    $symlinkHome = Join-Path $tempRoot 'symlink-home'
    New-Item -ItemType Directory -Path $symlinkRepo, $symlinkHome | Out-Null
    [void](Invoke-FixtureGit -WorkingTree $symlinkRepo -Arguments @('init', '--quiet') -IsolatedHome $symlinkHome)
    Set-Content -LiteralPath (Join-Path $symlinkRepo 'link-target.txt') -Value '../outside-target' -Encoding UTF8
    $linkBlobResult = Invoke-FixtureGit `
        -WorkingTree $symlinkRepo `
        -Arguments @('hash-object', '-w', '--', 'link-target.txt') `
        -IsolatedHome $symlinkHome
    $linkBlob = $linkBlobResult.Output.Trim()
    [void](Invoke-FixtureGit `
        -WorkingTree $symlinkRepo `
        -Arguments @('update-index', '--add', '--cacheinfo', "120000,$linkBlob,synthetic-link") `
        -IsolatedHome $symlinkHome)
    $symlinkResult = Invoke-Scanner -ScanPath $symlinkRepo
    if ($symlinkResult.ExitCode -eq 0 -or $symlinkResult.Output -notmatch 'tracked-entry-symlink') {
        Add-Failure "Expected tracked symlink to fail closed without following its target. Output: $($symlinkResult.Output.Trim())"
    }
}
finally {
    Write-SelfTestProgress -Phase 'final-cleanup'
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}

if ($failures.Count -gt 0) {
    Write-Host 'Private marker scan self-test failed:'
    foreach ($failure in $failures) {
        Write-Host "- $failure"
    }
    exit 1
}

Write-SelfTestProgress -Phase 'complete'
Write-Host 'Private marker scan self-test passed.'
exit 0
