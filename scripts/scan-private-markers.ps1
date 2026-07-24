[CmdletBinding()]
param(
    [string]$Path = '',
    [ValidateRange(1, 60)]
    [int]$GitCommandTimeoutSeconds = 15
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

# user-controlled path の解決失敗をPowerShell標準error framingへ流すと、
# raw path内の改行・bidi・zero-width文字がterminal診断を偽装できる。
# 生例外を一切表示せず、固定codeだけでfail closedにする。
try {
    $root = (
        Resolve-Path `
            -LiteralPath $Path `
            -ErrorAction Stop
    ).Path
}
catch {
    [byte[]]$rootFailureBytes = [System.Text.Encoding]::UTF8.GetBytes(
        'Private marker scan aborted: scan-root-resolution-failed' +
        [char]10)
    $rootFailureOutput = [Console]::OpenStandardOutput()
    try {
        $rootFailureOutput.Write(
            $rootFailureBytes,
            0,
            $rootFailureBytes.Length)
        $rootFailureOutput.Flush()
    }
    finally {
        $rootFailureOutput.Dispose()
    }
    exit 1
}
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
$maxLocalMarkerBytes = 64 * 1024
$maxLocalMarkerCount = 100
$maxLocalMarkerCharacters = 1024

function Add-LocalMarker {
    param([string]$Marker)

    $trimmed = $Marker.Trim()
    # Windows PowerShell 5.1 の Set-Content -Encoding UTF8 は BOM を付ける。
    # strict decode 後の先頭 U+FEFF は marker 本体に含めず互換に扱う。
    if ($trimmed.StartsWith([string][char]0xFEFF)) {
        $trimmed = $trimmed.Substring(1).Trim()
    }
    if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) {
        return
    }
    if ($trimmed.Length -gt $maxLocalMarkerCharacters) {
        throw 'local-marker-character-limit'
    }
    if ($script:localMarkerIndex -ge $maxLocalMarkerCount) {
        throw 'local-marker-count-limit'
    }

    $script:localMarkerIndex++
    Add-ScanRule -Name "local-private-marker-$script:localMarkerIndex" -Pattern $trimmed -Kind 'literal'
}

function Test-IsRegularFileSystemItem {
    param([System.IO.FileSystemInfo]$Item)

    if ($Item.PSIsContainer -or
        (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
        return $false
    }
    if (-not $script:isWindowsRuntime) {
        $unixModeProperty = $Item.PSObject.Properties['UnixMode']
        if ($null -eq $unixModeProperty -or
            -not ([string]$unixModeProperty.Value).StartsWith('-')) {
            return $false
        }
    }
    return $true
}

$githubUrlPattern = 'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?'
$findings = New-Object System.Collections.Generic.List[object]
$maxFindingCount = 1000
$maxFindingsPerLine = 32
$maxFindingsPerFile = 256
$maxDiagnosticFieldCharacters = 1024
$maxFindingOutputBytes = 64 * 1024
$maxTextLineCount = 100000
$scannedTextLineCount = 0

# Limit scanning to text files to avoid binary noise and expensive regex work.
# Extensionless text files such as LICENSE are still allowed.
$textExtensions = @(
    '.md', '.markdown', '.txt', '.ps1', '.psm1', '.psd1', '.yml', '.yaml',
    '.json', '.jsonc', '.toml', '.ini', '.cfg', '.conf', '.xml', '.csv',
    '.sh', '.bash', '.bat', '.cmd', '.py', '.js', '.ts', '.css', '.html',
    '.htm', '.editorconfig', '.gitattributes', '.gitignore', '.env', '.pem',
    '.key', '.tfvars', '.crt', '.asc'
)
$textExtensionSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]$textExtensions, [System.StringComparer]::OrdinalIgnoreCase)

function Test-IsTextFile {
    param([string]$FullPath)

    $fileName = [System.IO.Path]::GetFileName($FullPath)
    # dotenv variant と拡張子風の設定名は Path.GetExtension だけでは拾えない。
    if ($fileName -imatch '^\.env(?:\..+)?$' -or
        $fileName -iin @('.envrc', '.npmrc', '.pypirc', '.netrc')) {
        return $true
    }
    $extension = [System.IO.Path]::GetExtension($FullPath)
    if ([string]::IsNullOrEmpty($extension)) {
        # Treat extensionless files as text.
        return $true
    }
    return $textExtensionSet.Contains($extension)
}

function ConvertTo-NativeArgument {
    param([AllowEmptyString()][string]$Argument)

    if ($Argument.Length -eq 0) {
        return '""'
    }
    if ($Argument -notmatch '[\s"]') {
        return $Argument
    }

    # Windows PowerShell 5.1 does not expose ProcessStartInfo.ArgumentList.
    # Quote one argument with the Windows command-line backslash/quote rules.
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

function Initialize-ScannerProcessContainment {
    if (-not $script:isWindowsRuntime) {
        return
    }

    # Windows では CreateProcessW(CREATE_SUSPENDED) で child を止めたまま作り、
    # kill-on-close Job へ assign してからだけ resume する。Process.Start 後の
    # assign では immediate-spawn descendant が Job 外へ逃げる race が残る。
    $jobSource = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public sealed class PrivateMarkerScannerProcess : IDisposable
{
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const int JobObjectExtendedLimitInformationClass = 9;
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint ExtendedStartupInfoPresent = 0x00080000;
    private const uint CreateNoWindow = 0x08000000;
    private const uint StartfUseStdHandles = 0x00000100;
    private const uint HandleFlagInherit = 0x00000001;
    private const uint ResumeFailed = 0xFFFFFFFF;
    private const uint WaitObject0 = 0x00000000;
    private static readonly IntPtr ProcThreadAttributeHandleList =
        new IntPtr(0x00020002);

    private IntPtr jobHandle;
    private IntPtr processHandle;
    private bool disposed;

    public Stream StandardInput { get; private set; }
    public Stream StandardOutput { get; private set; }
    public Stream StandardError { get; private set; }

    private PrivateMarkerScannerProcess(
        IntPtr childProcess,
        Stream standardInput,
        Stream standardOutput,
        Stream standardError,
        IntPtr job)
    {
        processHandle = childProcess;
        StandardInput = standardInput;
        StandardOutput = standardOutput;
        StandardError = standardError;
        jobHandle = job;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
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

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreatePipe(
        out IntPtr readPipe,
        out IntPtr writePipe,
        ref SECURITY_ATTRIBUTES pipeAttributes,
        int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetHandleInformation(
        IntPtr handle,
        uint mask,
        uint flags);

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
        ref STARTUPINFOEX startupInfo,
        out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(
        IntPtr attributeList,
        int attributeCount,
        int flags,
        ref IntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(
        IntPtr attributeList,
        uint flags,
        IntPtr attribute,
        IntPtr value,
        IntPtr size,
        IntPtr previousValue,
        IntPtr returnSize);

    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(
        IntPtr attributeList);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr jobAttributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(
        IntPtr job,
        int informationClass,
        ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(
        IntPtr process,
        out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    private static string Quote(string value)
    {
        if (value.Length == 0)
            return "\"\"";
        if (value.IndexOfAny(new char[] { ' ', '\t', '"' }) < 0)
            return value;

        StringBuilder result = new StringBuilder("\"");
        int slashes = 0;
        foreach (char character in value)
        {
            if (character == '\\')
            {
                slashes++;
                continue;
            }
            if (character == '"')
            {
                result.Append('\\', (slashes * 2) + 1);
                result.Append('"');
                slashes = 0;
                continue;
            }
            result.Append('\\', slashes);
            slashes = 0;
            result.Append(character);
        }
        result.Append('\\', slashes * 2);
        result.Append('"');
        return result.ToString();
    }

    private static StringBuilder BuildCommandLine(
        string filePath,
        string[] arguments)
    {
        StringBuilder commandLine = new StringBuilder(Quote(filePath));
        foreach (string argument in arguments)
        {
            commandLine.Append(' ');
            commandLine.Append(Quote(argument ?? String.Empty));
        }
        return commandLine;
    }

    private static IntPtr BuildEnvironmentBlock(IDictionary environment)
    {
        List<string> entries = new List<string>();
        foreach (DictionaryEntry entry in environment)
        {
            string name = Convert.ToString(entry.Key);
            string value = Convert.ToString(entry.Value) ?? String.Empty;
            if (String.IsNullOrEmpty(name) ||
                name.IndexOf('=') >= 0 ||
                name.IndexOf('\0') >= 0 ||
                value.IndexOf('\0') >= 0)
            {
                throw new ArgumentException("Invalid child environment entry.");
            }
            entries.Add(name + "=" + value);
        }
        entries.Sort(StringComparer.OrdinalIgnoreCase);
        string block = String.Join("\0", entries.ToArray()) + "\0\0";
        return Marshal.StringToHGlobalUni(block);
    }

    private static IntPtr CreateKillOnCloseJob()
    {
        IntPtr job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero)
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "CreateJobObject failed.");

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION information =
            new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        information.BasicLimitInformation.LimitFlags =
            JobObjectLimitKillOnJobClose;
        if (!SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformationClass,
                ref information,
                (uint)Marshal.SizeOf(
                    typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))))
        {
            int error = Marshal.GetLastWin32Error();
            CloseHandle(job);
            throw new Win32Exception(error, "SetInformationJobObject failed.");
        }
        return job;
    }

    private static void CloseOwnedHandle(ref IntPtr handle)
    {
        if (handle != IntPtr.Zero)
        {
            CloseHandle(handle);
            handle = IntPtr.Zero;
        }
    }

    public static PrivateMarkerScannerProcess StartContained(
        string filePath,
        string[] arguments,
        IDictionary environment)
    {
        IntPtr stdinRead = IntPtr.Zero;
        IntPtr stdinWrite = IntPtr.Zero;
        IntPtr stdoutRead = IntPtr.Zero;
        IntPtr stdoutWrite = IntPtr.Zero;
        IntPtr stderrRead = IntPtr.Zero;
        IntPtr stderrWrite = IntPtr.Zero;
        IntPtr environmentBlock = IntPtr.Zero;
        IntPtr attributeList = IntPtr.Zero;
        IntPtr inheritedHandleList = IntPtr.Zero;
        IntPtr job = IntPtr.Zero;
        PROCESS_INFORMATION processInformation = new PROCESS_INFORMATION();
        SafeFileHandle stdinSafeHandle = null;
        SafeFileHandle stdoutSafeHandle = null;
        SafeFileHandle stderrSafeHandle = null;
        FileStream stdout = null;
        FileStream stderr = null;
        FileStream stdin = null;
        bool processCreated = false;
        bool processAssigned = false;
        bool attributeListInitialized = false;
        try
        {
            SECURITY_ATTRIBUTES attributes = new SECURITY_ATTRIBUTES();
            attributes.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            attributes.bInheritHandle = true;

            if (!CreatePipe(out stdinRead, out stdinWrite, ref attributes, 0) ||
                !CreatePipe(out stdoutRead, out stdoutWrite, ref attributes, 0) ||
                !CreatePipe(out stderrRead, out stderrWrite, ref attributes, 0))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "CreatePipe failed.");
            if (!SetHandleInformation(stdinWrite, HandleFlagInherit, 0) ||
                !SetHandleInformation(stdoutRead, HandleFlagInherit, 0) ||
                !SetHandleInformation(stderrRead, HandleFlagInherit, 0))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "SetHandleInformation failed.");

            // bInheritHandles=true でも child stdio 以外を渡さない。親側の
            // unrelated inheritable handle が Git やその孫へ漏れるのを防ぐ。
            IntPtr attributeListSize = IntPtr.Zero;
            InitializeProcThreadAttributeList(
                IntPtr.Zero, 1, 0, ref attributeListSize);
            if (attributeListSize == IntPtr.Zero)
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "InitializeProcThreadAttributeList size query failed.");
            attributeList = Marshal.AllocHGlobal(attributeListSize);
            if (!InitializeProcThreadAttributeList(
                    attributeList, 1, 0, ref attributeListSize))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "InitializeProcThreadAttributeList failed.");
            attributeListInitialized = true;

            inheritedHandleList = Marshal.AllocHGlobal(IntPtr.Size * 3);
            Marshal.WriteIntPtr(inheritedHandleList, 0, stdinRead);
            Marshal.WriteIntPtr(inheritedHandleList, IntPtr.Size, stdoutWrite);
            Marshal.WriteIntPtr(
                inheritedHandleList, IntPtr.Size * 2, stderrWrite);
            if (!UpdateProcThreadAttribute(
                    attributeList,
                    0,
                    ProcThreadAttributeHandleList,
                    inheritedHandleList,
                    new IntPtr(IntPtr.Size * 3),
                    IntPtr.Zero,
                    IntPtr.Zero))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "UpdateProcThreadAttribute failed.");

            STARTUPINFOEX startupInfo = new STARTUPINFOEX();
            startupInfo.StartupInfo.cb =
                Marshal.SizeOf(typeof(STARTUPINFOEX));
            startupInfo.StartupInfo.dwFlags = StartfUseStdHandles;
            startupInfo.StartupInfo.hStdInput = stdinRead;
            startupInfo.StartupInfo.hStdOutput = stdoutWrite;
            startupInfo.StartupInfo.hStdError = stderrWrite;
            startupInfo.lpAttributeList = attributeList;

            job = CreateKillOnCloseJob();
            environmentBlock = BuildEnvironmentBlock(environment);
            if (!CreateProcessW(
                    filePath,
                    BuildCommandLine(filePath, arguments),
                    IntPtr.Zero,
                    IntPtr.Zero,
                    true,
                    CreateSuspended |
                        CreateUnicodeEnvironment |
                        CreateNoWindow |
                        ExtendedStartupInfoPresent,
                    environmentBlock,
                    null,
                    ref startupInfo,
                    out processInformation))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "CreateProcessW failed.");
            }
            processCreated = true;

            if (!AssignProcessToJobObject(job, processInformation.hProcess))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "AssignProcessToJobObject failed.");
            processAssigned = true;

            stdinSafeHandle = new SafeFileHandle(stdinWrite, true);
            stdinWrite = IntPtr.Zero;
            stdoutSafeHandle = new SafeFileHandle(stdoutRead, true);
            stdoutRead = IntPtr.Zero;
            stderrSafeHandle = new SafeFileHandle(stderrRead, true);
            stderrRead = IntPtr.Zero;
            stdin = new FileStream(
                stdinSafeHandle, FileAccess.Write, 8192, false);
            stdinSafeHandle = null;
            stdout = new FileStream(
                stdoutSafeHandle, FileAccess.Read, 8192, false);
            stdoutSafeHandle = null;
            stderr = new FileStream(
                stderrSafeHandle, FileAccess.Read, 8192, false);
            stderrSafeHandle = null;

            // Child pipe ends must be closed in the parent before resume.
            CloseOwnedHandle(ref stdinRead);
            CloseOwnedHandle(ref stdoutWrite);
            CloseOwnedHandle(ref stderrWrite);

            if (ResumeThread(processInformation.hThread) == ResumeFailed)
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "ResumeThread failed.");
            CloseOwnedHandle(ref processInformation.hThread);

            PrivateMarkerScannerProcess result =
                new PrivateMarkerScannerProcess(
                    processInformation.hProcess,
                    stdin,
                    stdout,
                    stderr,
                    job);
            processInformation.hProcess = IntPtr.Zero;
            stdin = null;
            stdout = null;
            stderr = null;
            job = IntPtr.Zero;
            return result;
        }
        catch
        {
            if (processCreated)
            {
                if (processAssigned && job != IntPtr.Zero)
                    CloseOwnedHandle(ref job);
                else
                    TerminateProcess(processInformation.hProcess, 1);
                WaitForSingleObject(processInformation.hProcess, 5000);
            }
            throw;
        }
        finally
        {
            if (environmentBlock != IntPtr.Zero)
                Marshal.FreeHGlobal(environmentBlock);
            if (attributeListInitialized)
                DeleteProcThreadAttributeList(attributeList);
            if (attributeList != IntPtr.Zero)
                Marshal.FreeHGlobal(attributeList);
            if (inheritedHandleList != IntPtr.Zero)
                Marshal.FreeHGlobal(inheritedHandleList);
            CloseOwnedHandle(ref stdinRead);
            CloseOwnedHandle(ref stdinWrite);
            CloseOwnedHandle(ref stdoutRead);
            CloseOwnedHandle(ref stdoutWrite);
            CloseOwnedHandle(ref stderrRead);
            CloseOwnedHandle(ref stderrWrite);
            CloseOwnedHandle(ref processInformation.hThread);
            CloseOwnedHandle(ref processInformation.hProcess);
            if (job != IntPtr.Zero)
                CloseOwnedHandle(ref job);
            if (stdout != null)
                stdout.Dispose();
            if (stderr != null)
                stderr.Dispose();
            if (stdin != null)
                stdin.Dispose();
            if (stdinSafeHandle != null)
                stdinSafeHandle.Dispose();
            if (stdoutSafeHandle != null)
                stdoutSafeHandle.Dispose();
            if (stderrSafeHandle != null)
                stderrSafeHandle.Dispose();
        }
    }

    public bool WaitForExit(int milliseconds)
    {
        return WaitForSingleObject(processHandle, (uint)milliseconds) ==
            WaitObject0;
    }

    public bool HasExited
    {
        get { return WaitForSingleObject(processHandle, 0) == WaitObject0; }
    }

    public int ExitCode
    {
        get
        {
            uint exitCode;
            if (!GetExitCodeProcess(processHandle, out exitCode))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return unchecked((int)exitCode);
        }
    }

    public void CloseJob()
    {
        if (jobHandle == IntPtr.Zero)
            return;
        IntPtr handle = jobHandle;
        jobHandle = IntPtr.Zero;
        if (!CloseHandle(handle))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    public void Dispose()
    {
        if (disposed)
            return;
        disposed = true;
        try
        {
            CloseJob();
        }
        finally
        {
            try
            {
                StandardInput.Dispose();
                StandardOutput.Dispose();
                StandardError.Dispose();
            }
            finally
            {
                CloseOwnedHandle(ref processHandle);
            }
        }
    }
}
'@

    try {
        # wrapper integration test だけが使う fault injection。実Gitを示す
        # companion 値も必要にし、通常環境では分岐を有効にしない。
        if ($env:SCANNER_TEST_FORCE_CONTAINMENT_FAILURE -eq '1' -and
            -not [string]::IsNullOrEmpty($env:SCANNER_TEST_REAL_GIT)) {
            throw 'synthetic containment failure'
        }
        if (-not ('PrivateMarkerScannerProcess' -as [type])) {
            Add-Type -TypeDefinition $jobSource -Language CSharp -ErrorAction Stop |
                Out-Null
        }
    }
    catch {
        # atomic containment helper を確立できない環境では Git を起動しない。
        throw 'git-process-containment-unavailable'
    }
}

function Stop-ProcessTreeBounded {
    param([System.Diagnostics.Process]$Process)

    if ($Process.HasExited) {
        return
    }

    # PowerShell 7 / modern .NET can terminate a descendant tree directly.
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
        # Windows PowerShell 5.1 fallback. taskkill is also given a finite wait.
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

    # Windows PowerShell 5.1 is Windows-only. This is a defensive fallback for
    # an unusual runtime that lacks the modern recursive Kill overload.
    $Process.Kill()
}

function ConvertFrom-StrictUtf8 {
    param(
        [byte[]]$Bytes,
        [string]$Context
    )

    if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
        return ''
    }
    try {
        $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
        return $strictUtf8.GetString($Bytes)
    }
    catch {
        throw "Child process emitted invalid UTF-8 on $Context."
    }
}

function Complete-BoundedProcessStreams {
    param(
        [System.IO.Stream[]]$Streams,
        [System.Threading.Tasks.Task[]]$Tasks,
        [int]$WaitMilliseconds = 1000
    )

    # child tree 停止後も pipe を継承した descendant が残る場合がある。まず
    # EOF を有限時間待ち、残った parent endpoint を閉じてから task 完了を
    # もう一度有限時間で確認する。未完了 task を残したまま return しない。
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
            # fault/cancel も task 完了状態である。下の IsCompleted で判定する。
        }
    }

    $pending = @($Tasks | Where-Object {
        $null -ne $_ -and -not $_.IsCompleted
    })
    if ($pending.Count -gt 0) {
        foreach ($stream in $Streams) {
            if ($null -ne $stream) {
                $stream.Dispose()
            }
        }
        try {
            [void][System.Threading.Tasks.Task]::WaitAll(
                [System.Threading.Tasks.Task[]]$pending,
                $WaitMilliseconds)
        }
        catch {
            # endpoint close に伴う fault/cancel は許容するが、未完了は拒否する。
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
        [byte[]]$StandardInputBytes = @(),
        [int]$TimeoutSeconds = 15,
        [int]$MaxStandardOutputBytes = (4 * 1024 * 1024),
        [int]$MaxStandardErrorBytes = (1024 * 1024)
    )

    $process = $null
    $nativeChild = $null
    $stdinStream = $null
    $stdoutStream = $null
    $stderrStream = $null
    $stdoutBuffer = New-Object System.IO.MemoryStream
    $stderrBuffer = New-Object System.IO.MemoryStream
    $processStarted = $false
    $stdinTask = $null
    $stdoutTask = $null
    $stderrTask = $null
    try {
        if ($script:isWindowsRuntime) {
            try {
                $nativeChild = [PrivateMarkerScannerProcess]::StartContained(
                    $FilePath,
                    [string[]]$ArgumentList,
                    $Environment)
                $stdinStream = $nativeChild.StandardInput
                $stdoutStream = $nativeChild.StandardOutput
                $stderrStream = $nativeChild.StandardError
            }
            catch {
                throw 'git-child-process-containment-unavailable'
            }
        } else {
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
            $startInfo.RedirectStandardInput = $true
            $startInfo.RedirectStandardOutput = $true
            $startInfo.RedirectStandardError = $true
            $startInfo.EnvironmentVariables.Clear()
            foreach ($entry in $Environment.GetEnumerator()) {
                $startInfo.EnvironmentVariables[[string]$entry.Key] =
                    [string]$entry.Value
            }
            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $startInfo
            [void]$process.Start()
            $stdinStream = $process.StandardInput.BaseStream
            $stdoutStream = $process.StandardOutput.BaseStream
            $stderrStream = $process.StandardError.BaseStream
        }
        $processStarted = $true

        # stdin write と stdout/stderr read を同時に進め、batch input/output の
        # pipe backpressure で相互待ちしない。全taskが同じdeadlineを共有する。
        $stdinClosed = $StandardInputBytes.Length -eq 0
        if ($stdinClosed) {
            $stdinStream.Dispose()
        } else {
            $stdinTask = $stdinStream.WriteAsync(
                $StandardInputBytes, 0, $StandardInputBytes.Length)
        }
        $stdoutChunk = New-Object byte[] 8192
        $stderrChunk = New-Object byte[] 8192
        $stdoutTask = $stdoutStream.ReadAsync(
            $stdoutChunk, 0, $stdoutChunk.Length)
        $stderrTask = $stderrStream.ReadAsync(
            $stderrChunk, 0, $stderrChunk.Length)
        $stdoutClosed = $false
        $stderrClosed = $false
        $limitExceeded = ''
        $deadline = $TimeoutSeconds * 1000
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        while ((-not $stdinClosed -or -not $stdoutClosed -or
                -not $stderrClosed) -and
            [string]::IsNullOrEmpty($limitExceeded) -and
            $stopwatch.ElapsedMilliseconds -lt $deadline) {
            $pendingTasks = New-Object System.Collections.Generic.List[System.Threading.Tasks.Task]
            if (-not $stdoutClosed) {
                $pendingTasks.Add($stdoutTask)
            }
            if (-not $stderrClosed) {
                $pendingTasks.Add($stderrTask)
            }
            if (-not $stdinClosed) {
                $pendingTasks.Add($stdinTask)
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
                    $stdoutTask = $stdoutStream.ReadAsync(
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
                    $stderrTask = $stderrStream.ReadAsync(
                        $stderrChunk, 0, $stderrChunk.Length)
                }
            }

            if (-not $stdinClosed -and $stdinTask.IsCompleted) {
                try {
                    [void]$stdinTask.GetAwaiter().GetResult()
                }
                catch {
                    throw 'Child process stdin write failed.'
                }
                $stdinStream.Dispose()
                $stdinClosed = $true
            }
        }

        $remaining = [Math]::Max(
            0,
            $deadline - [int]$stopwatch.ElapsedMilliseconds)
        $streamsCompleted = $stdinClosed -and $stdoutClosed -and $stderrClosed
        $processExited = $false
        if ($streamsCompleted -and [string]::IsNullOrEmpty($limitExceeded)) {
            $processExited = if ($null -ne $nativeChild) {
                $nativeChild.WaitForExit($remaining)
            } else {
                $process.WaitForExit($remaining)
            }
        }
        $timedOut = (
            [string]::IsNullOrEmpty($limitExceeded) -and
            -not ($streamsCompleted -and $processExited))
        if ($timedOut -or -not [string]::IsNullOrEmpty($limitExceeded)) {
            if ($null -ne $nativeChild) {
                $nativeChild.CloseJob()
                if (-not $nativeChild.HasExited -and
                    -not $nativeChild.WaitForExit(5000)) {
                    throw 'Git child process did not exit after bounded tree termination.'
                }
            } elseif (-not $process.HasExited) {
                Stop-ProcessTreeBounded -Process $process
                if (-not $process.HasExited -and -not $process.WaitForExit(5000)) {
                    throw 'Git child process did not exit after bounded tree termination.'
                }
            }
            Complete-BoundedProcessStreams `
                -Streams @($stdinStream, $stdoutStream, $stderrStream) `
                -Tasks @($stdinTask, $stdoutTask, $stderrTask)
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
            } elseif ($null -ne $nativeChild) {
                $nativeChild.ExitCode
            } else {
                $process.ExitCode
            }
            StandardOutputBytes = $stdoutBytes
            StandardErrorBytes = $stderrBytes
            TimedOut = $timedOut
            OutputLimitExceeded = $limitExceeded
        }
    }
    catch {
        $originalFailure = $_
        $cleanupFailure = $null
        if ($processStarted) {
            try {
                if ($null -ne $nativeChild) {
                    $nativeChild.CloseJob()
                    if (-not $nativeChild.HasExited -and
                        -not $nativeChild.WaitForExit(5000)) {
                        throw 'Git child process did not exit after bounded tree termination.'
                    }
                } elseif (-not $process.HasExited) {
                    Stop-ProcessTreeBounded -Process $process
                    if (-not $process.HasExited -and -not $process.WaitForExit(5000)) {
                        throw 'Git child process did not exit after bounded tree termination.'
                    }
                }
                Complete-BoundedProcessStreams `
                    -Streams @($stdinStream, $stdoutStream, $stderrStream) `
                    -Tasks @($stdinTask, $stdoutTask, $stderrTask)
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
        if ($null -ne $nativeChild) {
            $nativeChild.Dispose()
        } elseif ($null -ne $process) {
            if ($null -ne $stdinStream) { $stdinStream.Dispose() }
            if ($null -ne $stdoutStream) { $stdoutStream.Dispose() }
            if ($null -ne $stderrStream) { $stderrStream.Dispose() }
            $process.Dispose()
        }
    }
}

function New-GitBatchInputBytes {
    param([System.Collections.Generic.List[object]]$Entries)

    # cat-file --batch へ object id だけを LF 区切りで渡す。OID は列挙時に
    # 40/64桁 hex として検証済みであり、最大100,000件でも入力は約6.5MiBに収まる。
    $builder = New-Object System.Text.StringBuilder
    foreach ($entry in $Entries) {
        [void]$builder.Append($entry.ObjectId)
        [void]$builder.Append([char]10)
    }
    return ,[System.Text.Encoding]::ASCII.GetBytes($builder.ToString())
}

function ConvertFrom-GitBatchOutput {
    param(
        [byte[]]$Bytes,
        [System.Collections.Generic.List[object]]$Entries,
        [long]$MaxBlobBytes
    )

    # protocol は "<oid> blob <size>\n<raw bytes>\n"。header だけを
    # printable ASCII として読み、blob 本体は UTF-8 変換前の raw bytes を保つ。
    $responses = New-Object System.Collections.Generic.List[object]
    $offset = 0
    foreach ($entry in $Entries) {
        $headerStart = $offset
        while ($offset -lt $Bytes.Length -and $Bytes[$offset] -ne 10) {
            if (($offset - $headerStart) -ge 128) {
                throw 'git-index-blob-read-failed'
            }
            if ($Bytes[$offset] -lt 32 -or $Bytes[$offset] -gt 126) {
                throw 'git-index-blob-read-failed'
            }
            $offset++
        }
        if ($offset -ge $Bytes.Length -or $offset -eq $headerStart) {
            throw 'git-index-blob-read-failed'
        }

        $header = [System.Text.Encoding]::ASCII.GetString(
            $Bytes,
            $headerStart,
            $offset - $headerStart)
        $offset++
        if ($header -match '^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64}) missing$') {
            throw 'git-index-blob-read-failed'
        }
        $headerMatch = [regex]::Match(
            $header,
            '^(?<Object>(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})) (?<Type>[a-z]+) (?<Size>[0-9]+)$')
        if (-not $headerMatch.Success -or
            $headerMatch.Groups['Type'].Value -cne 'blob' -or
            -not [string]::Equals(
                $headerMatch.Groups['Object'].Value,
                [string]$entry.ObjectId,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'git-index-blob-read-failed'
        }

        $blobSize = 0L
        if (-not [long]::TryParse(
                $headerMatch.Groups['Size'].Value,
                [Globalization.NumberStyles]::None,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$blobSize)) {
            throw 'git-index-blob-read-failed'
        }
        if ($blobSize -gt $MaxBlobBytes) {
            throw 'git-index-blob-size-limit'
        }
        $contentEnd = [long]$offset + $blobSize
        if ($contentEnd -ge $Bytes.Length -or
            $Bytes[[int]$contentEnd] -ne 10) {
            throw 'git-index-blob-read-failed'
        }

        $content = New-Object byte[] ([int]$blobSize)
        if ($blobSize -gt 0) {
            [System.Buffer]::BlockCopy(
                $Bytes,
                $offset,
                $content,
                0,
                [int]$blobSize)
        }
        $responses.Add($content) | Out-Null
        $offset = [int]$contentEnd + 1
    }

    # 件数分を読み切った後に余剰 response があれば、要求/応答対応を信頼しない。
    if ($offset -ne $Bytes.Length) {
        throw 'git-index-blob-read-failed'
    }
    return ,$responses
}

function ConvertFrom-GitIndexDebug {
    param([byte[]]$Bytes)

    # `ls-files --stage --debug -z` は各stage recordのNUL直後に固定5行の
    # stat/flags metadataを置く。recordを逐次復元し、flags全体はraw比較にも使う。
    $debugText = ConvertFrom-StrictUtf8 `
        -Bytes $Bytes `
        -Context 'Git index debug stdout'
    $stageBuilder = New-Object System.Text.StringBuilder
    $metadataPattern = (
        '\G  ctime: [0-9]+:[0-9]+\r?\n' +
        '  mtime: [0-9]+:[0-9]+\r?\n' +
        '  dev: [0-9]+\tino: [0-9]+\r?\n' +
        '  uid: [0-9]+\tgid: [0-9]+\r?\n' +
        '  size: -?[0-9]+\tflags: (?<Flags>[0-9a-fA-F]+)\r?\n')
    $metadataRegex = New-Object System.Text.RegularExpressions.Regex(
        $metadataPattern,
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
    $offset = 0
    $debugEntryCount = 0
    $hasIntentToAdd = $false
    while ($offset -lt $debugText.Length) {
        $nulIndex = $debugText.IndexOf([char]0, $offset)
        if ($nulIndex -lt 0 -or $nulIndex -eq $offset) {
            throw 'git-index-debug-malformed'
        }
        $debugEntryCount++
        if ($debugEntryCount -gt $maxTrackedEntries) {
            throw 'git-index-debug-entry-limit'
        }
        [void]$stageBuilder.Append(
            $debugText.Substring($offset, $nulIndex - $offset))
        [void]$stageBuilder.Append([char]0)
        $offset = $nulIndex + 1

        $metadataMatch = $metadataRegex.Match($debugText, $offset)
        if (-not $metadataMatch.Success -or
            $metadataMatch.Index -ne $offset) {
            throw 'git-index-debug-malformed'
        }
        $flags = 0L
        if (-not [long]::TryParse(
                $metadataMatch.Groups['Flags'].Value,
                [Globalization.NumberStyles]::HexNumber,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$flags)) {
            throw 'git-index-debug-malformed'
        }
        if (($flags -band 0x20000000L) -ne 0) {
            $hasIntentToAdd = $true
        }
        $offset = $metadataMatch.Index + $metadataMatch.Length
    }
    return [pscustomobject]@{
        StageBytes = [System.Text.Encoding]::UTF8.GetBytes(
            $stageBuilder.ToString())
        HasIntentToAdd = $hasIntentToAdd
    }
}

function New-SanitizedGitEnvironment {
    param(
        [string]$IsolationRoot,
        [string]$EmptyConfigPath
    )

    $environment = @{}
    $removedNames = @(
        'HOME',
        'USERPROFILE',
        'XDG_CONFIG_HOME',
        'SSH_ASKPASS',
        'GCM_INTERACTIVE',
        'GCM_GUI_PROMPT'
    )
    foreach ($entry in [Environment]::GetEnvironmentVariables('Process').GetEnumerator()) {
        $name = [string]$entry.Key
        # 未知の将来変数も含め、ambient GIT_* は allowlist 方式で全て落とす。
        if ($name -match '^GIT_' -or $removedNames -contains $name) {
            continue
        }
        $environment[$name] = [string]$entry.Value
    }

    # machine/global/system config、prompt、trace、optional lock の境界を固定する。
    $environment['HOME'] = $IsolationRoot
    $environment['USERPROFILE'] = $IsolationRoot
    $environment['XDG_CONFIG_HOME'] = $IsolationRoot
    $environment['GIT_ATTR_NOSYSTEM'] = '1'
    $environment['GIT_CONFIG_GLOBAL'] = $EmptyConfigPath
    $environment['GIT_CONFIG_NOSYSTEM'] = '1'
    $environment['GIT_CONFIG_SYSTEM'] = $EmptyConfigPath
    $environment['GIT_NO_LAZY_FETCH'] = '1'
    $environment['GIT_NO_REPLACE_OBJECTS'] = '1'
    $environment['GIT_OPTIONAL_LOCKS'] = '0'
    $environment['GIT_TERMINAL_PROMPT'] = '0'
    $environment['GIT_ASKPASS'] = ''
    $environment['SSH_ASKPASS'] = ''
    $environment['GCM_INTERACTIVE'] = 'Never'
    $environment['GCM_GUI_PROMPT'] = '0'
    return $environment
}

function Get-NormalizedPath {
    param([string]$InputPath)

    $resolved = (Resolve-Path -LiteralPath $InputPath).Path
    $fullPath = [System.IO.Path]::GetFullPath($resolved)
    $pathRoot = [System.IO.Path]::GetPathRoot($fullPath)
    if ([string]::Equals($fullPath, $pathRoot, [StringComparison]::OrdinalIgnoreCase)) {
        return $pathRoot
    }
    return $fullPath.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar)
}

function Test-HasGitControlEntryAtOrAbove {
    param([string]$StartPath)

    # healthy Git probe なら root mismatch を直接拒否できる。一方で probe 自体が
    # 失敗した場合も、祖先の .git を見落として non-Git fallback へ開かない。
    $cursor = Get-NormalizedPath -InputPath $StartPath
    while ($true) {
        $gitEntries = @(Get-ChildItem -LiteralPath $cursor -Force | Where-Object {
            $_.Name -ieq '.git'
        })
        if ($gitEntries.Count -gt 0) {
            return $true
        }

        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrEmpty($parent) -or
            [string]::Equals(
                $parent,
                $cursor,
                [StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
        $cursor = $parent
    }
}

function Test-PathHasReparsePoint {
    param(
        [string]$FullPath,
        [string]$BoundaryRoot,
        [StringComparison]$Comparison
    )

    $cursor = $FullPath
    while ($true) {
        $item = Get-Item -LiteralPath $cursor -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            return $true
        }
        if ([string]::Equals($cursor, $BoundaryRoot, $Comparison)) {
            return $false
        }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrEmpty($parent) -or
            -not $parent.StartsWith($BoundaryRoot, $Comparison)) {
            throw 'tracked-path-parent-escape'
        }
        $cursor = $parent
    }
}

function ConvertTo-SafeDiagnosticText {
    param([AllowEmptyString()][string]$Value)

    # path 由来の bidi override / zero-width Format / line separator を
    # console 制御へ渡さず、code point escape へ変換する。長大pathも出力前に止める。
    $builder = New-Object System.Text.StringBuilder
    $index = 0
    while ($index -lt $Value.Length) {
        $width = 1
        if ([char]::IsHighSurrogate($Value[$index]) -and
            ($index + 1) -lt $Value.Length -and
            [char]::IsLowSurrogate($Value[$index + 1])) {
            $width = 2
        }
        $category = [Globalization.CharUnicodeInfo]::GetUnicodeCategory(
            $Value,
            $index)
        $unsafe = $category -in @(
            [Globalization.UnicodeCategory]::Control,
            [Globalization.UnicodeCategory]::Format,
            [Globalization.UnicodeCategory]::LineSeparator,
            [Globalization.UnicodeCategory]::ParagraphSeparator,
            [Globalization.UnicodeCategory]::Surrogate)
        if ($unsafe) {
            $codePoint = if ($width -eq 2) {
                [char]::ConvertToUtf32(
                    $Value[$index],
                    $Value[$index + 1])
            } else {
                [int]$Value[$index]
            }
            if ($codePoint -le 0xffff) {
                [void]$builder.AppendFormat('\u{0:X4}', $codePoint)
            } else {
                [void]$builder.AppendFormat('\U{0:X8}', $codePoint)
            }
        } else {
            [void]$builder.Append($Value.Substring($index, $width))
        }
        if ($builder.Length -gt $maxDiagnosticFieldCharacters) {
            throw 'scan-diagnostic-field-limit'
        }
        $index += $width
    }
    return $builder.ToString()
}

function Add-ScanFinding {
    param(
        [string]$File,
        [string]$Source,
        [int]$Line,
        [string]$Rule,
        [hashtable]$Counters
    )

    # 同一行・同一file・scan全体の3段階で finding 増幅を止める。
    # 上限到達時は marker 値や local path を含めず generic code だけを返す。
    if ($Counters.Line -ge $maxFindingsPerLine) {
        throw 'scan-line-finding-limit'
    }
    if ($Counters.File -ge $maxFindingsPerFile) {
        throw 'scan-file-finding-limit'
    }
    if ($findings.Count -ge $maxFindingCount) {
        throw 'scan-finding-limit'
    }
    $findings.Add([pscustomobject]@{
        File = ConvertTo-SafeDiagnosticText -Value $File
        Source = ConvertTo-SafeDiagnosticText -Value $Source
        Line = $Line
        Rule = ConvertTo-SafeDiagnosticText -Value $Rule
        Match = '<redacted>'
    }) | Out-Null
    $Counters.Line++
    $Counters.File++
}

function Scan-TextBytes {
    param(
        [byte[]]$Bytes,
        [string]$Context,
        [string]$Relative,
        [string]$Source
    )

    # -split は短行の反復を数百万 string へ増幅し得るため、1行ずつ読む。
    # raw bytes は呼出側の per-file/total cap 済みで、line/finding も全体上限を持つ。
    $text = ConvertFrom-StrictUtf8 -Bytes $Bytes -Context $Context
    $reader = New-Object System.IO.StringReader($text)
    try {
        $lineNumber = 0
        $findingCounters = @{
            File = 0
            Line = 0
        }
        while ($null -ne ($line = $reader.ReadLine())) {
            $lineNumber++
            $findingCounters.Line = 0
            $script:scannedTextLineCount++
            if ($script:scannedTextLineCount -gt $maxTextLineCount) {
                throw 'scan-text-line-limit'
            }

            $urlMatch = [regex]::Match($line, $githubUrlPattern)
            while ($urlMatch.Success) {
                if ($urlMatch.Value -notmatch $allowedRepoUrlPattern) {
                    Add-ScanFinding `
                        -File $Relative `
                        -Source $Source `
                        -Line $lineNumber `
                        -Rule 'non-allowlisted-github-repo-url' `
                        -Counters $findingCounters
                }
                $urlMatch = $urlMatch.NextMatch()
            }

            foreach ($rule in $rules) {
                $matched = $false
                if ($rule.Kind -eq 'literal') {
                    $matched = $line.Contains($rule.Pattern)
                } elseif ([string]::IsNullOrEmpty($rule.Allowlist)) {
                    $matched = [regex]::IsMatch($line, $rule.Pattern, 'IgnoreCase')
                } else {
                    # allowlist 対象は Match/NextMatch で逐次評価し、MatchCollection
                    # 自体が短い反復入力を全件保持しないようにする。
                    $ruleMatch = [regex]::Match($line, $rule.Pattern, 'IgnoreCase')
                    while ($ruleMatch.Success) {
                        if (-not [regex]::IsMatch($ruleMatch.Value, $rule.Allowlist)) {
                            $matched = $true
                            break
                        }
                        $ruleMatch = $ruleMatch.NextMatch()
                    }
                }

                if ($matched) {
                    Add-ScanFinding `
                        -File $Relative `
                        -Source $Source `
                        -Line $lineNumber `
                        -Rule $rule.Name `
                        -Counters $findingCounters
                }
            }
        }
    }
    finally {
        $reader.Dispose()
    }
}

function Read-BoundedFileSnapshot {
    param(
        [string]$FullPath,
        [long]$MaxBytes,
        [string]$SizeFailureCode = 'tracked-worktree-file-size-limit'
    )

    $buffer = New-Object System.IO.MemoryStream
    $stream = [System.IO.File]::Open(
        $FullPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    try {
        $chunk = New-Object byte[] 8192
        while (($count = $stream.Read($chunk, 0, $chunk.Length)) -gt 0) {
            if (($buffer.Length + $count) -gt $MaxBytes) {
                throw $SizeFailureCode
            }
            $buffer.Write($chunk, 0, $count)
        }
        [byte[]]$snapshot = $buffer.ToArray()
        return ,$snapshot
    }
    finally {
        $stream.Dispose()
        $buffer.Dispose()
    }
}

function Read-TrackedWorktreeBytes {
    param(
        [string]$FullPath,
        [string]$BoundaryRoot,
        [StringComparison]$Comparison,
        [long]$MaxBytes,
        [string]$SizeFailureCode = 'tracked-worktree-file-size-limit'
    )

    # FileShare.Read だけで開き、Windows では scan 中の write/delete を拒否する。
    # POSIX の rename/同サイズ・同mtime差替えにも備え、bounded snapshot を2回
    # 取得して bytes と metadata の両方が安定している場合だけ採用する。
    $before = Get-Item -LiteralPath $FullPath -Force
    if (-not (Test-IsRegularFileSystemItem -Item $before) -or
        (Test-PathHasReparsePoint `
            -FullPath $FullPath `
            -BoundaryRoot $BoundaryRoot `
            -Comparison $Comparison)) {
        throw 'tracked-worktree-reparse-point'
    }
    if ($before.Length -gt $MaxBytes) {
        throw $SizeFailureCode
    }

    [byte[]]$firstBytes = Read-BoundedFileSnapshot `
        -FullPath $FullPath `
        -MaxBytes $MaxBytes `
        -SizeFailureCode $SizeFailureCode
    $middle = Get-Item -LiteralPath $FullPath -Force
    if (-not (Test-IsRegularFileSystemItem -Item $middle) -or
        (Test-PathHasReparsePoint `
            -FullPath $FullPath `
            -BoundaryRoot $BoundaryRoot `
            -Comparison $Comparison) -or
        $before.Length -ne $middle.Length -or
        $before.CreationTimeUtc -ne $middle.CreationTimeUtc -or
        $before.LastWriteTimeUtc -ne $middle.LastWriteTimeUtc -or
        $before.Attributes -ne $middle.Attributes -or
        $middle.Length -ne $firstBytes.Length) {
        throw 'tracked-worktree-changed-during-scan'
    }

    [byte[]]$secondBytes = Read-BoundedFileSnapshot `
        -FullPath $FullPath `
        -MaxBytes $MaxBytes `
        -SizeFailureCode $SizeFailureCode
    $after = Get-Item -LiteralPath $FullPath -Force
    $sameBytes = [System.Collections.StructuralComparisons]::StructuralEqualityComparer.Equals(
        $firstBytes,
        $secondBytes)
    if (-not $sameBytes -or
        -not (Test-IsRegularFileSystemItem -Item $after) -or
        (Test-PathHasReparsePoint `
            -FullPath $FullPath `
            -BoundaryRoot $BoundaryRoot `
            -Comparison $Comparison) -or
        $middle.Length -ne $after.Length -or
        $middle.CreationTimeUtc -ne $after.CreationTimeUtc -or
        $middle.LastWriteTimeUtc -ne $after.LastWriteTimeUtc -or
        $middle.Attributes -ne $after.Attributes -or
        $after.Length -ne $secondBytes.Length) {
        throw 'tracked-worktree-changed-during-scan'
    }
    return ,$secondBytes
}

# local marker source も regular-file/byte/line/rule 上限内でだけ取り込む。
# ここまで helper 定義を完了してから読むことで、通常 scan と同じ bounded reader を使う。
try {
    $localMarkerEntries = @(Get-ChildItem -LiteralPath $root -Force | Where-Object {
        $_.Name -ieq '.private-markers.local'
    })
    if ($localMarkerEntries.Count -gt 1) {
        throw 'local-marker-ambiguous-entry'
    }
    if ($localMarkerEntries.Count -eq 1) {
        $localMarkerItem = $localMarkerEntries[0]
        if (-not (Test-IsRegularFileSystemItem -Item $localMarkerItem)) {
            throw 'local-marker-not-regular-file'
        }
        $localMarkerRoot = Get-NormalizedPath -InputPath $root
        $localMarkerComparison = if ($script:isWindowsRuntime) {
            [StringComparison]::OrdinalIgnoreCase
        } else {
            [StringComparison]::Ordinal
        }
        [byte[]]$localMarkerBytes = Read-TrackedWorktreeBytes `
            -FullPath $localMarkerItem.FullName `
            -BoundaryRoot $localMarkerRoot `
            -Comparison $localMarkerComparison `
            -MaxBytes $maxLocalMarkerBytes `
            -SizeFailureCode 'local-marker-byte-limit'
        $localMarkerText = ConvertFrom-StrictUtf8 `
            -Bytes $localMarkerBytes `
            -Context 'local marker file'
        $localMarkerReader = New-Object System.IO.StringReader($localMarkerText)
        try {
            while ($null -ne ($localMarkerLine = $localMarkerReader.ReadLine())) {
                Add-LocalMarker -Marker $localMarkerLine
            }
        }
        finally {
            $localMarkerReader.Dispose()
        }
    }

    $environmentMarkers = [Environment]::GetEnvironmentVariable(
        'WINDOWS_GIT_STALE_LOCK_RECOVERY_PRIVATE_MARKERS')
    if (-not [string]::IsNullOrWhiteSpace($environmentMarkers)) {
        if ([System.Text.Encoding]::UTF8.GetByteCount($environmentMarkers) -gt
            $maxLocalMarkerBytes) {
            throw 'local-marker-environment-byte-limit'
        }
        $environmentMarkerReader = New-Object System.IO.StringReader($environmentMarkers)
        try {
            while ($null -ne ($environmentMarkerLine = $environmentMarkerReader.ReadLine())) {
                Add-LocalMarker -Marker $environmentMarkerLine
            }
        }
        finally {
            $environmentMarkerReader.Dispose()
        }
    }
}
catch {
    $localMarkerFailure = [string]$_.Exception.Message
    if ($localMarkerFailure -notmatch '^local-marker-') {
        $localMarkerFailure = 'local-marker-read-failed'
    }
    Write-Host "Private marker scan aborted: $localMarkerFailure"
    exit 1
}

# Git repo は index blob と tracked worktree の両方を scan する。非 Git
# fixture だけが従来の working-tree fallback を使える。
$scanMode = 'working-tree'
$gitFailureCode = $null
$maxTrackedEntries = 100000
$maxTextEntries = 8192
$maxTextFileBytes = 4 * 1024 * 1024
$maxTotalTextBytes = 64 * 1024 * 1024
$maxGitIndexDebugBytes = 16 * 1024 * 1024
$trackedEntryCount = 0
$totalTextBytes = 0L
try {
    $gitControlDetectedAtOrAbove = Test-HasGitControlEntryAtOrAbove `
        -StartPath $root
}
catch {
    Write-Host 'Private marker scan aborted: git-control-detection-failed'
    exit 1
}
$gitExe = Get-Command git -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($null -eq $gitExe -and $gitControlDetectedAtOrAbove) {
    $gitFailureCode = 'git-executable-missing'
} elseif ($null -ne $gitExe) {
    $gitIsolationRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        'windows-git-stale-lock-recovery-scan-' + [System.Guid]::NewGuid().ToString('N'))
    try {
        Initialize-ScannerProcessContainment
        New-Item -ItemType Directory -Path $gitIsolationRoot | Out-Null
        $emptyConfig = Join-Path $gitIsolationRoot 'empty.gitconfig'
        $emptyAttributes = Join-Path $gitIsolationRoot 'empty.attributes'
        $emptyExcludes = Join-Path $gitIsolationRoot 'empty.excludes'
        $emptyHooks = Join-Path $gitIsolationRoot 'hooks'
        $emptyTemplate = Join-Path $gitIsolationRoot 'template'
        [System.IO.File]::WriteAllText($emptyConfig, '')
        [System.IO.File]::WriteAllText($emptyAttributes, '')
        [System.IO.File]::WriteAllText($emptyExcludes, '')
        New-Item -ItemType Directory -Path $emptyHooks, $emptyTemplate | Out-Null

        $gitEnvironment = New-SanitizedGitEnvironment `
            -IsolationRoot $gitIsolationRoot `
            -EmptyConfigPath $emptyConfig
        $safeConfigArguments = @(
            '--no-replace-objects',
            '-c', "core.hooksPath=$emptyHooks",
            '-c', "core.attributesFile=$emptyAttributes",
            '-c', "core.excludesFile=$emptyExcludes",
            '-c', "init.templateDir=$emptyTemplate",
            '-c', 'core.fsmonitor=false',
            '-c', 'credential.helper=',
            '-c', 'core.askPass='
        )

        # まず正規 repo root / git dir を取得し、要求された root と一致する場合だけ使う。
        $probeResult = Invoke-BoundedProcess `
            -FilePath $gitExe.Source `
            -ArgumentList (@('-C', $root) + $safeConfigArguments + @(
                'rev-parse', '--show-toplevel', '--absolute-git-dir')) `
            -Environment $gitEnvironment `
            -TimeoutSeconds $GitCommandTimeoutSeconds `
            -MaxStandardOutputBytes (64 * 1024)
        if (-not [string]::IsNullOrEmpty($probeResult.OutputLimitExceeded)) {
            throw 'git-repository-probe-output-limit'
        }
        if ($probeResult.TimedOut) {
            throw 'git-repository-probe-timeout'
        }
        if ($probeResult.ExitCode -eq 0) {
            $probeOutput = ConvertFrom-StrictUtf8 `
                -Bytes $probeResult.StandardOutputBytes `
                -Context 'Git probe stdout'
            $probeLines = @($probeOutput -split "\r?\n" | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            })
            if ($probeLines.Count -ne 2) {
                throw 'malformed-git-probe'
            }

            $requestedRoot = Get-NormalizedPath -InputPath $root
            $reportedRoot = Get-NormalizedPath -InputPath $probeLines[0]
            $pathComparison = if ($script:isWindowsRuntime) {
                [StringComparison]::OrdinalIgnoreCase
            } else {
                [StringComparison]::Ordinal
            }
            if (-not [string]::Equals($requestedRoot, $reportedRoot, $pathComparison)) {
                throw 'scan-root-must-be-repository-root'
            }

            $absoluteGitDir = Get-NormalizedPath -InputPath $probeLines[1]
            $gitCommandPrefix = @(
                "--git-dir=$absoluteGitDir",
                "--work-tree=$requestedRoot"
            ) + $safeConfigArguments
            $listArguments = $gitCommandPrefix + @(
                'ls-files', '-z', '--stage', '--')
            $listResult = Invoke-BoundedProcess `
                -FilePath $gitExe.Source `
                -ArgumentList $listArguments `
                -Environment $gitEnvironment `
                -TimeoutSeconds $GitCommandTimeoutSeconds `
                -MaxStandardOutputBytes (4 * 1024 * 1024)
            if (-not [string]::IsNullOrEmpty($listResult.OutputLimitExceeded)) {
                throw 'git-index-output-limit'
            }
            if ($listResult.TimedOut) {
                throw 'git-index-enumeration-timeout'
            }
            if ($listResult.ExitCode -ne 0) {
                throw 'git-index-enumeration-failed'
            }

            $listOutput = ConvertFrom-StrictUtf8 `
                -Bytes $listResult.StandardOutputBytes `
                -Context 'Git index metadata stdout'
            $seenPaths = @{}
            $trackedEntries = New-Object System.Collections.Generic.List[object]
            $textEntries = New-Object System.Collections.Generic.List[object]
            $rootPrefix = $requestedRoot
            if (-not $rootPrefix.EndsWith(
                    [string][System.IO.Path]::DirectorySeparatorChar)) {
                $rootPrefix += [System.IO.Path]::DirectorySeparatorChar
            }
            # `-split NUL` は空record反復を巨大string配列へ増幅するため、
            # delimiter index を1件ずつ進め、substring作成前にentry capを数える。
            $recordOffset = 0
            while ($recordOffset -lt $listOutput.Length) {
                $nulIndex = $listOutput.IndexOf([char]0, $recordOffset)
                if ($nulIndex -lt 0) {
                    throw 'malformed-git-index-terminator'
                }
                $trackedEntryCount++
                if ($trackedEntryCount -gt $maxTrackedEntries) {
                    throw 'git-index-entry-limit'
                }
                if ($nulIndex -eq $recordOffset) {
                    throw 'malformed-git-index-entry'
                }
                $entry = $listOutput.Substring(
                    $recordOffset,
                    $nulIndex - $recordOffset)
                $recordOffset = $nulIndex + 1

                $tabIndex = $entry.IndexOf([char]9)
                if ($tabIndex -le 0 -or $tabIndex -eq ($entry.Length - 1)) {
                    throw 'malformed-git-index-entry'
                }
                $metadata = $entry.Substring(0, $tabIndex)
                $relative = $entry.Substring($tabIndex + 1)
                if ($relative -match '[\x00-\x1F\x7F]') {
                    throw 'tracked-path-control-character'
                }
                $metadataMatch = [regex]::Match(
                    $metadata,
                    '^(?<Mode>[0-9]{6}) (?<Object>(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})) (?<Stage>[0-3])$')
                if (-not $metadataMatch.Success) {
                    throw 'malformed-git-index-metadata'
                }
                if ($metadataMatch.Groups['Stage'].Value -ne '0') {
                    throw 'tracked-entry-conflict-stage'
                }

                $mode = $metadataMatch.Groups['Mode'].Value
                $objectId = $metadataMatch.Groups['Object'].Value
                if ($objectId -match '^0+$') {
                    throw 'tracked-entry-intent-to-add'
                }
                if ($mode -eq '120000') {
                    throw 'tracked-entry-symlink'
                }
                if ($mode -eq '160000') {
                    throw 'tracked-entry-gitlink'
                }
                if ($mode -notin @('100644', '100755')) {
                    throw 'tracked-entry-unsupported-mode'
                }
                if ($seenPaths.ContainsKey($relative)) {
                    throw 'duplicate-git-index-path'
                }
                $seenPaths[$relative] = $true

                $platformEntry = $relative.Replace(
                    [char]47, [System.IO.Path]::DirectorySeparatorChar)
                if ([System.IO.Path]::IsPathRooted($platformEntry)) {
                    throw 'tracked-path-escape'
                }
                $fullPath = [System.IO.Path]::GetFullPath(
                    (Join-Path $requestedRoot $platformEntry))
                if (-not $fullPath.StartsWith($rootPrefix, $pathComparison)) {
                    throw 'tracked-path-escape'
                }
                # local marker file は untracked 専用である。index に現れた時点で
                # 内容を出力・走査せず、公開候補への混入として fail closed にする。
                if ($relative -imatch '(?:^|/)\.private-markers\.local$') {
                    throw 'tracked-local-marker-file'
                }
                $trackedEntry = [pscustomobject]@{
                    Relative = $relative
                    ObjectId = $objectId
                    FullPath = $fullPath
                    IsText = Test-IsTextFile -FullPath $relative
                }
                $trackedEntries.Add($trackedEntry) | Out-Null
                if ($trackedEntry.IsText) {
                    if ($textEntries.Count -ge $maxTextEntries) {
                        throw 'git-index-text-entry-limit'
                    }
                    $textEntries.Add($trackedEntry) | Out-Null
                }
            }

            # stage metadataと同じ順序のdebug snapshotを取得し、reconstructed
            # stage bytes一致とCE_INTENT_TO_ADD flagをworktree access前に確認する。
            $debugArguments = $gitCommandPrefix + @(
                'ls-files', '-z', '--stage', '--debug', '--')
            $debugResult = Invoke-BoundedProcess `
                -FilePath $gitExe.Source `
                -ArgumentList $debugArguments `
                -Environment $gitEnvironment `
                -TimeoutSeconds $GitCommandTimeoutSeconds `
                -MaxStandardOutputBytes $maxGitIndexDebugBytes
            if (-not [string]::IsNullOrEmpty($debugResult.OutputLimitExceeded)) {
                throw 'git-index-debug-output-limit'
            }
            if ($debugResult.TimedOut) {
                throw 'git-index-debug-timeout'
            }
            if ($debugResult.ExitCode -ne 0) {
                throw 'git-index-debug-failed'
            }
            $debugInfo = ConvertFrom-GitIndexDebug `
                -Bytes $debugResult.StandardOutputBytes
            if (-not [System.Collections.StructuralComparisons]::StructuralEqualityComparer.Equals(
                    $listResult.StandardOutputBytes,
                    $debugInfo.StageBytes)) {
                throw 'git-index-changed-during-scan'
            }
            if ($debugInfo.HasIntentToAdd) {
                throw 'tracked-entry-intent-to-add'
            }

            # flag snapshotを固定した後にworktreeを検査するため、削除済みITAも
            # generic missingより先に上のintent codeでfail closedになる。
            foreach ($trackedEntry in $trackedEntries) {
                if (-not (Test-Path -LiteralPath $trackedEntry.FullPath)) {
                    throw 'tracked-worktree-missing'
                }
                $worktreeItem = Get-Item `
                    -LiteralPath $trackedEntry.FullPath `
                    -Force
                if (-not (Test-IsRegularFileSystemItem -Item $worktreeItem)) {
                    throw 'tracked-worktree-not-regular-file'
                }
                if (Test-PathHasReparsePoint `
                    -FullPath $trackedEntry.FullPath `
                    -BoundaryRoot $requestedRoot `
                    -Comparison $pathComparison) {
                    throw 'tracked-worktree-reparse-point'
                }
            }

            if ($textEntries.Count -gt 0) {
                # 全OIDを単一 batch child で読む。tracked file 数に比例した
                # process fan-out をなくし、Git child は scan 全体で最大6回に固定する。
                [byte[]]$batchInput = New-GitBatchInputBytes -Entries $textEntries
                $maxGitBatchOutputBytes = [int](
                    $maxTotalTextBytes +
                    ([long]$maxTextEntries * 160) +
                    1)
                $batchResult = Invoke-BoundedProcess `
                    -FilePath $gitExe.Source `
                    -ArgumentList ($gitCommandPrefix + @('cat-file', '--batch')) `
                    -Environment $gitEnvironment `
                    -StandardInputBytes $batchInput `
                    -TimeoutSeconds $GitCommandTimeoutSeconds `
                    -MaxStandardOutputBytes $maxGitBatchOutputBytes
                if (-not [string]::IsNullOrEmpty($batchResult.OutputLimitExceeded)) {
                    throw 'git-index-blob-size-limit'
                }
                if ($batchResult.TimedOut) {
                    throw 'git-index-blob-timeout'
                }
                if ($batchResult.ExitCode -ne 0) {
                    throw 'git-index-blob-read-failed'
                }
                $indexBlobs = ConvertFrom-GitBatchOutput `
                    -Bytes $batchResult.StandardOutputBytes `
                    -Entries $textEntries `
                    -MaxBlobBytes $maxTextFileBytes

                for ($entryIndex = 0;
                    $entryIndex -lt $textEntries.Count;
                    $entryIndex++) {
                    $textEntry = $textEntries[$entryIndex]
                    [byte[]]$indexBytes = $indexBlobs[$entryIndex]
                    [byte[]]$worktreeBytes = Read-TrackedWorktreeBytes `
                        -FullPath $textEntry.FullPath `
                        -BoundaryRoot $requestedRoot `
                        -Comparison $pathComparison `
                        -MaxBytes $maxTextFileBytes
                    $totalTextBytes += (
                        $indexBytes.Length +
                        $worktreeBytes.Length)
                    if ($totalTextBytes -gt $maxTotalTextBytes) {
                        throw 'scan-total-text-size-limit'
                    }
                    $portableRelative = $textEntry.Relative.Replace(
                        [char]92, [char]47)
                    Scan-TextBytes `
                        -Bytes $indexBytes `
                        -Context 'Git index blob' `
                        -Relative $portableRelative `
                        -Source 'index'
                    Scan-TextBytes `
                        -Bytes $worktreeBytes `
                        -Context 'tracked worktree file' `
                        -Relative $portableRelative `
                        -Source 'worktree'
                }
            }

            # 完了直前に同一 ls-files command を再実行し、NULを含む raw bytes が
            # 1byteでも変われば stage add/replace/delete を見逃さず fail closed。
            $finalListResult = Invoke-BoundedProcess `
                -FilePath $gitExe.Source `
                -ArgumentList $listArguments `
                -Environment $gitEnvironment `
                -TimeoutSeconds $GitCommandTimeoutSeconds `
                -MaxStandardOutputBytes (4 * 1024 * 1024)
            if (-not [string]::IsNullOrEmpty($finalListResult.OutputLimitExceeded)) {
                throw 'git-index-output-limit'
            }
            if ($finalListResult.TimedOut) {
                throw 'git-index-enumeration-timeout'
            }
            if ($finalListResult.ExitCode -ne 0) {
                throw 'git-index-enumeration-failed'
            }
            $finalDebugResult = Invoke-BoundedProcess `
                -FilePath $gitExe.Source `
                -ArgumentList $debugArguments `
                -Environment $gitEnvironment `
                -TimeoutSeconds $GitCommandTimeoutSeconds `
                -MaxStandardOutputBytes $maxGitIndexDebugBytes
            if (-not [string]::IsNullOrEmpty($finalDebugResult.OutputLimitExceeded)) {
                throw 'git-index-debug-output-limit'
            }
            if ($finalDebugResult.TimedOut) {
                throw 'git-index-debug-timeout'
            }
            if ($finalDebugResult.ExitCode -ne 0) {
                throw 'git-index-debug-failed'
            }
            $finalDebugInfo = ConvertFrom-GitIndexDebug `
                -Bytes $finalDebugResult.StandardOutputBytes
            if (-not [System.Collections.StructuralComparisons]::StructuralEqualityComparer.Equals(
                    $finalListResult.StandardOutputBytes,
                    $finalDebugInfo.StageBytes)) {
                throw 'git-index-changed-during-scan'
            }
            if (-not [System.Collections.StructuralComparisons]::StructuralEqualityComparer.Equals(
                    $listResult.StandardOutputBytes,
                    $finalListResult.StandardOutputBytes)) {
                throw 'git-index-changed-during-scan'
            }
            if (-not [System.Collections.StructuralComparisons]::StructuralEqualityComparer.Equals(
                    $debugResult.StandardOutputBytes,
                    $finalDebugResult.StandardOutputBytes)) {
                throw 'git-index-debug-changed-during-scan'
            }
            if ($finalDebugInfo.HasIntentToAdd) {
                throw 'tracked-entry-intent-to-add'
            }
            $scanMode = 'git-index+worktree'
        } elseif ($gitControlDetectedAtOrAbove) {
            throw 'git-repository-probe-failed'
        }
    }
    catch {
        $knownFailure = [string]$_.Exception.Message
        if ($knownFailure -match '^(?:malformed-|scan-|tracked-|duplicate-|git-|Child process)') {
            $gitFailureCode = $knownFailure
        } else {
            $gitFailureCode = 'git-scan-internal-error'
        }
    }
    finally {
        # 成否を問わず scanner 専用 config/home/hooks/template を回収する。
        try {
            if (Test-Path -LiteralPath $gitIsolationRoot) {
                Remove-Item -LiteralPath $gitIsolationRoot -Recurse -Force
            }
        }
        catch {
            # temp の絶対 path や生例外を公開出力へ流さず、匿名 code で止める。
            $gitFailureCode = 'git-isolation-cleanup-failed'
        }
    }
}

if (-not [string]::IsNullOrEmpty($gitFailureCode)) {
    Write-Host "Private marker scan aborted: $gitFailureCode"
    exit 1
}

if ($scanMode -eq 'working-tree') {
    try {
        $fallbackRoot = Get-NormalizedPath -InputPath $root
        $fallbackComparison = if ($script:isWindowsRuntime) {
            [StringComparison]::OrdinalIgnoreCase
        } else {
            [StringComparison]::Ordinal
        }
        $fallbackPrefix = $fallbackRoot
        if (-not $fallbackPrefix.EndsWith(
                [string][System.IO.Path]::DirectorySeparatorChar)) {
            $fallbackPrefix += [System.IO.Path]::DirectorySeparatorChar
        }
        $rootLocalMarkerPath = Join-Path $fallbackRoot '.private-markers.local'

        # pipeline のまま1件ずつ処理し、全file/line配列を同時保持しない。
        Get-ChildItem -LiteralPath $fallbackRoot -Recurse -File -Force |
            ForEach-Object {
                $script:trackedEntryCount++
                if ($script:trackedEntryCount -gt $maxTrackedEntries) {
                    throw 'working-tree-entry-limit'
                }
                $fullPath = [System.IO.Path]::GetFullPath($_.FullName)
                $portablePath = $fullPath.Replace([char]92, [char]47)
                $excluded = (
                    $portablePath -match '/\.git(/|$)' -or
                    $portablePath -match '/node_modules(/|$)' -or
                    $portablePath -match '/\.cache(/|$)')
                if (-not $excluded) {
                    if (-not (Test-IsRegularFileSystemItem -Item $_)) {
                        throw 'working-tree-entry-not-regular-file'
                    }
                    if (-not $fullPath.StartsWith(
                            $fallbackPrefix,
                            $fallbackComparison)) {
                        throw 'working-tree-path-escape'
                    }
                    $isRootLocalMarker = [string]::Equals(
                        $fullPath,
                        $rootLocalMarkerPath,
                        $fallbackComparison)
                    if (-not $isRootLocalMarker -and
                        ($_.Name -ieq '.private-markers.local' -or
                            (Test-IsTextFile $fullPath))) {
                        [byte[]]$worktreeBytes = Read-TrackedWorktreeBytes `
                            -FullPath $fullPath `
                            -BoundaryRoot $fallbackRoot `
                            -Comparison $fallbackComparison `
                            -MaxBytes $maxTextFileBytes
                        $script:totalTextBytes += $worktreeBytes.Length
                        if ($script:totalTextBytes -gt $maxTotalTextBytes) {
                            throw 'scan-total-text-size-limit'
                        }
                        $relative = $fullPath.Substring($fallbackPrefix.Length)
                        Scan-TextBytes `
                            -Bytes $worktreeBytes `
                            -Context 'working-tree file' `
                            -Relative $relative.Replace([char]92, [char]47) `
                            -Source 'worktree'
                    }
                }
            }
    }
    catch {
        $knownFailure = [string]$_.Exception.Message
        if ($knownFailure -notmatch '^(?:scan-|tracked-|working-tree-|Child process)') {
            $knownFailure = 'working-tree-scan-internal-error'
        }
        Write-Host "Private marker scan aborted: $knownFailure"
        exit 1
    }
}

if ($findings.Count -gt 0) {
    # prefix/header/rowを明示LFの単一payloadへ積み、最終時に一度だけUTF-8化する。
    # Write-Hostのplatform newline差やpartial tableを出力境界へ持ち込まない。
    $findingOutputBuilder = New-Object System.Text.StringBuilder
    $findingOutputPrefix = "Private marker scan failed (scan target: $scanMode):"
    $findingOutputHeader = "File`tSource`tLine`tRule`tMatch"
    [void]$findingOutputBuilder.Append($findingOutputPrefix)
    [void]$findingOutputBuilder.Append([char]10)
    [void]$findingOutputBuilder.Append($findingOutputHeader)
    [void]$findingOutputBuilder.Append([char]10)
    $findingOutputByteCount = (
        [System.Text.Encoding]::UTF8.GetByteCount($findingOutputPrefix) +
        1 +
        [System.Text.Encoding]::UTF8.GetByteCount($findingOutputHeader) +
        1)
    foreach ($finding in ($findings | Sort-Object File, Source, Line, Rule)) {
        $findingOutputLine = "{0}`t{1}`t{2}`t{3}`t{4}" -f @(
            $finding.File,
            $finding.Source,
            $finding.Line,
            $finding.Rule,
            $finding.Match)
        # prefixを含むactual UTF-8 payload byte数で上限を先に判定する。
        $findingOutputByteCount += (
            [System.Text.Encoding]::UTF8.GetByteCount($findingOutputLine) + 1)
        if ($findingOutputByteCount -gt $maxFindingOutputBytes) {
            Write-Host 'Private marker scan aborted: scan-diagnostic-output-limit'
            exit 1
        }
        [void]$findingOutputBuilder.Append($findingOutputLine)
        [void]$findingOutputBuilder.Append([char]10)
    }
    [byte[]]$findingOutputBytes = [System.Text.Encoding]::UTF8.GetBytes(
        $findingOutputBuilder.ToString())
    if ($findingOutputBytes.Length -ne $findingOutputByteCount -or
        $findingOutputBytes.Length -gt $maxFindingOutputBytes) {
        Write-Host 'Private marker scan aborted: scan-diagnostic-output-limit'
        exit 1
    }
    $standardOutput = [Console]::OpenStandardOutput()
    try {
        $standardOutput.Write(
            $findingOutputBytes,
            0,
            $findingOutputBytes.Length)
        $standardOutput.Flush()
    }
    finally {
        $standardOutput.Dispose()
    }
    exit 1
}

Write-Host "Private marker scan passed (scan target: $scanMode)."
exit 0
