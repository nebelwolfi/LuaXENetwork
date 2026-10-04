# TB-287 test runner for the LuaXE network module.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tests\run_all.ps1 -Dll <network.dll>
#   powershell ... -Lxe D:\LuaXE\bin\lxe.exe        (default)
#   powershell ... -Script tests\tls_matrix.lua       (one script, same watchdog)
#
# It starts tests\fixtures\servers.ps1 as a child, waits for its ports file, runs
# every test script against it, then stops the child and proves that no private
# key it created survived. Every child gets an isolated USERPROFILE/HOME under the
# work directory, so nothing reaches the real user state.

param(
    [Parameter(Mandatory = $true)][string]$Dll,
    [string]$Lxe = 'D:\LuaXE\bin\lxe.exe',
    [string]$Script = '',
    [switch]$KeepWork,
    [int]$TimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)   # the module directory
# The work directory holds the openssl certificates and keys this run generates,
# so it lives where it is cleaned up afterwards and never in the user's TEMP:
# GIRL_SCRATCH when the harness provides one, the module's own tmp otherwise.
$scratchRoot = $env:GIRL_SCRATCH
if (-not $scratchRoot) { $scratchRoot = Join-Path $root 'tmp' }
$work = Join-Path $scratchRoot ('network-tests-' + $PID)
New-Item -ItemType Directory -Force -Path $work | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $work 'home') | Out-Null

# Isolated home for every child this runner starts.
$env:USERPROFILE = Join-Path $work 'home'
$env:HOME = $env:USERPROFILE

$infoPath = Join-Path $work 'info.json'
$fixtureOut = Join-Path $work 'fixture.out'
$fixtureErr = Join-Path $work 'fixture.err'
$fixture = $null
$results = New-Object System.Collections.ArrayList
$exitCode = 0

function Invoke-Script {
    param([string]$ScriptPath, [string[]]$Extra)
    # lxe wants: run <script> [args]
    $arguments = @('run', $ScriptPath) + $Extra
    $out = Join-Path $work ((Split-Path -Leaf $ScriptPath) + '.out')
    $err = Join-Path $work ((Split-Path -Leaf $ScriptPath) + '.err')
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath $Lxe -ArgumentList $arguments -NoNewWindow -PassThru `
        -RedirectStandardOutput $out -RedirectStandardError $err
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        try { $process.Kill() } catch { }
        Write-Output ('TIMEOUT ' + (Split-Path -Leaf $ScriptPath))
        $results.Add([pscustomobject]@{ Name = (Split-Path -Leaf $ScriptPath); Ok = $false; Seconds = $TimeoutSeconds })
        $exitCode = 1
        return
    }
    # The second, parameterless WaitForExit is what actually populates ExitCode
    # when the output was redirected: without it a script that exits 0 is read
    # back as a failure.
    $process.WaitForExit()
    $watch.Stop()
    $code = $process.ExitCode
    $seconds = [math]::Round($watch.Elapsed.TotalSeconds, 1)
    $text = ''
    foreach ($path in @($out, $err)) {
        if (Test-Path $path) { $text += (Get-Content -Raw -LiteralPath $path) }
    }
    Write-Output $text.TrimEnd()
    # The verdict is the line the script prints, not the process exit code:
    # with output redirected, a child that exits 0 is not reliably reported as 0
    # here (an earlier version of this runner called a passing suite a failure).
    $ok = $text -match '(?m)^\s*TB287 RESULT: pass\s*$'
    if (-not $ok) { $exitCode = 1 }
    $results.Add([pscustomobject]@{ Name = (Split-Path -Leaf $ScriptPath); Ok = $ok; Seconds = $seconds })
}

# One fixture per script, because the TLS servers are `openssl s_server`
# processes and they handle one connection at a time: a script that deliberately
# rejects a certificate (there are several such checks) leaves s_server busy with
# a half-finished handshake, and every later connection in the same run would time
# out. A fresh fixture per script keeps the tests independent.
function Start-Fixture {
    Remove-Item -LiteralPath $infoPath -Force -ErrorAction SilentlyContinue
    $process = Start-Process -FilePath 'powershell' -PassThru -NoNewWindow `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
            (Join-Path $root 'tests\fixtures\servers.ps1'), '-Work', $work, '-Info', $infoPath) `
        -RedirectStandardOutput $fixtureOut -RedirectStandardError $fixtureErr
    # The process object goes into a script-scope variable rather than being
    # returned: Write-Output in here would otherwise be collected as part of the
    # return value and the caller would get an array instead of the process.
    $script:fixtureProcess = $process
    $deadline = (Get-Date).AddSeconds(60)
    while (-not (Test-Path $infoPath)) {
        if ($process.HasExited) {
            Write-Output 'FIXTURE DIED:'
            Write-Output (Get-Content -Raw -LiteralPath $fixtureErr)
            throw 'the fixture did not start'
        }
        if ((Get-Date) -gt $deadline) {
            Write-Output 'FIXTURE TIMED OUT:'
            Write-Output (Get-Content -Raw -LiteralPath $fixtureErr)
            throw 'the fixture did not report its ports in 60 s'
        }
        Start-Sleep -Milliseconds 200
    }
}

function Get-Ports {
    $info = Get-Content -Raw -LiteralPath $infoPath | ConvertFrom-Json
    $ports = @()
    foreach ($property in $info.PSObject.Properties) {
        if ($property.Name -eq 'socks_replies') {
            foreach ($reply in $property.Value.PSObject.Properties) {
                $ports += ($reply.Name + '=' + $reply.Value)
            }
        } else {
            $ports += ($property.Name + '=' + $property.Value)
        }
    }
    # prefix is the only one the tests do not want: everything else, including
    # socks_report_dir (where the SOCKS fixtures write their reports), is passed on.
    return @($ports | Where-Object { $_ -notmatch '^prefix=' })
}

function Stop-Fixture {
    param($Process)
    Set-Content -Path (Join-Path $work 'stop') -Value 'stop' -Encoding ASCII
    if ($Process -and -not $Process.HasExited) {
        if (-not $Process.WaitForExit(20000)) {
            Write-Output 'FAIL the fixture ignored its stop file and had to be killed'
            try { $Process.Kill() } catch { }
            $script:exitCode = 1
        }
    }
    Remove-Item -LiteralPath (Join-Path $work 'stop') -Force -ErrorAction SilentlyContinue
}

try {
    # The TB-287 scripts are the suite. The older smoke scripts in this directory
    # need an external server and stay available one at a time via -Script.
    $scripts = if ($Script -ne '') { @($Script) } else {
        @(Get-ChildItem -Path (Join-Path $root 'tests') -Filter '*_matrix.lua' |
            Sort-Object Name | ForEach-Object { $_.FullName })
    }
    foreach ($path in $scripts) {
        Start-Fixture
        try {
            Invoke-Script -ScriptPath $path -Extra (@($Dll) + (Get-Ports))
        } finally {
            Stop-Fixture -Process $script:fixtureProcess
            $script:fixtureProcess = $null
            # A stopped fixture has already taken its openssl children down; the
            # outer check below still covers the case where it had to be killed.
            foreach ($name in @('children.json', 'info.json')) {
                Remove-Item -LiteralPath (Join-Path $work $name) -Force -ErrorAction SilentlyContinue
            }
        }
    }
} finally {
    if ($script:fixtureProcess) { Stop-Fixture -Process $script:fixtureProcess }
    # The fixture's TLS servers are openssl children. A killed fixture would leave
    # them listening, so they are stopped here too - by pid, and only after the
    # command line says both s_server and this run's work directory.
    $childrenFile = Join-Path $work 'children.json'
    if (Test-Path $childrenFile) {
        foreach ($child in @(Get-Content -Raw -LiteralPath $childrenFile | ConvertFrom-Json)) {
            $process = Get-CimInstance Win32_Process -Filter ('ProcessId = ' + $child.Id) -ErrorAction SilentlyContinue
            if (-not $process) { continue }
            if ($process.Name -eq 'openssl.exe' -and $process.CommandLine -like ('*s_server*' + $work + '*')) {
                try { Stop-Process -Id $child.Id -Force } catch { }
            } else {
                Write-Output ('FAIL refusing to stop pid ' + $child.Id + ': ' + $process.Name)
                $exitCode = 1
            }
        }
    }
    # The fixture must not touch a key store at all: its certificates are openssl
    # files. A key ledger appearing means that changed, and fails the run.
    if (Test-Path (Join-Path $work 'keys.txt')) {
        Write-Output 'FAIL the fixture wrote a key ledger: it must not create key containers'
        $exitCode = 1
    }
    Write-Output 'keys: none created (openssl file certificates), none to clean'
    foreach ($result in $results) {
        Write-Output (("{0,-28} {1,6}  {2}" -f $result.Name, $result.Seconds, $(if ($result.Ok) { 'pass' } else { 'FAIL' })))
    }
    # The whole work directory goes, including the openssl keys it generated.
    # -KeepWork leaves it behind for inspection.
    if (-not $KeepWork) {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $work) { Write-Output ('FAIL could not remove the work directory ' + $work) }
    } else {
        Write-Output ('work directory kept at ' + $work)
    }
}

exit $exitCode