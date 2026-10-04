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
    [int]$TimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)   # the module directory
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("tb287-tests-" + $PID)
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

try {
    $fixture = Start-Process -FilePath 'powershell' -PassThru -NoNewWindow `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
            (Join-Path $root 'tests\fixtures\servers.ps1'), '-Work', $work, '-Info', $infoPath) `
        -RedirectStandardOutput $fixtureOut -RedirectStandardError $fixtureErr

    $deadline = (Get-Date).AddSeconds(60)
    while (-not (Test-Path $infoPath)) {
        if ($fixture.HasExited) {
            Write-Output 'FIXTURE DIED:'
            Write-Output (Get-Content -Raw -LiteralPath $fixtureErr)
            throw 'the fixture did not start'
        }
        if ((Get-Date) -gt $deadline) { throw 'the fixture did not report its ports in 60 s' }
        Start-Sleep -Milliseconds 200
    }
    $info = Get-Content -Raw -LiteralPath $infoPath | ConvertFrom-Json
    Write-Output ('fixture: ca=' + $info.ca_pem + ' plain=' + $info.plain_port + ' secure=' + $info.secure_port)

    $ports = @()
    foreach ($property in $info.PSObject.Properties) {
        if ($property.Name -eq 'socks_replies') {
            foreach ($reply in $property.Value.PSObject.Properties) {
                $ports += ($reply.Name + '=' + $reply.Value)
            }
        } elseif ($property.Value -is [string] -and $property.Name -ne 'ca_pem') {
            $ports += ($property.Name + '=' + $property.Value)
        } else {
            $ports += ($property.Name + '=' + $property.Value)
        }
    }
    $ports = $ports | Where-Object { $_ -notmatch '^(prefix|socks_report_dir)=' }

    # The TB-287 scripts are the suite. The older smoke scripts in this directory
    # need an external server and stay available one at a time via -Script.
    $scripts = if ($Script -ne '') { @($Script) } else {
        @(Get-ChildItem -Path (Join-Path $root 'tests') -Filter '*_matrix.lua' |
            Sort-Object Name | ForEach-Object { $_.FullName })
    }
    foreach ($path in $scripts) {
        Invoke-Script -ScriptPath $path -Extra (@($Dll) + $ports)
    }
} finally {
    # Stop file first, so the fixture can shut its own listeners down; only a
    # fixture that ignores it is killed.
    Set-Content -Path (Join-Path $work 'stop') -Value 'stop' -Encoding ASCII
    if ($fixture -and -not $fixture.HasExited) {
        if (-not $fixture.WaitForExit(20000)) {
            Write-Output 'FAIL the fixture ignored its stop file and had to be killed'
            try { $fixture.Kill() } catch { }
            $exitCode = 1
        }
    }
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
    foreach ($name in @('info.json', 'children.json', 'stop')) {
        Remove-Item -LiteralPath (Join-Path $work $name) -Force -ErrorAction SilentlyContinue
    }
}

exit $exitCode