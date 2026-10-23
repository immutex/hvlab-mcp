//! Embedded PowerShell Direct sidecar script.
//!
//! The host spawns one `powershell.exe` running [`SIDECAR_SCRIPT`],
//! which creates the persistent `New-PSSession -VMName <vm>` and then
//! serves length-prefixed JSON requests on stdin/stdout from that one
//! process (`PSSession` handles are process-local, so a second process
//! could never re-attach to a session the first one created). Identity
//! is asserted by the Rust side before any payload; the script echoes
//! the session nonce on every response, refuses payload requests when
//! no guest session exists (they are never run on the host), verifies
//! SHA-256 on both ends of file transfers (H-08), and reports exit
//! codes as structured fields, never as scraped text (H-05). The VM
//! name travels base64-encoded, so no guest-controlled string ever
//! appears in a command line (H-34).

use crate::protocol::MAX_FRAME_LEN;

fn base64(data: &[u8]) -> String {
    crate::psdirect::b64_encode(data)
}

/// Build the single-process sidecar command line: the main loop, with
/// the VM name base64-encoded as a parameter. The base64 alphabet has
/// no quote or interpolation characters, so the VM name can never break
/// out of the single-quoted literal (H-34).
#[must_use]
pub fn sidecar_command(vm_name: &str) -> String {
    format!(
        "& {{ {} }} -VMNameB64 '{}'",
        sidecar_script(),
        base64(vm_name.as_bytes())
    )
}

/// The main-loop script with the frame cap substituted on first use.
#[must_use]
pub fn sidecar_script() -> &'static str {
    static SCRIPT: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        SIDECAR_SCRIPT.replace("@@MAX_FRAME_LEN@@", &MAX_FRAME_LEN.to_string())
    });
    &SCRIPT
}

/// The sidecar main loop: creates the guest session, then serves
/// framed JSON requests. Payload requests are REFUSED when the session
/// could not be created — they are never run on the host.
///
/// Frame cap is [`MAX_FRAME_LEN`] (16 MiB), mirrored on the Rust side.
pub const SIDECAR_SCRIPT: &str = r#"
param([string]$VMNameB64)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# The VM name arrives base64-encoded: decoding it is the only way it
# enters the script, and it is never interpolated into a command.
$vmName = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($VMNameB64))
$session = New-PSSession -VMName $vmName -ErrorAction Stop

function Write-Frame([byte[]]$bytes) {
    $out = [Console]::OpenStandardOutput()
    $len = [BitConverter]::GetBytes([UInt32]$bytes.Length)
    $out.Write($len, 0, 4)
    $out.Write($bytes, 0, $bytes.Length)
    $out.Flush()
}

function Read-Frame {
    $stdin = [Console]::OpenStandardInput()
    $lb = New-Object byte[] 4
    $off = 0
    while ($off -lt 4) {
        $n = $stdin.Read($lb, $off, 4 - $off)
        if ($n -le 0) { throw 'stdin closed' }
        $off += $n
    }
    $len = [BitConverter]::ToUInt32($lb, 0)
    if ($len -gt @@MAX_FRAME_LEN@@) { throw 'frame too large' }
    $buf = New-Object byte[] $len
    $off = 0
    while ($off -lt $len) {
        $n = $stdin.Read($buf, $off, $len - $off)
        if ($n -le 0) { throw 'stdin closed' }
        $off += $n
    }
    [System.Text.Encoding]::UTF8.GetString($buf)
}

function Send-Obj($obj, [int]$Depth = 10) {
    # PowerShell does not allow a pipeline inside a method-call argument,
    # so the JSON text is materialized first.
    $json = $obj | ConvertTo-Json -Compress -Depth $Depth
    Write-Frame ([System.Text.Encoding]::UTF8.GetBytes([string]$json))
}

function B64ToBytes([string]$s) { [Convert]::FromBase64String($s) }
function BytesToB64([byte[]]$b) { [Convert]::ToBase64String($b) }
function Utf8ToB64([string]$s) { BytesToB64 [System.Text.Encoding]::UTF8.GetBytes($s) }

function Get-Sha256([byte[]]$bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '' }
    finally { $sha.Dispose() }
}

# A payload must never run on the host: without an established guest
# session every execution request is refused, not downgraded (H-36).
function Assert-GuestSession {
    if ($null -eq $session) { throw 'no guest session established: payload refused' }
}

# Win32 argv quoting: wrap in quotes when needed, double backslashes
# that precede a quote or trail the argument. Typed parameters only —
# the guest payload never touches a shell (H-34).
# Read a temp capture file, keeping the TAIL when it exceeds the cap so
# the beginning of a huge log cannot OOM the pipe (H-27: bounded
# buffers, explicit about what was dropped).
function Read-Tail([string]$path) {
    $limitBytes = 8MB
    $fi = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
    if (-not $fi -or $fi.Length -le $limitBytes) {
        return [IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
    }
    $fs = [IO.File]::OpenRead($path)
    try {
        $fs.Seek(-$limitBytes, [IO.SeekOrigin]::End) | Out-Null
        $buf = New-Object byte[] $limitBytes
        $null = $fs.Read($buf, 0, $limitBytes)
        return [System.Text.Encoding]::UTF8.GetString($buf)
    } finally { $fs.Dispose() }
}

function Quote-Arg([string]$s) {
    if ($s -eq '') { return '""' }
    if ($s -notmatch '[\s"]') {
        if ($s.EndsWith('\')) { return $s + '\\' }
        return $s
    }
    $r = $s -replace '(\\*)"', '$1$1\"'
    $r = $r -replace '(\\+)$', '$1$1'
    '"' + $r + '"'
}

while ($true) {
    try { $req = Read-Frame | ConvertFrom-Json } catch { break }

    $nonce = ''
    if ($req.PSObject.Properties['nonce']) { $nonce = [string]$req.nonce }
    $id = [UInt64]0
    if ($req.PSObject.Properties['id']) { $id = [UInt64]$req.id }

    try {
        switch ([string]$req.kind) {
            'ident' {
                $resp = @{ kind = 'ident'; nonce = $nonce; hostname = $env:COMPUTERNAME
                           session = ($null -ne $session) }
                Send-Obj $resp
            }
            'ping' {
                Assert-GuestSession
                $resp = @{ id = $id; ok = $true; nonce = $nonce; hostname = $env:COMPUTERNAME
                           session = $true }
                Send-Obj $resp
            }
            'exec' {
                Assert-GuestSession
                $program = [System.Text.Encoding]::UTF8.GetString((B64ToBytes $req.program_b64))
                $argv = @($req.argv | ForEach-Object { [string]$_ })
                $argLine = ($argv | ForEach-Object { Quote-Arg $_ }) -join ' '
                $timeoutMs = [int]$req.timeout_ms
                $out = Invoke-Command -Session $session -ScriptBlock {
                    param($exe, $line, $limitMs)
                    $soTmp = [IO.Path]::GetTempFileName()
                    $seTmp = [IO.Path]::GetTempFileName()
                    try {
                        $proc = Start-Process -FilePath $exe -ArgumentList $line `
                            -NoNewWindow -PassThru `
                            -RedirectStandardOutput $soTmp -RedirectStandardError $seTmp
                        if (-not $proc.WaitForExit($limitMs)) {
                            # Tree kill that works on Windows PowerShell 5.1
                            # (no Process.Kill($true) there): walk
                            # Win32_Process parent links and stop every
                            # descendant, then the root. Best effort.
                            try {
                                $all = @(Get-CimInstance Win32_Process -ErrorAction Stop)
                                $pending = @($proc.Id)
                                $killed = New-Object System.Collections.Generic.HashSet[uint32]
                                while ($pending.Count -gt 0) {
                                    $pid = $pending[0]; $pending = $pending[1..($pending.Count - 1)]
                                    if (-not $killed.Add([uint32]$pid)) { continue }
                                    foreach ($c in ($all | Where-Object { $_.ParentProcessId -eq $pid })) {
                                        $pending += [uint32]$c.ProcessId
                                    }
                                    try { Stop-Process -Id $pid -Force -ErrorAction Stop } catch {}
                                }
                            } catch {}
                            $so = Read-Tail $soTmp
                            $se = Read-Tail $seTmp
                            return @{ exit_code = -1; stdout = $so; stderr = $se; timed_out = $true }
                        }
                        $so = Read-Tail $soTmp
                        $se = Read-Tail $seTmp
                        return @{ exit_code = $proc.ExitCode; stdout = $so; stderr = $se; timed_out = $false }
                    } finally {
                        Remove-Item -Force $soTmp, $seTmp -ErrorAction SilentlyContinue
                    }
                } -ArgumentList $program, $argLine, $timeoutMs | ConvertTo-Json -Compress -Depth 4
                $out = $out | ConvertFrom-Json
                $resp = @{
                    id = $id; ok = $true; nonce = $nonce
                    exit_code = [int]$out.exit_code
                    stdout_b64 = Utf8ToB64 ([string]$out.stdout)
                    stderr_b64 = Utf8ToB64 ([string]$out.stderr)
                    timed_out = [bool]$out.timed_out
                }
                Send-Obj $resp
            }
            'ps' {
                Assert-GuestSession
                $script = [System.Text.Encoding]::UTF8.GetString((B64ToBytes $req.script_b64))
                $sb = [ScriptBlock]::Create($script)
                $limitBytes = 8MB
                $exitCode = 0
                $errCount = 0
                $so = ''
                try {
                    $so = Invoke-Command -Session $session -ScriptBlock $sb -ErrorVariable +psErrors -ErrorAction Continue | Out-String
                } catch {
                    # A terminating error in the guest script is a real
                    # failure; surface it as a nonzero exit, never as a
                    # success-shaped exit_code of 0 (H-01/H-06).
                    $errCount = 1
                    $so = [string]$_
                    $exitCode = 1
                }
                if ($errCount -eq 0) { $errCount = @($psErrors).Count }
                if ($errCount -gt 0 -and $exitCode -eq 0) { $exitCode = 1 }
                # Bound the payload: guest output can be arbitrarily large
                # and the pipe is the only path back (H-27).
                if ($so.Length -gt $limitBytes) { $so = $so.Substring($so.Length - $limitBytes) }
                $resp = @{
                    id = $id; ok = $true; nonce = $nonce; exit_code = $exitCode
                    stdout_b64 = Utf8ToB64 $so; stderr_b64 = ''
                }
                Send-Obj $resp
            }
            'put' {
                Assert-GuestSession
                $data = B64ToBytes $req.data_b64
                $hash = Get-Sha256 $data
                if ($hash -ne [string]$req.sha256) { throw 'sha256 mismatch' }
                $dest = [string]$req.path
                $remote = Invoke-Command -Session $session -ScriptBlock {
                    param($bytes, $path)
                    [IO.File]::WriteAllBytes($path, $bytes)
                    $h = [System.Security.Cryptography.SHA256]::Create()
                    try {
                        ($h.ComputeHash([IO.File]::ReadAllBytes($path)) |
                            ForEach-Object { $_.ToString('x2') }) -join ''
                    } finally { $h.Dispose() }
                } -ArgumentList $data, $dest
                if ($remote -ne $hash) { throw 'post-write hash mismatch on guest' }
                $resp = @{ id = $id; ok = $true; nonce = $nonce; sha256 = $hash }
                Send-Obj $resp
            }
            'get' {
                Assert-GuestSession
                $src = [string]$req.path
                $result = Invoke-Command -Session $session -ScriptBlock {
                    param($path)
                    $bytes = [IO.File]::ReadAllBytes($path)
                    $h = [System.Security.Cryptography.SHA256]::Create()
                    try {
                        @{ data = [Convert]::ToBase64String($bytes)
                           sha256 = (($h.ComputeHash($bytes) |
                               ForEach-Object { $_.ToString('x2') }) -join '') }
                    } finally { $h.Dispose() }
                } -ArgumentList $src
                $resp = @{
                    id = $id; ok = $true; nonce = $nonce
                    sha256 = [string]$result.sha256; data_b64 = [string]$result.data
                }
                Send-Obj $resp
            }
            default { throw "unknown kind: $($req.kind)" }
        }
    } catch {
        $resp = @{ id = $id; ok = $false; nonce = $nonce; error = [string]$_.Exception.Message }
        Send-Obj $resp
    }
}
"#;
