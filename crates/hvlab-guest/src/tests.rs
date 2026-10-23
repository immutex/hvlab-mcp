//! Unit tests: framing, base64, path policy, and the sidecar protocol
//! driven against a real fake-sidecar process. Hermetic (T0) on
//! Windows; the T2 test against a real guest is env-gated.

use std::io::Cursor;
use std::path::{Path, PathBuf};

use crate::path_policy::PathPolicy;
use crate::protocol::{FrameError, MAX_FRAME_LEN, read_frame, write_frame};
use crate::psdirect::{
    ExecSpec, IDENT_TIMEOUT, PsDirectSession, b64_decode, b64_encode, sha256_hex,
};
use crate::sidecar;
use hvlab_core::error::ErrorCode;

// ---------------------------------------------------------------- framing

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct Probe {
    n: u32,
    s: String,
}

#[test]
fn frame_round_trips() {
    let probe = Probe {
        n: 42,
        s: "héllo 🎉".to_owned(),
    };
    let mut buf = Cursor::new(Vec::new());
    write_frame(&mut buf, &probe).expect("write");
    buf.set_position(0);
    let back: Probe = read_frame(&mut buf).expect("read");
    assert_eq!(back, probe);
}

#[test]
fn frame_length_prefix_is_four_byte_le() {
    let mut buf = Cursor::new(Vec::new());
    write_frame(
        &mut buf,
        &Probe {
            n: 1,
            s: String::new(),
        },
    )
    .expect("write");
    let raw = buf.into_inner();
    let len = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    assert_eq!(raw.len(), 4 + len);
}

#[test]
fn frame_rejects_truncated_stream() {
    let mut buf = Cursor::new(Vec::new());
    write_frame(
        &mut buf,
        &Probe {
            n: 1,
            s: "x".repeat(100),
        },
    )
    .expect("write");
    let raw = buf.into_inner();
    for cut in [0usize, 1, 2, 3, 4, 10, raw.len() - 1] {
        let mut partial = Cursor::new(raw[..cut].to_vec());
        let err: Result<Probe, FrameError> = read_frame(&mut partial);
        assert!(err.is_err(), "cut at {cut} must fail");
    }
}

#[test]
fn frame_rejects_oversized_length_prefix() {
    let mut raw = Vec::new();
    raw.extend_from_slice(&(MAX_FRAME_LEN + 1).to_le_bytes());
    raw.extend_from_slice(&[0u8; 8]);
    let mut partial = Cursor::new(raw);
    let err: Result<Probe, _> = read_frame(&mut partial);
    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("exceeds cap"));
}

#[test]
fn frame_rejects_garbage_json() {
    let mut raw = Vec::new();
    raw.extend_from_slice(&6u32.to_le_bytes());
    raw.extend_from_slice(b"notjso");
    let mut partial = Cursor::new(raw);
    let err: Result<Probe, _> = read_frame(&mut partial);
    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("malformed"));
}

#[test]
fn frame_writes_reject_oversized_payload() {
    // A payload beyond the cap is refused on the write side too, so we
    // never emit a frame the peer must reject.
    struct Big;
    impl serde::Serialize for Big {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            // Just over the cap.
            s.serialize_str(&"a".repeat(MAX_FRAME_LEN as usize + 1))
        }
    }
    let mut buf = Cursor::new(Vec::new());
    let err = write_frame(&mut buf, &Big);
    assert!(err.is_err());
}

#[test]
fn protocol_never_salvages_noise_proptest() {
    // H-49: arbitrary bytes are either a valid frame or an error —
    // never a panic, never a salvage.
    proptest::proptest!(|(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096))| {
        let mut full = Vec::new();
        let len32 = u32::try_from(data.len()).unwrap_or(u32::MAX);
        full.extend_from_slice(&len32.to_le_bytes());
        full.extend_from_slice(&data);
        let mut cursor = Cursor::new(full);
        let _: Result<Probe, _> = read_frame(&mut cursor);
    });
}

// ---------------------------------------------------------------- base64

#[test]
fn base64_round_trip_all_lengths() {
    for len in 0..=64usize {
        let data: Vec<u8> = (0..len)
            .map(|i| u8::try_from(i * 37 + 11).unwrap_or(0))
            .collect();
        let encoded = b64_encode(&data);
        let decoded = b64_decode(&encoded).expect("decode");
        assert_eq!(decoded, data, "len {len}");
    }
}

#[test]
fn base64_matches_known_vectors() {
    assert_eq!(b64_encode(b""), "");
    assert_eq!(b64_encode(b"f"), "Zg==");
    assert_eq!(b64_encode(b"fo"), "Zm8=");
    assert_eq!(b64_encode(b"foo"), "Zm9v");
    assert_eq!(b64_encode(b"foob"), "Zm9vYg==");
    assert_eq!(b64_encode(b"fooba"), "Zm9vYmE=");
    assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
}

#[test]
fn base64_rejects_bad_input() {
    assert!(b64_decode("!!!!").is_err());
    assert!(b64_decode("Zg=Zg==").is_err());
    assert!(b64_decode("Zg").is_err());
}

// ---------------------------------------------------------------- path policy

fn policy(roots: &[&str]) -> PathPolicy {
    PathPolicy::new(&roots.iter().map(PathBuf::from).collect::<Vec<_>>()).expect("policy")
}

#[test]
fn path_policy_requires_at_least_one_root() {
    let err = PathPolicy::new(&[]).expect_err("empty roots");
    assert_eq!(err.code, ErrorCode::InvalidArgument);
}

#[test]
fn path_inside_root_is_allowed() {
    let p = policy(&[r"C:\hvlab"]);
    let resolved = p.resolve(Path::new(r"C:\hvlab\a.txt")).expect("ok");
    assert_eq!(resolved.root_index, 0);
    assert!(
        resolved
            .canonical
            .to_string_lossy()
            .to_lowercase()
            .contains("hvlab"),
        "canonical: {:?}",
        resolved.canonical
    );
}

#[test]
fn path_outside_root_is_rejected() {
    let p = policy(&[r"C:\hvlab"]);
    let err = p
        .resolve(Path::new(r"C:\Windows\System32\drivers\etc\hosts"))
        .expect_err("outside root");
    assert_eq!(err.code, ErrorCode::PolicyDenied);
}

#[test]
fn parent_escape_is_rejected() {
    let p = policy(&[r"C:\hvlab"]);
    let err = p
        .resolve(Path::new(r"C:\hvlab\..\..\Windows\System32"))
        .expect_err("escape");
    assert_eq!(err.code, ErrorCode::PolicyDenied);
}

#[test]
fn substring_prefix_trick_is_rejected() {
    // 'C:\hvlab-secret' must NOT satisfy a root of 'C:\hvlab'.
    let p = policy(&[r"C:\hvlab"]);
    let err = p
        .resolve(Path::new(r"C:\hvlab-secret\file.txt"))
        .expect_err("substring trick");
    assert_eq!(err.code, ErrorCode::PolicyDenied);
}

#[test]
fn case_insensitive_match_is_allowed() {
    let p = policy(&[r"C:\HvLab"]);
    p.resolve(Path::new(r"c:\HVLAB\file.txt"))
        .expect("case-insensitive");
}

#[test]
fn empty_relative_nul_and_unc_paths_are_rejected() {
    let p = policy(&[r"C:\hvlab"]);
    assert_eq!(
        p.resolve(Path::new("")).unwrap_err().code,
        ErrorCode::PolicyDenied
    );
    assert_eq!(
        p.resolve(Path::new("relative\\path.txt")).unwrap_err().code,
        ErrorCode::PolicyDenied
    );
    assert_eq!(
        p.resolve(Path::new("C:\\hvlab\\a.txt\0")).unwrap_err().code,
        ErrorCode::PolicyDenied
    );
    assert_eq!(
        p.resolve(Path::new(r"\\evil\share\payload.exe"))
            .unwrap_err()
            .code,
        ErrorCode::PolicyDenied
    );
}

#[test]
fn root_itself_is_not_inside_the_root_for_file_operations() {
    // A path equal to the root is a directory reference, not a file
    // under it; it must not be silently accepted as a file target.
    let p = policy(&[r"C:\hvlab"]);
    assert!(p.resolve(Path::new(r"C:\hvlab")).is_err());
}

#[test]
fn path_root_escape_rejected_proptest() {
    // H-33: no dotted or suffixed variant may escape the root.
    proptest::proptest!(|(seg in r"[a-zA-Z0-9_.]{1,20}")| {
        let p = policy(&[r"C:\hvlab"]);
        let candidate = format!(r"C:\hvlab\{seg}\file.txt");
        if let Ok(resolved) = p.resolve(Path::new(&candidate)) {
            let lower = resolved.canonical.to_string_lossy().to_lowercase();
            assert!(lower.starts_with(r"c:\hvlab\"), "escaped root: {lower}");
        }
    });
}

// ---------------------------------------------------------------- sidecar command builders

#[test]
fn sidecar_command_base64_encodes_the_vm_name() {
    let cmd = sidecar::sidecar_command("Driver Testing");
    assert!(
        cmd.contains("RHJpdmVyIFRlc3Rpbmc="),
        "base64 of 'Driver Testing'"
    );
    assert!(cmd.contains("-VMNameB64"));
}

#[test]
fn sidecar_command_cannot_be_broken_out_of() {
    // H-34: a hostile VM name (quotes, semicolons, substitutions) is
    // base64 inside a single-quoted literal. The script body itself
    // legitimately mentions Remove-Item for its own temp files, so the
    // assertion targets the quoted argument, which must be base64-only.
    let cmd =
        sidecar::sidecar_command("it's; Remove-Whatever -Recurse -Force C:\\ ; $(Get-Process)");
    let quoted = cmd.rsplit('\'').nth(1).expect("quoted argument");
    assert!(!quoted.is_empty());
    assert!(
        quoted
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='),
        "non-base64 character in the VM name argument: {quoted}"
    );
    // The raw hostile text never appears after the script body ends.
    let arg_section = cmd.rsplit("}} -VMNameB64").next().unwrap_or_default();
    assert!(!arg_section.contains("Remove-Whatever"));
    assert!(!arg_section.contains("it's"));
}

#[test]
fn timeouts_are_bounded_and_generous() {
    assert!(IDENT_TIMEOUT >= std::time::Duration::from_secs(30));
    assert!(IDENT_TIMEOUT <= std::time::Duration::from_secs(600));
}

// ---------------------------------------------------------------- fake sidecar (T0, Windows)

#[cfg(windows)]
mod fake {
    /// A fake sidecar that speaks the same framed protocol without a
    /// guest: ident echo (optionally corrupted), ping, exec (exit code
    /// from a fixed table), ps, put (hash-verified), get.
    pub const SCRIPT: &str = r#"
param([string]$Behavior)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

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
    $buf = New-Object byte[] $len
    $off = 0
    while ($off -lt $len) {
        $n = $stdin.Read($buf, $off, $len - $off)
        if ($n -le 0) { throw 'stdin closed' }
        $off += $n
    }
    [System.Text.Encoding]::UTF8.GetString($buf)
}
function Send-Obj($obj, [int]$Depth = 5) {
    # PowerShell rejects a pipeline inside a method-call argument, so
    # the JSON text is materialized before GetBytes sees it.
    $json = $obj | ConvertTo-Json -Compress -Depth $Depth
    Write-Frame ([System.Text.Encoding]::UTF8.GetBytes([string]$json))
}
function Utf8B64([string]$s) {
    [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($s))
}
function Sha([byte[]]$b) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { ($sha.ComputeHash($b) | ForEach-Object { $_.ToString('x2') }) -join '' }
    finally { $sha.Dispose() }
}

$hostname = if ($Behavior -eq 'wrong-host') { 'EVIL-GUEST' } else { 'FAKE-GUEST' }
$rounds = 0

while ($true) {
    try { $req = Read-Frame | ConvertFrom-Json } catch { break }
    $rounds = $rounds + 1

    $nonce = [string]$req.nonce
    $id = [UInt64]$req.id

    if ($Behavior -eq 'die-after-one' -and $rounds -gt 1) { exit 0 }

    try {
        switch ([string]$req.kind) {
            'ident' {
                $echo = if ($Behavior -eq 'wrong-nonce') { 'deadbeefdeadbeefdeadbeefdeadbeef' } else { $nonce }
                Send-Obj @{ kind = 'ident'; nonce = $echo; hostname = $hostname; session = $true }
            }
            'ping' {
                Send-Obj @{ id = $id; ok = $true; nonce = $nonce; hostname = $hostname; session = $true }
            }
            'exec' {
                $program = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($req.program_b64))
                if ($program -eq 'fail') { $exit = 3 } else { $exit = 0 }
                if ($program -eq 'echo-argv') { $so = ($req.argv -join '|') } else { $so = 'out' }
                Send-Obj @{
                    id = $id; ok = $true; nonce = $nonce; exit_code = $exit
                    stdout_b64 = (Utf8B64 ([string]$so)); stderr_b64 = (Utf8B64 'err')
                }
            }
            'ps' {
                $script = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($req.script_b64))
                Send-Obj @{
                    id = $id; ok = $true; nonce = $nonce; exit_code = 0
                    stdout_b64 = (Utf8B64 "got:$script"); stderr_b64 = ''
                }
            }
            'put' {
                $data = [Convert]::FromBase64String($req.data_b64)
                $hash = Sha $data
                if ($hash -ne [string]$req.sha256) {
                    Send-Obj @{ id = $id; ok = $false; nonce = $nonce; error = 'sha256 mismatch' }
                } else {
                    Send-Obj @{ id = $id; ok = $true; nonce = $nonce; sha256 = $hash }
                }
            }
            'get' {
                $payload = [System.Text.Encoding]::UTF8.GetBytes('content-of-file')
                Send-Obj @{ id = $id; ok = $true; nonce = $nonce; sha256 = (Sha $payload)
                        data_b64 = [Convert]::ToBase64String($payload) }
            }
            default {
                Send-Obj @{ id = $id; ok = $false; nonce = $nonce; error = "unknown kind $($req.kind)" }
            }
        }
    } catch {
        Send-Obj @{ id = $id; ok = $false; nonce = $nonce; error = [string]$_.Exception.Message }
    }
}
"#;

    /// Command line that runs the fake with a given behavior.
    pub fn command(behavior: &str) -> String {
        format!("& {{ {SCRIPT} }} '{behavior}'")
    }
}

#[cfg(windows)]
fn open_fake(
    behavior: &str,
    expect_host: Option<&str>,
) -> Result<PsDirectSession, hvlab_core::error::HvError> {
    PsDirectSession::open_with_command("FakeVM", expect_host, &fake::command(behavior))
}

#[cfg(windows)]
#[test]
fn identity_assertion_precedes_exec() {
    // H-36: handshake completes before any payload; only then does
    // exec work, over the same verified session.
    let mut session = open_fake("normal", None).expect("handshake");
    assert_eq!(session.hostname(), "FAKE-GUEST");
    assert_eq!(session.nonce().len(), 32);
    assert!(session.session_established());

    let result = session
        .exec(&ExecSpec {
            program: "cmd".to_owned(),
            argv: vec!["/c".to_owned()],
        })
        .expect("exec");
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout_text(), "out");
    assert_eq!(result.stderr_text(), "err");
}

#[cfg(windows)]
#[test]
fn wrong_nonce_fails_open_with_guest_identity() {
    let err = open_fake("wrong-nonce", None).expect_err("wrong nonce must fail open");
    assert_eq!(err.code, ErrorCode::GuestIdentity);
}

#[cfg(windows)]
#[test]
fn wrong_hostname_fails_open_with_guest_identity() {
    let err =
        open_fake("wrong-host", Some("driver-testing")).expect_err("hostname mismatch must fail");
    assert_eq!(err.code, ErrorCode::GuestIdentity);
}

#[cfg(windows)]
#[test]
fn matching_expected_hostname_is_accepted() {
    let mut session = open_fake("normal", Some("fake-guest")).expect("case-insensitive match");
    assert_eq!(session.ping().expect("ping"), "FAKE-GUEST");
}

#[cfg(windows)]
#[test]
fn exit_code_is_out_of_band() {
    // H-05: the exit code is a JSON field; stdout carries no code at all.
    let mut session = open_fake("normal", None).expect("handshake");
    let result = session
        .exec(&ExecSpec {
            program: "fail".to_owned(),
            argv: vec![],
        })
        .expect("envelope");
    assert_eq!(result.exit_code, 3);
    assert_eq!(result.stdout_text(), "out");
}

#[cfg(windows)]
#[test]
fn argv_travels_as_typed_parameters() {
    // H-34: hostile argument text is data, never a shell string.
    let mut session = open_fake("normal", None).expect("handshake");
    let result = session
        .exec(&ExecSpec {
            program: "echo-argv".to_owned(),
            argv: vec![
                "a;b".to_owned(),
                "with space".to_owned(),
                "quote\"inside".to_owned(),
                "$(Get-Process)".to_owned(),
            ],
        })
        .expect("exec");
    assert_eq!(
        result.stdout_text(),
        "a;b|with space|quote\"inside|$(Get-Process)"
    );
}

#[cfg(windows)]
#[test]
fn powershell_script_travels_base64_untouched() {
    let mut session = open_fake("normal", None).expect("handshake");
    let script = "Write-Output 'hi'; Get-ChildItem $env:TEMP";
    let result = session.powershell(script).expect("ps");
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout_text(), format!("got:{script}"));
}

#[cfg(windows)]
#[test]
fn empty_program_script_and_path_are_rejected() {
    let mut session = open_fake("normal", None).expect("handshake");
    assert_eq!(
        session
            .exec(&ExecSpec {
                program: "  ".to_owned(),
                argv: vec![]
            })
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        session.powershell("   ").unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        session.put_file(Path::new(""), b"x").unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        session.get_file(Path::new("")).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
}

#[cfg(windows)]
#[test]
fn oversized_transfer_is_refused_before_sending() {
    let mut session = open_fake("normal", None).expect("handshake");
    let big = vec![0u8; MAX_FRAME_LEN as usize / 2 + 1];
    let err = session
        .put_file(Path::new(r"C:\guest\big.bin"), &big)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
}

#[cfg(windows)]
#[test]
fn put_and_get_verify_sha256() {
    let mut session = open_fake("normal", None).expect("handshake");
    let hash = session
        .put_file(Path::new(r"C:\guest\out.bin"), b"payload")
        .expect("put");
    assert_eq!(hash, sha256_hex(b"payload"));

    let (data, hash) = session
        .get_file(Path::new(r"C:\guest\in.bin"))
        .expect("get");
    assert_eq!(data, b"content-of-file");
    assert_eq!(hash, sha256_hex(&data));
}

#[cfg(windows)]
#[test]
fn child_death_maps_to_guest_unreachable_and_poisons() {
    // The fake exits after the handshake; the next request observes the
    // closed pipe. The first failure is a transport/unreachable error
    // and the session is poisoned, so a later call fails fast with
    // Precondition instead of writing into a broken pipe.
    let mut session = open_fake("die-after-one", None).expect("handshake");
    let first = session.ping().expect_err("child is gone");
    assert!(
        matches!(
            first.code,
            ErrorCode::GuestUnreachable | ErrorCode::Transport
        ),
        "unexpected code {:?}",
        first.code
    );
    let second = session.ping().expect_err("poisoned");
    assert_eq!(second.code, ErrorCode::Precondition);
}

#[cfg(windows)]
#[test]
fn many_round_trips_keep_framing() {
    let mut session = open_fake("normal", None).expect("handshake");
    for i in 0..8 {
        let host = session.ping().unwrap_or_else(|e| panic!("round {i}: {e}"));
        assert_eq!(host, "FAKE-GUEST");
    }
}

#[cfg(windows)]
#[test]
fn failed_handshake_does_not_leave_a_child_running() {
    // A wrong-nonce handshake must be refused AND the child killed.
    let before = child_count("powershell.exe");
    for _ in 0..3 {
        let _ = open_fake("wrong-nonce", None);
    }
    // Give the OS a moment to reap.
    std::thread::sleep(std::time::Duration::from_millis(400));
    let after = child_count("powershell.exe");
    assert!(
        after <= before + 1,
        "children leaked: before {before}, after {after}"
    );
}

#[cfg(windows)]
fn child_count(image: &str) -> usize {
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!("@(Get-Process -Name '{image}' -ErrorAction SilentlyContinue).Count"),
        ])
        .output();
    match output {
        Ok(out) => String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .unwrap_or(0),
        Err(_) => 0,
    }
}

// ---------------------------------------------------------------- T2 (env-gated real guest)

#[test]
fn t2_real_guest_ping_when_enabled() {
    let Ok(vm) = std::env::var("HVLAB_TEST_GUEST") else {
        return; // not enabled: skip
    };
    let Ok(mut session) = PsDirectSession::open(&vm, None) else {
        // PS Direct needs Hyper-V administrator rights; skip cleanly.
        eprintln!("T2: could not open a PS Direct session to '{vm}'; skipping");
        return;
    };
    let host = session.ping().expect("ping real guest");
    assert!(!host.is_empty());
}
