//! PS Direct sidecar channel.
//!
//! A persistent `powershell.exe` child on the host holds one remote
//! session into a guest and serves framed requests. Identity is
//! asserted with a per-session nonce BEFORE any payload is sent
//! (H-36): the sidecar must echo the exact nonce — and match the
//! expected hostname when one is given — before `exec`/`put`/`get` are
//! allowed. Exit codes travel as structured JSON fields, never scraped
//! from output (H-05). File transfers are SHA-256 verified on both
//! sides (H-08). Payload is NEVER executed on the host: a request that
//! arrives without an established guest session is refused, not run
//! locally.

use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::protocol::{FrameError, MAX_FRAME_LEN, read_frame, write_frame};
use crate::sidecar::sidecar_command;
use hvlab_core::error::{ErrorCode, HvError};

/// `CREATE_NO_WINDOW`: children never get a console window (H-20).
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Bound on the captured stderr tail (H-27).
const STDERR_TAIL_CAP: usize = 4096;

/// How long `open` waits for the identity handshake.
pub const IDENT_TIMEOUT: Duration = Duration::from_secs(90);

/// Default per-request deadline for a session.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

#[cfg(windows)]
use std::os::windows::process::CommandExt as _;

/// Arguments for one exec request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecSpec {
    /// Program on the guest. Travels as base64 data, never a shell string.
    pub program: String,
    /// Argument vector. Quoted with Win32 argv rules inside the guest.
    pub argv: Vec<String>,
}

/// One completed exec: exit code is out-of-band, streams are base64.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    /// Guest process exit code, taken from the JSON envelope (H-05).
    pub exit_code: i32,
    /// Base64-encoded guest stdout.
    pub stdout_b64: String,
    /// Base64-encoded guest stderr.
    pub stderr_b64: String,
    /// True when the guest process was killed at the sidecar's deadline
    /// or when a kill request was issued.
    #[serde(default)]
    pub timed_out: bool,
}

impl ExecResult {
    /// Decode stdout.
    ///
    /// # Errors
    /// [`HvError`] with code `Internal` when the base64 is malformed.
    pub fn stdout(&self) -> Result<Vec<u8>, HvError> {
        b64_decode(&self.stdout_b64)
    }

    /// Decode stderr.
    ///
    /// # Errors
    /// [`HvError`] with code `Internal` when the base64 is malformed.
    pub fn stderr(&self) -> Result<Vec<u8>, HvError> {
        b64_decode(&self.stderr_b64)
    }

    /// Decode stdout as (lossy) UTF-8 text.
    #[must_use]
    pub fn stdout_text(&self) -> String {
        let bytes = self.stdout().unwrap_or_default();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Decode stderr as (lossy) UTF-8 text.
    #[must_use]
    pub fn stderr_text(&self) -> String {
        let bytes = self.stderr().unwrap_or_default();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

/// Outbound request envelope. Everything variable is base64 so no
/// payload text can ever be spliced into a command line (H-34).
#[derive(Debug, Clone, Serialize)]
struct Request {
    id: u64,
    kind: String,
    nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    program_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    argv: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    script_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_b64: Option<String>,
}

impl Request {
    fn new(id: u64, kind: &str, nonce: &str) -> Self {
        Self {
            id,
            kind: kind.to_owned(),
            nonce: nonce.to_owned(),
            program_b64: None,
            argv: None,
            timeout_ms: None,
            script_b64: None,
            path: None,
            sha256: None,
            data_b64: None,
        }
    }
}

/// Response envelope from the sidecar.
#[derive(Debug, Clone, Deserialize)]
struct Response {
    #[serde(default)]
    id: u64,
    #[serde(default)]
    nonce: String,
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    session: Option<bool>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    exit_code: Option<i32>,
    #[serde(default)]
    stdout_b64: Option<String>,
    #[serde(default)]
    stderr_b64: Option<String>,
    #[serde(default)]
    timed_out: Option<bool>,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    data_b64: Option<String>,
}

/// A live sidecar session with a verified guest identity.
pub struct PsDirectSession {
    child: Child,
    stdin: BufWriter<ChildStdin>,
    rx: Receiver<Result<Response, FrameError>>,
    reader: Option<JoinHandle<()>>,
    stderr_tail: Arc<Mutex<Vec<u8>>>,
    stderr_thread: Option<JoinHandle<()>>,
    nonce: String,
    hostname: String,
    expected_hostname: Option<String>,
    session_established: bool,
    request_timeout: Duration,
    dead: bool,
    next_id: u64,
}

impl std::fmt::Debug for PsDirectSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PsDirectSession")
            .field("nonce", &self.nonce)
            .field("hostname", &self.hostname)
            .field("session_established", &self.session_established)
            .field("dead", &self.dead)
            .finish_non_exhaustive()
    }
}

fn spawn_error(vm: &str, detail: impl std::fmt::Display) -> HvError {
    HvError::new(
        ErrorCode::GuestUnreachable,
        format!("PS Direct sidecar for VM '{vm}' failed: {detail}"),
    )
    .with_context("vm", vm)
}

/// Drain a pipe into a bounded in-memory tail so error reporting never
/// blocks on a live child (H-27).
fn drain_tail(pipe: ChildStderr, sink: &Arc<Mutex<Vec<u8>>>) {
    let mut reader = BufReader::new(pipe);
    let mut chunk = [0u8; 512];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if let Ok(mut buf) = sink.lock() {
                    buf.extend_from_slice(&chunk[..n]);
                    let overflow = buf.len().saturating_sub(STDERR_TAIL_CAP);
                    if overflow > 0 {
                        buf.drain(..overflow);
                    }
                }
            }
        }
    }
}

/// Standard base64 encoding (RFC 4648, with padding).
#[must_use]
pub fn b64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        out.push(TABLE[(n >> 18 & 0x3f) as usize] as char);
        out.push(TABLE[(n >> 12 & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6 & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Standard base64 decoding; whitespace-tolerant, padding-checked.
///
/// # Errors
/// [`HvError`] with code `Internal` on non-base64 characters, bad
/// padding, or a length that is not a multiple of four.
#[allow(clippy::cast_possible_truncation)] // shifts of a 24-bit window into u8 are exact
pub fn b64_decode(s: &str) -> Result<Vec<u8>, HvError> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        if chunk.len() != 4 {
            return Err(HvError::new(
                ErrorCode::Internal,
                "invalid base64: bad chunk length",
            ));
        }
        let mut n = 0u32;
        let mut pad = 0usize;
        for &c in chunk {
            if c == b'=' {
                pad += 1;
                n <<= 6;
            } else {
                if pad > 0 {
                    return Err(HvError::new(
                        ErrorCode::Internal,
                        "invalid base64: padding in the middle",
                    ));
                }
                let v = val(c)
                    .ok_or_else(|| HvError::new(ErrorCode::Internal, "invalid base64 character"))?;
                n = (n << 6) | v;
            }
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

/// SHA-256 of `data` as lower-case hex.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut s = String::with_capacity(64);
    for byte in digest {
        let hex = format!("{byte:02x}");
        s.push_str(&hex);
    }
    s
}

impl PsDirectSession {
    /// Open a PS Direct session to `vm_name` through the embedded
    /// sidecar, which creates the persistent guest session before the
    /// first request is served.
    ///
    /// # Errors
    /// Same surface as [`Self::open_with_command`].
    pub fn open(vm_name: &str, expected_hostname: Option<&str>) -> Result<Self, HvError> {
        Self::open_with_command(vm_name, expected_hostname, &sidecar_command(vm_name))
    }

    /// Open with an arbitrary sidecar command line — the seam hermetic
    /// tests use to substitute a fake sidecar that speaks the same
    /// framed protocol.
    ///
    /// # Errors
    /// [`HvError`] with `GuestUnreachable` when the sidecar cannot be
    /// spawned or dies during the handshake, `GuestIdentity` when the
    /// nonce or hostname assertion fails, `Timeout` when no identity
    /// response arrives in time.
    pub fn open_with_command(
        vm_name: &str,
        expected_hostname: Option<&str>,
        loop_cmd: &str,
    ) -> Result<Self, HvError> {
        if vm_name.trim().is_empty() {
            return Err(HvError::new(ErrorCode::InvalidArgument, "vm_name is empty"));
        }
        if loop_cmd.trim().is_empty() {
            return Err(HvError::new(
                ErrorCode::InvalidArgument,
                "sidecar command is empty",
            ));
        }

        let mut child = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                loop_cmd,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(CREATE_NO_WINDOW) // H-20
            .spawn()
            .map_err(|e| spawn_error(vm_name, format!("failed to spawn sidecar: {e}")))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| spawn_error(vm_name, "child stdin not piped"))?;
        let stdout: ChildStdout = child
            .stdout
            .take()
            .ok_or_else(|| spawn_error(vm_name, "child stdout not piped"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| spawn_error(vm_name, "child stderr not piped"))?;

        // Reader thread: frames arrive on a channel so every wait has a
        // real deadline instead of a blocking pipe read.
        let (tx, rx) = channel();
        let reader = thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let frame: Result<Response, FrameError> = read_frame(&mut reader);
                let stop = frame.is_err();
                if tx.send(frame).is_err() || stop {
                    break;
                }
            }
        });

        let stderr_tail = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&stderr_tail);
        let stderr_thread = thread::spawn(move || drain_tail(stderr, &sink));

        let mut session = Self {
            child,
            stdin: BufWriter::new(stdin),
            rx,
            reader: Some(reader),
            stderr_tail,
            stderr_thread: Some(stderr_thread),
            nonce: String::new(),
            hostname: String::new(),
            expected_hostname: expected_hostname.map(str::to_owned),
            session_established: false,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            dead: false,
            next_id: 0,
        };
        if let Err(e) = session.handshake(vm_name) {
            session.kill_and_wait();
            return Err(e);
        }
        Ok(session)
    }

    /// Set the per-request deadline used by `exec`/`powershell`/file
    /// transfers.
    pub fn set_request_timeout(&mut self, timeout: Duration) {
        self.request_timeout = timeout;
    }

    /// Identity assertion (H-36): the sidecar must echo the exact nonce
    /// and hostname before any payload is sent.
    fn handshake(&mut self, vm_name: &str) -> Result<(), HvError> {
        self.nonce = Uuid::now_v7().simple().to_string();
        let req = Request::new(0, "ident", &self.nonce);
        write_frame(&mut self.stdin, &req)
            .map_err(|e| spawn_error(vm_name, format!("failed writing ident: {e}")))?;
        self.stdin
            .flush()
            .map_err(|e| spawn_error(vm_name, format!("failed flushing ident: {e}")))?;

        let resp = self.await_response(IDENT_TIMEOUT, vm_name)?;
        if resp.nonce != self.nonce {
            return Err(HvError::new(
                ErrorCode::GuestIdentity,
                "identity nonce mismatch: the sidecar did not echo the session nonce",
            )
            .with_context("vm", vm_name));
        }
        let hostname = resp.hostname.clone().unwrap_or_default();
        if hostname.is_empty() {
            return Err(HvError::new(
                ErrorCode::GuestIdentity,
                "sidecar did not report a hostname",
            ));
        }
        if let Some(expect) = &self.expected_hostname
            && !hostname.eq_ignore_ascii_case(expect)
        {
            return Err(HvError::new(
                ErrorCode::GuestIdentity,
                format!("hostname mismatch: expected '{expect}', sidecar reported '{hostname}'"),
            ));
        }
        self.hostname = hostname;
        self.session_established = resp.session.unwrap_or(false);
        Ok(())
    }

    /// Wait for the next response frame, bounded by `timeout`.
    ///
    /// # Errors
    /// `Transport` on a malformed frame, `Timeout` when the sidecar is
    /// silent, `GuestUnreachable` when the sidecar process is gone.
    fn await_response(&mut self, timeout: Duration, vm_name: &str) -> Result<Response, HvError> {
        match self.rx.recv_timeout(timeout) {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(frame_err)) => {
                self.dead = true;
                Err(HvError::new(
                    ErrorCode::Transport,
                    format!("sidecar sent a malformed frame: {frame_err}"),
                ))
            }
            Err(RecvTimeoutError::Timeout) => {
                self.dead = true;
                Err(HvError::new(
                    ErrorCode::Timeout,
                    format!("sidecar did not answer within {timeout:?}"),
                )
                .with_context("vm", vm_name))
            }
            Err(RecvTimeoutError::Disconnected) => {
                self.dead = true;
                let tail = self.stderr_text();
                let message = if tail.trim().is_empty() {
                    "sidecar exited without answering".to_owned()
                } else {
                    format!("sidecar exited without answering: {}", tail.trim())
                };
                Err(HvError::new(ErrorCode::GuestUnreachable, message))
            }
        }
    }

    /// The captured tail of the child's stderr (non-blocking).
    #[must_use]
    pub fn stderr_text(&self) -> String {
        self.stderr_tail
            .lock()
            .map(|buf| String::from_utf8_lossy(&buf).into_owned())
            .unwrap_or_default()
    }

    fn poisoned(err: HvError) -> HvError {
        err.with_context("session", "poisoned: closed for further use")
    }

    /// Send one request and read its response. Any transport problem
    /// poisons the session: the framing may be desynchronized.
    fn round_trip(
        &mut self,
        kind: &str,
        build: impl FnOnce(&mut Request),
        timeout: Duration,
    ) -> Result<Response, HvError> {
        if self.dead {
            return Err(HvError::new(
                ErrorCode::Precondition,
                "session is closed after an earlier failure",
            ));
        }
        if requires_guest_session(kind) && !self.session_established {
            return Err(HvError::new(
                ErrorCode::Precondition,
                "no guest session is established: refusing to run the payload on the host",
            ));
        }
        self.next_id = self.next_id.saturating_add(1);
        let id = self.next_id;
        let mut req = Request::new(id, kind, &self.nonce);
        build(&mut req);
        if write_frame(&mut self.stdin, &req).is_err() || self.stdin.flush().is_err() {
            self.dead = true;
            return Err(Self::poisoned(HvError::new(
                ErrorCode::Transport,
                "failed writing request to the sidecar",
            )));
        }
        let resp = self.await_response(timeout, &self.hostname.clone())?;
        if resp.id != id {
            self.dead = true;
            return Err(Self::poisoned(HvError::new(
                ErrorCode::Transport,
                format!("response id {} does not match request {id}", resp.id),
            )));
        }
        if resp.nonce != self.nonce {
            self.dead = true;
            return Err(Self::poisoned(HvError::new(
                ErrorCode::GuestIdentity,
                "response nonce mismatch: the framing may be desynchronized",
            )));
        }
        Ok(resp)
    }

    /// Run `program` with `argv` on the guest. The per-request deadline
    /// is enforced inside the guest by the sidecar, which terminates
    /// the process it started.
    ///
    /// # Errors
    /// `InvalidArgument` when the program is empty, `Timeout` when the
    /// guest process hit the deadline, `GuestFailed` when the sidecar
    /// reports an error, `GuestIdentity` on a nonce mismatch, and
    /// `Precondition` on a poisoned session (or when no guest session
    /// exists), plus `Transport`/`GuestUnreachable` failures.
    pub fn exec(&mut self, spec: &ExecSpec) -> Result<ExecResult, HvError> {
        self.exec_with_timeout(spec, self.request_timeout)
    }

    /// `exec` with an explicit guest-side deadline.
    ///
    /// # Errors
    /// `InvalidArgument` when the program is empty, `Timeout` when the
    /// guest process hit the deadline, `GuestFailed` when the sidecar
    /// reports an error, `GuestIdentity` on a nonce mismatch, and the
    /// poisoned-session/transport failures of [`Self::exec`].
    pub fn exec_with_timeout(
        &mut self,
        spec: &ExecSpec,
        timeout: Duration,
    ) -> Result<ExecResult, HvError> {
        if spec.program.trim().is_empty() {
            return Err(HvError::new(ErrorCode::InvalidArgument, "program is empty"));
        }
        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        let resp = self.round_trip(
            "exec",
            |req| {
                req.program_b64 = Some(b64_encode(spec.program.as_bytes()));
                req.argv = Some(spec.argv.clone());
                req.timeout_ms = Some(timeout_ms);
            },
            timeout.saturating_add(REQUEST_OVERHEAD),
        )?;
        finish_exec(resp)
    }

    /// Run a PowerShell script on the guest. The script travels
    /// base64-encoded in the JSON envelope and is compiled on the guest,
    /// never interpolated into a host command line (H-34).
    ///
    /// # Errors
    /// `InvalidArgument` when the script is empty; otherwise the same
    /// error surface as [`Self::exec`].
    pub fn powershell(&mut self, script: &str) -> Result<ExecResult, HvError> {
        self.powershell_with_timeout(script, self.request_timeout)
    }

    /// Run a PowerShell script with an explicit deadline.
    ///
    /// # Errors
    /// `InvalidArgument` when the script is empty; otherwise the same
    /// error surface as [`Self::exec`].
    pub fn powershell_with_timeout(
        &mut self,
        script: &str,
        timeout: Duration,
    ) -> Result<ExecResult, HvError> {
        if script.trim().is_empty() {
            return Err(HvError::new(ErrorCode::InvalidArgument, "script is empty"));
        }
        let resp = self.round_trip(
            "ps",
            |req| {
                req.script_b64 = Some(b64_encode(script.as_bytes()));
                req.timeout_ms = Some(u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX));
            },
            timeout.saturating_add(REQUEST_OVERHEAD),
        )?;
        finish_exec(resp)
    }

    /// Liveness probe. Returns the verified guest hostname.
    ///
    /// # Errors
    /// `GuestUnreachable` when the sidecar reports failure or is gone;
    /// poisoned-session `Precondition` after any earlier failure.
    pub fn ping(&mut self) -> Result<String, HvError> {
        let resp = self.round_trip("ping", |_req| {}, self.request_timeout)?;
        if !resp.ok {
            return Err(HvError::new(
                ErrorCode::GuestUnreachable,
                resp.error.unwrap_or_else(|| "ping failed".to_owned()),
            ));
        }
        Ok(resp.hostname.unwrap_or_else(|| self.hostname.clone()))
    }

    /// Copy bytes to a guest file, SHA-256 verified on both sides
    /// (H-08).
    ///
    /// # Errors
    /// `InvalidArgument` for an empty path or a payload beyond the
    /// single-frame limit, `GuestFailed` when the guest-computed hash
    /// disagrees or the sidecar reports an error, plus the transport
    /// and identity failures of [`Self::exec`].
    pub fn put_file(&mut self, path: &Path, data: &[u8]) -> Result<String, HvError> {
        if path.as_os_str().is_empty() {
            return Err(HvError::new(ErrorCode::InvalidArgument, "path is empty"));
        }
        if data.len() > MAX_FRAME_LEN as usize / 2 {
            return Err(HvError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "file of {} bytes exceeds the single-frame transfer limit of {}",
                    data.len(),
                    MAX_FRAME_LEN as usize / 2
                ),
            ));
        }
        let hash = sha256_hex(data);
        let resp = self.round_trip(
            "put",
            |req| {
                req.path = Some(path.to_string_lossy().into_owned());
                req.sha256 = Some(hash.clone());
                req.data_b64 = Some(b64_encode(data));
            },
            self.request_timeout,
        )?;
        if !resp.ok {
            return Err(HvError::new(
                ErrorCode::GuestFailed,
                resp.error.unwrap_or_else(|| "put failed".to_owned()),
            ));
        }
        let remote = resp.sha256.unwrap_or_default();
        if !remote.eq_ignore_ascii_case(&hash) {
            return Err(HvError::new(
                ErrorCode::GuestFailed,
                format!("guest hash mismatch: expected '{hash}', got '{remote}'"),
            ));
        }
        Ok(hash)
    }

    /// Read a guest file, SHA-256 verified against the hash the guest
    /// reported.
    ///
    /// # Errors
    /// `GuestFailed` on hash mismatch or a sidecar error; `Internal`
    /// when the base64 payload is malformed; plus the transport and
    /// identity failures of [`Self::exec`].
    pub fn get_file(&mut self, path: &Path) -> Result<(Vec<u8>, String), HvError> {
        if path.as_os_str().is_empty() {
            return Err(HvError::new(ErrorCode::InvalidArgument, "path is empty"));
        }
        let resp = self.round_trip(
            "get",
            |req| {
                req.path = Some(path.to_string_lossy().into_owned());
            },
            self.request_timeout,
        )?;
        if !resp.ok {
            return Err(HvError::new(
                ErrorCode::GuestFailed,
                resp.error.unwrap_or_else(|| "get failed".to_owned()),
            ));
        }
        let hash = resp.sha256.unwrap_or_default();
        let data = b64_decode(&resp.data_b64.unwrap_or_default())?;
        let computed = sha256_hex(&data);
        if !computed.eq_ignore_ascii_case(&hash) {
            return Err(HvError::new(
                ErrorCode::GuestFailed,
                format!("guest-reported hash mismatch: sidecar '{hash}', computed '{computed}'"),
            ));
        }
        Ok((data, hash))
    }

    /// The nonce verified at handshake.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// The hostname the sidecar reported at handshake.
    #[must_use]
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// Whether the sidecar confirmed a live guest session. When false,
    /// payload requests are refused rather than run on the host.
    #[must_use]
    pub fn session_established(&self) -> bool {
        self.session_established
    }

    fn kill_and_wait(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.stderr_thread.take() {
            let _ = handle.join();
        }
    }
}

/// Execution-control kinds need a live guest session; `ping`/`ident` do
/// not (they are how the host learns whether one exists).
fn requires_guest_session(kind: &str) -> bool {
    matches!(kind, "exec" | "ps" | "put" | "get")
}

/// Slack added to a guest-side deadline before the host gives up.
const REQUEST_OVERHEAD: Duration = Duration::from_secs(15);

fn finish_exec(resp: Response) -> Result<ExecResult, HvError> {
    if !resp.ok {
        return Err(HvError::new(
            ErrorCode::GuestFailed,
            resp.error
                .unwrap_or_else(|| "sidecar reported failure".to_owned()),
        ));
    }
    if resp.timed_out.unwrap_or(false) {
        return Err(HvError::new(
            ErrorCode::Timeout,
            "the guest process was terminated at the sidecar deadline",
        ));
    }
    let exit_code = resp
        .exit_code
        .ok_or_else(|| HvError::new(ErrorCode::Internal, "exec response is missing exit_code"))?;
    Ok(ExecResult {
        exit_code,
        stdout_b64: resp.stdout_b64.unwrap_or_default(),
        stderr_b64: resp.stderr_b64.unwrap_or_default(),
        timed_out: resp.timed_out.unwrap_or(false),
    })
}

impl Drop for PsDirectSession {
    fn drop(&mut self) {
        self.kill_and_wait();
    }
}
