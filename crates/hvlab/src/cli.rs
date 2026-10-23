//! CLI command implementations. Split from `main.rs` so integration
//! tests can call them without spawning a process.

use std::fmt::Write as _;
use std::io::Write;

/// `hvlab dump <verb>`. Returns the process exit code.
pub fn dump(args: &[String]) -> std::process::ExitCode {
    match args.first().map(String::as_str) {
        Some("inspect") => dump_inspect(args.get(1).map(String::as_str)),
        Some(other) => {
            eprintln!("unknown dump verb: {other}\n");
            eprintln!("USAGE: hvlab dump inspect <file>");
            std::process::ExitCode::from(2)
        }
        None => {
            eprintln!("USAGE: hvlab dump inspect <file>");
            std::process::ExitCode::from(2)
        }
    }
}

/// `hvlab dump inspect <file>`: header-only bugcheck extraction.
fn dump_inspect(path: Option<&str>) -> std::process::ExitCode {
    let Some(path) = path else {
        eprintln!("USAGE: hvlab dump inspect <file>");
        return std::process::ExitCode::from(2);
    };

    let header = match hvlab_dump::DumpHeader64::read_from(path) {
        Ok(h) => h,
        Err(e) => {
            // One error per cause, naming the missing artifact (H-02).
            eprintln!("error: {e}");
            return match e {
                hvlab_dump::HeaderError::Io { .. } | hvlab_dump::HeaderError::TooSmall { .. } => {
                    std::process::ExitCode::from(3)
                }
                hvlab_dump::HeaderError::BadSignature { .. }
                | hvlab_dump::HeaderError::BadValidDump { .. }
                | hvlab_dump::HeaderError::ThirtyTwoBit { .. } => std::process::ExitCode::from(4),
                // `HeaderError` is `#[non_exhaustive]`; a new variant is
                // a format we do not understand yet, not a crash.
                _ => std::process::ExitCode::from(5),
            };
        }
    };

    let kind = hvlab_dump::DumpHeader64::read_kind(&header, path)
        .map_or(hvlab_dump::DumpKind::Unknown(u32::MAX), |k| k);

    let mut out = String::new();
    let info = hvlab_dump::bugcheck_name(header.bug_check_code);
    let _ = writeln!(out, "path: {path}");
    let _ = writeln!(
        out,
        "os_version: {}.{}",
        header.os_version.0, header.os_version.1
    );
    let _ = writeln!(out, "dump_kind: {kind}");
    let _ = writeln!(
        out,
        "bugcheck_code: {}",
        hvlab_dump::format_bugcheck_code(header.bug_check_code)
    );
    if let Some(info) = info {
        let _ = writeln!(out, "bugcheck_name: {}", info.name);
        let _ = writeln!(out, "description: {}", info.description);
        let _ = writeln!(out, "reference: {}", info.doc_path);
    }
    for (i, p) in header.bug_check_parameters.iter().enumerate() {
        let _ = writeln!(out, "arg{}: {p:#x}", i + 1);
    }
    let _ = writeln!(
        out,
        "directory_table_base: {:#x}",
        header.directory_table_base
    );
    let _ = writeln!(
        out,
        "kd_debugger_data_block: {:#x}",
        header.kd_debugger_data_block
    );

    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = lock.write_all(out.as_bytes());
    std::process::ExitCode::SUCCESS
}

/// `hvlab tools`: list registered MCP tools with their safety classes.
#[must_use]
pub fn tools() -> std::process::ExitCode {
    let router = hvlab_mcp::HvlabServer::router();
    let mut tools: Vec<(String, String, String)> = router
        .list_all()
        .into_iter()
        .map(|t| {
            let name = t.name.into_owned();
            let class = hvlab_mcp::HvlabServer::tool_class(&name).to_owned();
            let desc = t
                .description
                .map(std::borrow::Cow::into_owned)
                .unwrap_or_default();
            (name, class, desc)
        })
        .collect();
    tools.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = String::new();
    for (name, class, desc) in &tools {
        let _ = writeln!(out, "{class}  {name}  {desc}");
    }
    let _ = write!(
        out,
        "\n{} tools; classes: R read-only, M mutating, D destructive (plan token), X guest code execution (plan token)\n",
        tools.len()
    );
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = lock.write_all(out.as_bytes());
    std::process::ExitCode::SUCCESS
}
