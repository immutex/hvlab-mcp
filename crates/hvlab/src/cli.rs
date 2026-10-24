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
/// `hvlab tools` — the catalogue, one line per tool, showing which are
/// advertised under each profile.
pub fn tools() -> std::process::ExitCode {
    use hvlab_mcp::profile::Profile;
    use hvlab_mcp::registry;

    let router = hvlab_mcp::HvlabServer::router();
    let mut out = String::new();
    let core = Profile::Core;
    let advertised = registry::REGISTRY
        .iter()
        .filter(|m| core.advertises(m.name))
        .count();

    for m in registry::REGISTRY {
        let desc = router
            .get(m.name)
            .and_then(|t| t.description.as_deref())
            .unwrap_or("");
        let marker = if core.advertises(m.name) {
            "core"
        } else {
            "-   "
        };
        let _ = writeln!(
            out,
            "{}  {marker}  {:<24} {:<11} {}",
            m.class.as_str(),
            m.name,
            m.family.as_str(),
            desc
        );
    }
    let _ = write!(
        out,
        "\n{} tools registered; {advertised} advertised by the `core` profile (the rest stay callable by name: \
         see hv_tools_search / hv_tools_describe).\nClasses: R read-only, M mutating, D destructive (plan token), X guest code execution (plan token).\n         Set HVLAB_TOOLS=core|full|readonly or a list of names/families to change what is advertised.\n",
        registry::REGISTRY.len()
    );
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = lock.write_all(out.as_bytes());
    std::process::ExitCode::SUCCESS
}
