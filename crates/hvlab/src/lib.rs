//! `hvlab` — Hyper-V control plane for agents and humans.
//!
//! Library half of the binary crate: CLI dispatch lives here so
//! integration tests can exercise it without spawning a process.
//! `main.rs` is a thin shell around [`run`].

// `unwrap`/`expect` are legitimate in tests; production code denies them
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

pub mod cli;

/// Dispatch a full argument vector (excluding the program name).
///
/// Returns the process exit code.
#[must_use]
pub fn run(args: &[String]) -> std::process::ExitCode {
    let Some(command) = args.first() else {
        print_usage();
        return std::process::ExitCode::from(2);
    };

    match command.as_str() {
        "dump" => cli::dump(&args[1..]),
        "mcp" => tokio_main(hvlab_mcp::HvlabServer::new().serve_stdio()),
        "doctor" => {
            eprintln!("hvlab doctor: not yet implemented (milestone M2)");
            std::process::ExitCode::from(2)
        }
        "version" | "--version" | "-V" => {
            println!("hvlab {}", env!("CARGO_PKG_VERSION"));
            std::process::ExitCode::SUCCESS
        }
        "help" | "--help" | "-h" => {
            print_usage();
            std::process::ExitCode::SUCCESS
        }
        other => {
            eprintln!("unknown command: {other}\n");
            print_usage();
            std::process::ExitCode::from(2)
        }
    }
}

/// Run `hvlab mcp`: block on the server future, mapping its error to an
/// exit message.
#[allow(clippy::expect_used)] // runtime startup; no meaningful recovery
fn tokio_main(
    fut: impl Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>,
) -> std::process::ExitCode {
    match tokio::runtime::Runtime::new()
        .expect("tokio runtime")
        .block_on(fut)
    {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hvlab mcp: {e}");
            std::process::ExitCode::from(1)
        }
    }
}

/// Print the top-level usage text.
pub fn print_usage() {
    println!(
        "hvlab — Hyper-V control plane for agents and humans

USAGE:
    hvlab <command> [args]

COMMANDS:
    dump inspect <file>   print bugcheck and header fields from a crash dump (< 5 ms)
    mcp                   run the MCP server (stdio)
    doctor                probe environment capabilities [M2]
    version               print version"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    mod run {
        use super::*;

        #[test]
        fn version_exits_success() {
            assert_eq!(run(&args(&["version"])), std::process::ExitCode::SUCCESS);
        }

        #[test]
        fn no_arguments_is_a_usage_error() {
            assert_eq!(run(&[]), std::process::ExitCode::from(2));
        }

        #[test]
        fn unknown_command_is_a_usage_error() {
            assert_eq!(run(&args(&["nope"])), std::process::ExitCode::from(2));
        }

        #[test]
        fn dump_without_verb_is_a_usage_error() {
            assert_eq!(run(&args(&["dump"])), std::process::ExitCode::from(2));
        }
    }
}
