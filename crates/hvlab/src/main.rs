//! Entry point. All logic lives in the library half so it is testable.

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    hvlab::run(&args)
}
