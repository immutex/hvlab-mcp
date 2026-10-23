//! Parsing `!analyze -v` output into structured fields.
//!
//! The debugger's text output is the interchange format between tools:
//! an agent may have it in a transcript, a CI job may have it in a log.
//! This parser reads that text the way the engine writes it, without
//! editorializing about what any of it means.

use std::collections::BTreeMap;

/// A single line of output, with surrounding context available.
type Line<'a> = &'a str;

/// A parsed `!analyze -v` report.
///
/// Every field is `Option`: the parser reports what it found, never
/// what it assumed. A field being absent is information.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ParsedAnalyze {
    /// `BUGCHECK_CODE` from the analysis summary.
    pub bugcheck_code: Option<u32>,
    /// The four bugcheck parameters, in order.
    pub bugcheck_parameters: [Option<u64>; 4],
    /// `MODULE_NAME` — the module the analysis blames.
    pub module_name: Option<String>,
    /// `IMAGE_NAME` — the image file name.
    pub image_name: Option<String>,
    /// `FAILURE_BUCKET_ID` — the engine's own classification string.
    pub failure_bucket_id: Option<String>,
    /// `PROCESS_NAME` for the faulting context, when present.
    pub process_name: Option<String>,
    /// `SYMBOL_NAME` when resolved.
    pub symbol_name: Option<String>,
    /// Whether the dump is a user-mode minidump (no bugcheck applies).
    pub user_mode_dump: bool,
    /// Whether symbol resolution appears to have failed or been skipped.
    pub symbols_incomplete: bool,
    /// Stack frames parsed from the `STACK_TEXT` section.
    pub stack_frames: Vec<StackFrame>,
    /// Modules from the `MODULE_LIST` / `lm` output, when present.
    pub modules: Vec<ModuleInfo>,
    /// The `DEFAULT_BUCKET_ID` string.
    pub default_bucket_id: Option<String>,
}

/// One stack frame from `STACK_TEXT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackFrame {
    /// Frame number as printed (`00`, `01`, …).
    pub number: String,
    /// The child-SP column, verbatim.
    pub child_sp: String,
    /// The ret-addr column, verbatim.
    pub ret_addr: Option<String>,
    /// Symbol text, e.g. `nt!KiSwapContext+0x76`.
    pub symbol: String,
    /// Raw args column, when present.
    pub args: Option<String>,
}

/// One module from a module listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleInfo {
    /// Module name, e.g. `nt` or `mydriver`.
    pub name: String,
    /// Load address, verbatim hex string.
    pub base: String,
    /// Module size, verbatim.
    pub size: String,
    /// Timestamp or symbol status, verbatim.
    pub timestamp: Option<String>,
}

/// Errors from parsing `!analyze` text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// The text does not look like `!analyze` output at all.
    #[error(
        "input does not contain an `!analyze` report (no BUGCHECK_CODE, STACK_TEXT, or summary markers)"
    )]
    NotAnalyzeOutput,
}

/// Parse `!analyze -v` text into structured fields.
///
/// Returns [`ParseError::NotAnalyzeOutput`] when the input has none of
/// the section markers, so a caller can distinguish "the analysis found
/// nothing" from "this is not an analysis".
///
/// # Example
///
/// ```
/// let text = "BUGCHECK_CODE:  9f\nMODULE_NAME: mydrv\nSTACK_TEXT: \n00 nt!KiBugCheck\n";
/// let parsed = hvlab_dump::analyze::parse_analyze_text(text).expect("recognizable output");
/// assert_eq!(parsed.bugcheck_code, Some(0x9F));
/// assert_eq!(parsed.module_name.as_deref(), Some("mydrv"));
/// ```
///
/// # Errors
///
/// [`ParseError::NotAnalyzeOutput`] when no section marker is present.
pub fn parse_analyze_text(text: &str) -> Result<ParsedAnalyze, ParseError> {
    let mut parsed = ParsedAnalyze::default();

    let mut section: Option<&str> = None;
    let mut found_marker = false;

    for line in text.lines() {
        let line = line.trim_end();

        // Section markers first: `STACK_TEXT:` looks like a summary
        // line (`KEY: value` with an empty value) and would otherwise
        // swallow the section state.
        if let Some(name) = section_marker(line) {
            found_marker = true;
            section = Some(name);
            continue;
        }

        if let Some((key, value)) = split_summary_line(line) {
            found_marker = true;
            section = None;
            apply_summary_field(&mut parsed, key, value);
            continue;
        }

        match section {
            Some("STACK_TEXT") => {
                if let Some(frame) = parse_stack_frame(line) {
                    parsed.stack_frames.push(frame);
                }
            }
            Some("MODULE_LIST") => {
                if let Some(module) = parse_module_line(line) {
                    parsed.modules.push(module);
                }
            }
            _ => {}
        }
    }

    parsed.user_mode_dump = detect_user_mode(text);
    parsed.symbols_incomplete = detect_symbols_incomplete(text);

    if !found_marker {
        return Err(ParseError::NotAnalyzeOutput);
    }
    Ok(parsed)
}

/// Split a `KEY: value` summary line, or return `None` if this line is
/// not one (wrapped lines, blank lines, section markers).
fn split_summary_line(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once(':')?;
    let key = key.trim();
    if key.is_empty() || key.contains(' ') {
        return None;
    }
    Some((key, value.trim()))
}

/// Recognize a section header line and return its canonical name.
fn section_marker(line: &str) -> Option<&'static str> {
    let trimmed = line.trim();
    if trimmed.eq_ignore_ascii_case("STACK_TEXT") || trimmed.starts_with("STACK_TEXT") {
        return Some("STACK_TEXT");
    }
    if trimmed.starts_with("MODULE_LIST") || trimmed.starts_with("MODULE_LIST:") {
        return Some("MODULE_LIST");
    }
    None
}

fn apply_summary_field(parsed: &mut ParsedAnalyze, key: &str, value: &str) {
    match key {
        "BUGCHECK_CODE" => {
            parsed.bugcheck_code = parse_code(value);
        }
        "BUGCHECK_P1" | "BUGCHECK_P2" | "BUGCHECK_P3" | "BUGCHECK_P4" => {
            let idx = match key {
                "BUGCHECK_P1" => 0,
                "BUGCHECK_P2" => 1,
                "BUGCHECK_P3" => 2,
                _ => 3,
            };
            if idx < 4 {
                parsed.bugcheck_parameters[idx] = parse_u64(value);
            }
        }
        "ARGUMENTS" => {
            // The `Arguments: Arg1: ... Arg2: ...` block; parameters may
            // also arrive here in some engine versions.
            for (i, slot) in parsed.bugcheck_parameters.iter_mut().enumerate() {
                if slot.is_none()
                    && let Some(v) = extract_arg_n(value, i + 1)
                {
                    *slot = Some(v);
                }
            }
        }
        "MODULE_NAME" => parsed.module_name = non_empty(value),
        "IMAGE_NAME" => parsed.image_name = non_empty(value),
        "FAILURE_BUCKET_ID" => parsed.failure_bucket_id = non_empty(value),
        "PROCESS_NAME" => parsed.process_name = non_empty(value),
        "SYMBOL_NAME" => parsed.symbol_name = non_empty(value),
        "DEFAULT_BUCKET_ID" => parsed.default_bucket_id = non_empty(value),
        _ => {}
    }
}

fn non_empty(value: &str) -> Option<String> {
    let v = value.trim();
    (!v.is_empty()).then(|| v.to_owned())
}

/// Parse a bugcheck code. The engine prints these in hex, with or
/// without a `0x` prefix (`BUGCHECK_CODE:  9f`), so a bare value is
/// hex. Anything that is not a clean integer is rejected — no substring
/// games.
fn parse_code(value: &str) -> Option<u32> {
    let v = value.trim().trim_start_matches('(').trim_end_matches(')');
    let hex = v
        .strip_prefix("0x")
        .or_else(|| v.strip_prefix("0X"))
        .unwrap_or(v);
    u32::from_str_radix(hex, 16).ok()
}

fn parse_u64(value: &str) -> Option<u64> {
    let v = value.trim();
    let hex = v.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(hex, 16)
        .or_else(|_| v.parse::<u64>())
        .ok()
}

/// Extract `ArgN: 0x...` from an arguments line.
fn extract_arg_n(line: &str, n: usize) -> Option<u64> {
    let needle = format!("Arg{n}:");
    let start = line.find(&needle)? + needle.len();
    let rest = line[start..].trim();
    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    parse_u64(&rest[..end])
}

/// Parse one `STACK_TEXT` frame line.
fn parse_stack_frame(line: Line<'_>) -> Option<StackFrame> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.split_whitespace();
    let number = parts.next()?.to_owned();
    // Frame numbers are two hex-ish digits; anything else is a wrapped
    // continuation line.
    if number.len() > 2 || !number.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let child_sp = parts.next()?.to_owned();
    let mut rest: Vec<&str> = parts.collect();
    if rest.is_empty() {
        return None;
    }
    // Symbol is everything after the optional ret-addr. WinDbg prints
    // `retaddr symbol` or just `symbol` when the frame is frameless.
    let ret_addr = if rest.first().is_some_and(|t| looks_like_addr(t)) {
        Some(rest.remove(0).to_owned())
    } else {
        None
    };
    let args = match rest.last() {
        Some(maybe_args) if ret_addr.is_some() && rest.len() > 1 && looks_like_args(maybe_args) => {
            rest.pop().map(std::borrow::ToOwned::to_owned)
        }
        _ => None,
    };
    let symbol = rest.join(" ");
    Some(StackFrame {
        number,
        child_sp,
        ret_addr,
        symbol,
        args,
    })
}

fn looks_like_addr(token: &str) -> bool {
    // WinDbg prints 64-bit addresses with a backtick spacer:
    // `fffff803`c596cad0`. Strip it before checking the digits.
    let cleaned = token
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .replace('`', "");
    !cleaned.is_empty() && cleaned.chars().all(|c| c.is_ascii_hexdigit())
}

fn looks_like_args(token: &str) -> bool {
    token.contains(':') || token.starts_with('(')
}

/// Parse one `lm` / module listing line.
fn parse_module_line(line: Line<'_>) -> Option<ModuleInfo> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut tokens = trimmed.split_whitespace();
    let name = tokens.next()?.to_owned();
    if name.len() > 32 || name.contains('\\') {
        return None;
    }
    let base = tokens.next()?.to_owned();
    if !looks_like_addr(&base) {
        return None;
    }
    let size = tokens.next()?.to_owned();
    let timestamp = tokens.next().map(str::to_owned);
    Some(ModuleInfo {
        name,
        base,
        size,
        timestamp,
    })
}

fn detect_user_mode(text: &str) -> bool {
    text.contains("User Mini Dump") || text.contains("This dump file has an exception")
}

fn detect_symbols_incomplete(text: &str) -> bool {
    const MARKERS: [&str; 4] = [
        "can't find file or load",
        "Symbol search path is: *** ERROR ***",
        "!sym noisy",
        "ERROR: Symbol file could not be found",
    ];
    MARKERS.iter().any(|m| text.contains(m))
}

/// A convenience wrapper: parse plus lookup of the documented name.
///
/// # Errors
///
/// [`ParseError::NotAnalyzeOutput`] when the text is not `!analyze` output.
pub fn parse_analyze_report(text: &str) -> Result<AnalyzeReport, ParseError> {
    let parsed = parse_analyze_text(text)?;
    let bugcheck_info = parsed.bugcheck_code.and_then(crate::bugcheck_name);
    Ok(AnalyzeReport {
        parsed,
        bugcheck_info,
    })
}

/// A parsed report plus the public catalog entry for its bugcheck, if
/// the code is documented.
#[derive(Debug, Clone, PartialEq)]
pub struct AnalyzeReport {
    /// The raw parsed fields.
    pub parsed: ParsedAnalyze,
    /// The public catalog entry, when the code is documented.
    pub bugcheck_info: Option<crate::bugcheck::BugcheckInfo>,
}

/// Convenience: render the parsed fields back to a compact JSON-ish
/// summary for structured transport.
///
/// Ordering is insertion-free (`BTreeMap`) so output is deterministic —
/// a snapshot test depends on it.
#[must_use]
pub fn summarize(parsed: &ParsedAnalyze) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(code) = parsed.bugcheck_code {
        out.insert("bugcheck_code".into(), crate::format_bugcheck_code(code));
        if let Some(info) = crate::bugcheck_name(code) {
            out.insert("bugcheck_name".into(), info.name.to_owned());
        }
    }
    for (i, p) in parsed.bugcheck_parameters.iter().enumerate() {
        if let Some(v) = p {
            out.insert(format!("bugcheck_p{}", i + 1), format!("{v:#x}"));
        }
    }
    for (key, field) in [
        ("module_name", &parsed.module_name),
        ("image_name", &parsed.image_name),
        ("failure_bucket_id", &parsed.failure_bucket_id),
        ("symbol_name", &parsed.symbol_name),
        ("process_name", &parsed.process_name),
        ("default_bucket_id", &parsed.default_bucket_id),
    ] {
        if let Some(v) = field {
            out.insert(key.to_owned(), v.clone());
        }
    }
    out.insert("stack_frames".into(), parsed.stack_frames.len().to_string());
    out.insert("modules".into(), parsed.modules.len().to_string());
    out.insert(
        "dump_kind".into(),
        if parsed.user_mode_dump {
            "user"
        } else {
            "kernel"
        }
        .into(),
    );
    out.insert(
        "symbols_incomplete".into(),
        parsed.symbols_incomplete.to_string(),
    );
    out
}
