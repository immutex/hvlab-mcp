//! Stack text extraction that covers both debugger layouts.
//!
//! [`hvlab_dump::analyze`] parses the kernel `kv` layout
//! (`NN <child-sp> <ret-addr> <symbol>`). User-mode dumps print a
//! different shape, with no frame numbers:
//!
//! ```text
//! 00000000`0015a8e0 00000000`0015a8e8 : app!Parse+0x2a8
//! ```
//!
//! This module extracts the `STACK_TEXT` section as address-first
//! triples regardless of layout, so a user-mode report still yields a
//! usable stack. Nothing here guesses: a line that does not match a
//! layout is skipped, and the raw log is always available.

/// One stack line, normalized across layouts.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StackLine {
    /// Frame number when the debugger printed one.
    pub number: Option<String>,
    /// The child stack pointer / first address column.
    pub address: String,
    /// The return address column, when present.
    pub return_address: Option<String>,
    /// Symbol text, e.g. `app!Parse+0x2a8`.
    pub symbol: String,
}

/// Collect the `STACK_TEXT` section's lines, ending at the next
/// `KEY:`-style section marker or blank-line-terminated block.
fn stack_section(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut in_section = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("STACK_TEXT") {
            in_section = true;
            continue;
        }
        if !in_section {
            continue;
        }
        if trimmed.is_empty() {
            // A blank line ends the section in cdb output; tolerate one
            // stray blank without dropping the rest of the report.
            if !out.is_empty() {
                break;
            }
            continue;
        }
        // Any `UPPER_CASE:` line starts the next section.
        if is_section_header(trimmed) {
            break;
        }
        out.push(trimmed);
    }
    out
}

/// `SYMBOL_NAME:` / `FOLLOWUP_NAME:` / `STACK_COMMAND:` style headers.
fn is_section_header(line: &str) -> bool {
    let Some(colon) = line.find(':') else {
        return false;
    };
    let (head, _) = line.split_at(colon);
    !head.is_empty()
        && head.len() <= 32
        && head
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// True when the token is a hex address, optionally containing a
/// backtick digit-group separator (the debugger's quoting style).
fn is_address(token: &str) -> bool {
    let stripped = token.replace('`', "");
    stripped.len() >= 8 && stripped.chars().all(|c| c.is_ascii_hexdigit())
}

/// Split a kernel-layout frame: `NN <sp> <ret?> <symbol...>`.
fn parse_numbered(line: &str) -> Option<StackLine> {
    let mut parts = line.split_whitespace();
    let number = parts.next()?;
    if number.len() > 2 || !number.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let address = parts.next()?.to_owned();
    let rest: Vec<&str> = parts.collect();
    if rest.is_empty() {
        return None;
    }
    let (return_address, symbol_start) = if is_address(rest[0]) {
        (Some(rest[0].to_owned()), 1)
    } else {
        (None, 0)
    };
    let symbol = rest[symbol_start..].join(" ");
    if symbol.is_empty() {
        return None;
    }
    Some(StackLine {
        number: Some(number.to_owned()),
        address,
        return_address,
        symbol,
    })
}

/// Split an address-first frame: `<sp> <ret> : <symbol>` or
/// `<sp> <ret> <symbol>`.
fn parse_address_first(line: &str) -> Option<StackLine> {
    if let Some((head, tail)) = line.split_once(':') {
        let head = head.trim();
        let symbol = tail.trim();
        let tokens: Vec<&str> = head.split_whitespace().collect();
        if tokens.is_empty() || !is_address(tokens[0]) || symbol.is_empty() {
            return None;
        }
        return Some(StackLine {
            number: None,
            address: tokens[0].to_owned(),
            return_address: tokens.get(1).map(|s| (*s).to_owned()),
            symbol: symbol.to_owned(),
        });
    }
    let mut parts = line.splitn(3, char::is_whitespace);
    let a = parts.next()?;
    let b = parts.next()?;
    let c = parts.next()?.trim();
    if !is_address(a) || c.is_empty() {
        return None;
    }
    Some(StackLine {
        number: None,
        address: a.to_owned(),
        return_address: Some(b.to_owned()),
        symbol: c.to_owned(),
    })
}

/// Extract every recognizable stack line from a debugger log.
///
/// Handles both the kernel `kv` layout and the user-mode
/// address-first layout. Lines that match neither are skipped.
#[must_use]
pub fn extract_stack(text: &str) -> Vec<StackLine> {
    stack_section(text)
        .into_iter()
        .filter_map(|line| parse_numbered(line).or_else(|| parse_address_first(line)))
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    const USER: &str = "STACK_TEXT:  \n\
00000000`0015a8e0 00000000`0015a8e8 : app!Parse+0x2a8\n\
00000000`0015a8e8 00000000`0015a940 : app!main+0x40\n\
\n\
SYMBOL_NAME:  app!Parse\n";

    const KERNEL: &str = "STACK_TEXT: \n\
00 ffffd481`32de5a98 fffff804`3aa8b1e0 nt!KiSwapContext+0x76\n\
01 ffffd481`32de5b30 fffff804`3aa8bf1f nt!KiCommitThreadWait+0x12e\n\
\n\
MODULE_NAME: mydriver\n";

    #[test]
    fn user_mode_address_first_frames_parse() {
        let frames = extract_stack(USER);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].symbol, "app!Parse+0x2a8");
        assert_eq!(frames[0].address, "00000000`0015a8e0");
        assert_eq!(
            frames[0].return_address.as_deref(),
            Some("00000000`0015a8e8")
        );
        assert!(frames[0].number.is_none());
    }

    #[test]
    fn kernel_numbered_frames_parse() {
        let frames = extract_stack(KERNEL);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].number.as_deref(), Some("00"));
        assert_eq!(frames[0].symbol, "nt!KiSwapContext+0x76");
        assert_eq!(frames[1].number.as_deref(), Some("01"));
    }

    #[test]
    fn missing_section_yields_empty() {
        let frames = extract_stack("BUGCHECK_CODE: 9f\n");
        assert!(
            frames.is_empty(),
            "a log without STACK_TEXT has no frames, got {frames:?}"
        );
    }

    #[test]
    fn garbage_lines_are_skipped_not_guessed() {
        let text =
            "STACK_TEXT: \nnot a frame at all\n00000000`0015a8e0 00000000`0015a8e8 : app!f+0x1\n";
        let frames = extract_stack(text);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].symbol, "app!f+0x1");
    }

    #[test]
    fn section_header_terminates_block() {
        let text = "STACK_TEXT: \n00000000`0015a8e0 00000000`0015a8e8 : app!f+0x1\nSTACK_COMMAND: ~0s; .ecxr ; kb\n";
        assert_eq!(extract_stack(text).len(), 1);
    }
}
