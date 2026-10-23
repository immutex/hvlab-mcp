//! Integration-level tests for `hvlab-dump`: fixture-based parser
//! tests, offset cross-checks against `kdmp-parser`, and proptest
//! invariants.

use crate::analyze::{parse_analyze_report, parse_analyze_text, summarize};
use crate::header::{DumpHeader64, DumpKind, HeaderError};

/// A realistic, abridged `!analyze -v` transcript (kernel dump, resolved
/// symbols). Field layout matches what the engine prints.
const FIXTURE_KERNEL_ANALYZE: &str = r"
DEBUG_FLR_IMAGE_TIMESTAMP:  0

BUGCHECK_CODE:  9f
BUGCHECK_P1: 3
BUGCHECK_P2: ffffe000f38c06a0
BUGCHECK_P3: fffff803c596cad0
BUGCHECK_P4: ffffe000f46a1010

DEFAULT_BUCKET_ID:  WIN8_DRIVER_FAULT

PROCESS_NAME:  System

STACK_TEXT:
00 ffffd001`12345678 fffff803`c596cad0 nt!KiSwapContext+0x76
01 ffffd001`12345680 fffff803`c5967a00 nt!KiCommitThreadWait+0x129
02 ffffd001`12345700 nt!KeWaitForSingleObject

MODULE_NAME: mydriver
IMAGE_NAME:  mydriver.sys
FAILURE_BUCKET_ID:  0x9F_3_mydriver
SYMBOL_NAME:  mydriver!AddDevice+0x10

MODULE_LIST:
nt fffff803`c4400000  8e000   Sat Jan 01 00:00:00 2026
mydriver fffff803`c5960000  12000   Sat Jan 01 00:00:00 2026
";

const FIXTURE_USER_MODE: &str = r"
This dump file has an exception of interest stored in it.
User Mini Dump File: Only registers and stack are available

MODULE_NAME: notepad
IMAGE_NAME:  notepad.exe
";

const FIXTURE_SYMBOLS_MISSING: &str = r"
BUGCHECK_CODE:  d1
ERROR: Symbol file could not be found.  Defaulted to export symbols for ntkrnlmp.exe -
MODULE_NAME: unknown
";

/// The header bytes used by parser tests: a valid, minimal `DUMP_HEADER64`
/// with a bugcheck of 0x9F and the parameters from the `WinDbg` docs.
pub fn fixture_header_bytes() -> [u8; 0x88] {
    let mut buf = [0u8; 0x88];
    buf[0x00..0x04].copy_from_slice(&0x4547_4150u32.to_le_bytes()); // PAGE
    buf[0x04..0x08].copy_from_slice(&0x3436_5544u32.to_le_bytes()); // DU64
    buf[0x08..0x0C].copy_from_slice(&10u32.to_le_bytes()); // Major
    buf[0x0C..0x10].copy_from_slice(&26_100u32.to_le_bytes()); // Minor
    buf[0x10..0x18].copy_from_slice(&0x1A000u64.to_le_bytes()); // DTB
    buf[0x18..0x20].copy_from_slice(&0xFFFF_F800_0000_0000u64.to_le_bytes()); // PFN db
    buf[0x80..0x88].copy_from_slice(&0xFFFF_F800_03A0_0000u64.to_le_bytes()); // KDBG at 0x80
    buf[0x38..0x3C].copy_from_slice(&0x9Fu32.to_le_bytes()); // BugCheckCode
    for (i, v) in [
        3u64,
        0xFFFF_E000_F38C_06A0,
        0xFFFF_F803_C596_CAD0,
        0xFFFF_E000_F46A_1010,
    ]
    .iter()
    .enumerate()
    {
        let off = 0x40 + i * 8;
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
    buf
}

mod header {
    use super::*;

    #[test]
    fn parses_valid_header_fields() {
        let h = DumpHeader64::read_from_reader(fixture_header_bytes().as_slice())
            .expect("valid fixture");
        assert_eq!(h.os_version, (10, 26_100));
        assert_eq!(h.directory_table_base, 0x1A000);
        assert_eq!(h.bug_check_code, 0x9F);
        assert_eq!(h.bug_check_parameters[0], 3);
        assert_eq!(h.bug_check_parameters[3], 0xFFFF_E000_F46A_1010);
    }

    #[test]
    fn rejects_bad_signature() {
        let mut buf = fixture_header_bytes();
        buf[0x00..0x04].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let err = DumpHeader64::read_from_reader(buf.as_slice()).expect_err("bad signature");
        assert!(
            matches!(
                err,
                HeaderError::BadSignature {
                    actual: 0xDEAD_BEEF
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn rejects_bad_valid_dump() {
        let mut buf = fixture_header_bytes();
        buf[0x04..0x08].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        let err = DumpHeader64::read_from_reader(buf.as_slice()).expect_err("bad ValidDump");
        assert!(
            matches!(
                err,
                HeaderError::BadValidDump {
                    actual: 0x1234_5678
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn rejects_too_small_file() {
        let buf = [0u8; 0x10];
        let err = DumpHeader64::read_from_reader(buf.as_slice()).expect_err("too small");
        assert!(
            matches!(
                err,
                HeaderError::TooSmall {
                    size: 0x10,
                    needed: 0x88
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn detects_32bit_header() {
        let mut buf = fixture_header_bytes();
        buf[0x00..0x04].copy_from_slice(&0x504D_5544u32.to_le_bytes()); // "PMDU"
        let err = DumpHeader64::read_from_reader(buf.as_slice()).expect_err("32-bit header");
        assert!(matches!(err, HeaderError::ThirtyTwoBit { .. }), "{err}");
    }

    #[test]
    fn error_names_the_actual_missing_input() {
        // H-02: a missing dependency (debugger) must never mask a
        // missing input (the dump). Header errors are precise by design.
        let err = DumpHeader64::read_from_reader(&b""[..]).expect_err("empty");
        assert!(
            err.to_string().contains("too small"),
            "error should name the file, got: {err}"
        );
    }

    /// Offset cross-check against `kdmp-parser`'s `Header64`, read
    /// via `std::mem::offset_of!` — the upstream struct is the layout
    /// authority. A real 373 MB dump caught `kd_debugger_data_block`
    /// being wrong here (0x28 vs the true 0x80); this test keeps every
    /// constant honest.
    #[test]
    fn offsets_match_kdmp_parser() {
        use crate::header::{
            OFFSET_BUGCHECK_CODE, OFFSET_BUGCHECK_PARAMS, OFFSET_DIRECTORY_TABLE_BASE,
            OFFSET_DUMP_TYPE, OFFSET_KDDEBUGGER_DATA_BLOCK, OFFSET_MAJOR_VERSION,
            OFFSET_MINOR_VERSION, OFFSET_PFN_DATABASE,
        };
        use kdmp_parser::structs::Header64;
        use std::mem::offset_of;

        assert_eq!(OFFSET_MAJOR_VERSION, offset_of!(Header64, major_version));
        assert_eq!(OFFSET_MINOR_VERSION, offset_of!(Header64, minor_version));
        assert_eq!(
            OFFSET_DIRECTORY_TABLE_BASE,
            offset_of!(Header64, directory_table_base)
        );
        assert_eq!(OFFSET_PFN_DATABASE, offset_of!(Header64, pfn_database));
        assert_eq!(
            OFFSET_KDDEBUGGER_DATA_BLOCK,
            offset_of!(Header64, kd_debugger_data_block)
        );
        assert_eq!(OFFSET_BUGCHECK_CODE, offset_of!(Header64, bug_check_code));
        assert_eq!(
            OFFSET_BUGCHECK_PARAMS,
            offset_of!(Header64, bug_check_code_parameters)
        );
        assert_eq!(OFFSET_DUMP_TYPE, offset_of!(Header64, dump_type));
    }

    #[test]
    fn dump_kind_decodes_known_values() {
        // Values validated against kdmp-parser's DumpType enum and
        // real dumps (6 = live kernel, 4 = mini).
        assert_eq!(DumpKind::from_dump_type(1), DumpKind::Full);
        assert_eq!(DumpKind::from_dump_type(5), DumpKind::Bitmap);
        assert_eq!(DumpKind::from_dump_type(6), DumpKind::LiveKernel);
        assert_eq!(DumpKind::from_dump_type(8), DumpKind::Kernel);
        assert_eq!(DumpKind::from_dump_type(9), DumpKind::KernelUser);
        assert_eq!(DumpKind::from_dump_type(0xA), DumpKind::Complete);
        assert!(matches!(DumpKind::from_dump_type(4), DumpKind::Unknown(4)));
        assert!(matches!(
            DumpKind::from_dump_type(0x1234),
            DumpKind::Unknown(0x1234)
        ));
    }

    #[test]
    fn unknown_and_mini_are_not_kernel() {
        // H-03: user-mode dumps must not receive kernel logic. Type 4
        // (mini) is the user-mode path; unrecognized types fail closed.
        assert!(!DumpKind::Unknown(4).is_kernel());
        assert!(!DumpKind::Unknown(0).is_kernel());
        assert!(DumpKind::Full.is_kernel());
        assert!(DumpKind::Kernel.is_kernel());
        assert!(DumpKind::LiveKernel.is_kernel());
    }
}

mod analyze {
    use super::*;

    #[test]
    fn parses_kernel_analyze_fields() {
        let parsed = parse_analyze_text(FIXTURE_KERNEL_ANALYZE).expect("fixture parses");
        assert_eq!(parsed.bugcheck_code, Some(0x9F));
        assert_eq!(parsed.module_name.as_deref(), Some("mydriver"));
        assert_eq!(parsed.image_name.as_deref(), Some("mydriver.sys"));
        assert_eq!(parsed.failure_bucket_id.as_deref(), Some("0x9F_3_mydriver"));
        assert_eq!(parsed.process_name.as_deref(), Some("System"));
        assert_eq!(
            parsed.symbol_name.as_deref(),
            Some("mydriver!AddDevice+0x10")
        );
        assert!(!parsed.user_mode_dump);
        assert!(!parsed.symbols_incomplete);
    }

    #[test]
    fn parses_all_four_bugcheck_parameters() {
        let parsed = parse_analyze_text(FIXTURE_KERNEL_ANALYZE).expect("fixture parses");
        assert_eq!(parsed.bugcheck_parameters[0], Some(3));
        assert_eq!(parsed.bugcheck_parameters[1], Some(0xFFFF_E000_F38C_06A0));
        assert_eq!(parsed.bugcheck_parameters[2], Some(0xFFFF_F803_C596_CAD0));
        assert_eq!(parsed.bugcheck_parameters[3], Some(0xFFFF_E000_F46A_1010));
    }

    #[test]
    fn parses_stack_frames_with_and_without_retaddr() {
        let parsed = parse_analyze_text(FIXTURE_KERNEL_ANALYZE).expect("fixture parses");
        assert_eq!(
            parsed.stack_frames.len(),
            3,
            "frames: {:?}",
            parsed.stack_frames
        );
        let f0 = &parsed.stack_frames[0];
        assert_eq!(f0.number, "00");
        assert_eq!(f0.symbol, "nt!KiSwapContext+0x76");
        assert!(f0.ret_addr.is_some());
        // Third frame has no return address column in real output.
        let f2 = &parsed.stack_frames[2];
        assert_eq!(f2.symbol, "nt!KeWaitForSingleObject");
    }

    #[test]
    fn parses_module_list() {
        let parsed = parse_analyze_text(FIXTURE_KERNEL_ANALYZE).expect("fixture parses");
        assert_eq!(parsed.modules.len(), 2);
        assert_eq!(parsed.modules[0].name, "nt");
        assert_eq!(parsed.modules[1].name, "mydriver");
    }

    #[test]
    fn detects_user_mode_dump() {
        let parsed = parse_analyze_text(FIXTURE_USER_MODE).expect("fixture parses");
        assert!(parsed.user_mode_dump);
        assert_eq!(parsed.bugcheck_code, None, "user dumps have no bugcheck");
        assert_eq!(parsed.module_name.as_deref(), Some("notepad"));
    }

    #[test]
    fn detects_symbols_incomplete() {
        let parsed = parse_analyze_text(FIXTURE_SYMBOLS_MISSING).expect("fixture parses");
        assert!(parsed.symbols_incomplete);
        assert_eq!(parsed.bugcheck_code, Some(0xD1));
    }

    #[test]
    fn rejects_non_analyze_input() {
        // H-49: malformed input is an error, not empty success.
        let err = parse_analyze_text("hello world\nrandom log lines\n").expect_err("not analyze");
        assert!(err.to_string().contains("does not contain"), "{err}");
    }

    #[test]
    fn rejects_empty_input() {
        let err = parse_analyze_text("").expect_err("empty");
        assert!(matches!(err, crate::analyze::ParseError::NotAnalyzeOutput));
    }

    #[test]
    fn wrapped_continuation_lines_do_not_become_frames() {
        let text =
            "STACK_TEXT: \n  symbol continuation without frame number\n00 ffffd001`abc nt!Foo\n";
        let parsed = parse_analyze_text(text).expect("parses");
        assert_eq!(parsed.stack_frames.len(), 1, "{:?}", parsed.stack_frames);
    }

    #[test]
    fn summary_is_deterministic_and_complete() {
        let parsed = parse_analyze_text(FIXTURE_KERNEL_ANALYZE).expect("parses");
        let s1 = summarize(&parsed);
        let s2 = summarize(&parsed);
        assert_eq!(s1, s2);
        assert_eq!(
            s1.get("bugcheck_code").map(String::as_str),
            Some("0x0000009F")
        );
        assert_eq!(
            s1.get("bugcheck_name").map(String::as_str),
            Some("DRIVER_POWER_STATE_FAILURE")
        );
        assert_eq!(s1.get("dump_kind").map(String::as_str), Some("kernel"));
        assert_eq!(
            s1.get("symbols_incomplete").map(String::as_str),
            Some("false")
        );
    }

    #[test]
    fn report_attaches_public_catalog_entry() {
        // The catalog lookup is facts-only; no interpretation.
        let report = parse_analyze_report(FIXTURE_KERNEL_ANALYZE).expect("parses");
        let info = report.bugcheck_info.expect("0x9F is documented");
        assert_eq!(info.name, "DRIVER_POWER_STATE_FAILURE");
        assert!(info.doc_path.contains("microsoft"));
    }

    #[test]
    fn unknown_bugcheck_has_no_catalog_entry() {
        let text = "BUGCHECK_CODE: 0xDEAD\nMODULE_NAME: x\n";
        let report = parse_analyze_report(text).expect("parses");
        assert!(report.bugcheck_info.is_none());
        assert_eq!(report.parsed.bugcheck_code, Some(0xDEAD));
    }

    #[test]
    fn bare_bugcheck_values_are_hex() {
        // The engine prints these in hex with no prefix; "159" is
        // 0x159, not 159 decimal.
        let text = "BUGCHECK_CODE:  159\n";
        let parsed = parse_analyze_text(text).expect("parses");
        assert_eq!(parsed.bugcheck_code, Some(0x159));
    }

    #[test]
    fn prefixed_bugcheck_values_parse() {
        let text = "BUGCHECK_CODE:  0x9F\n";
        let parsed = parse_analyze_text(text).expect("parses");
        assert_eq!(parsed.bugcheck_code, Some(0x9F));
    }
}

/// proptest: header parsing must never panic and must round-trip the
/// bugcheck fields for any well-formed header bytes.
mod prop {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn header_never_panics_and_roundtrips_bugcheck(
            code in proptest::num::u32::ANY,
            p0 in proptest::num::u64::ANY,
            p3 in proptest::num::u64::ANY,
            major in proptest::num::u32::ANY,
            minor in proptest::num::u32::ANY,
        ) {
            let mut buf = [0u8; 0x88];
            buf[0x00..0x04].copy_from_slice(&0x4547_4150u32.to_le_bytes());
            buf[0x04..0x08].copy_from_slice(&0x3436_5544u32.to_le_bytes());
            buf[0x08..0x0C].copy_from_slice(&major.to_le_bytes());
            buf[0x0C..0x10].copy_from_slice(&minor.to_le_bytes());
            buf[0x38..0x3C].copy_from_slice(&code.to_le_bytes());
            buf[0x40..0x48].copy_from_slice(&p0.to_le_bytes());
            buf[0x58..0x60].copy_from_slice(&p3.to_le_bytes());
            buf[0x80..0x88].copy_from_slice(&0u64.to_le_bytes());

            let h = DumpHeader64::read_from_reader(buf.as_slice())?;
            prop_assert_eq!(h.bug_check_code, code);
            prop_assert_eq!(h.bug_check_parameters[0], p0);
            prop_assert_eq!(h.bug_check_parameters[3], p3);
            prop_assert_eq!(h.os_version, (major, minor));
        }

        #[test]
        fn arbitrary_bytes_never_panic(data in proptest::collection::vec(proptest::num::u8::ANY, 0..0x100)) {
            // The parser must reject, never panic, on arbitrary input.
            let _ = DumpHeader64::read_from_reader(data.as_slice());
        }

        #[test]
        fn analyze_parser_never_panics_on_arbitrary_text(text in r"[!-~ \t\n]{0,2000}") {
            let _ = parse_analyze_text(&text);
        }
    }
}

/// Fixture for the `dump_kind` second read: a full dump type at the
/// canonical offset.
#[test]
fn dump_kind_reads_full_dump_type() {
    let mut buf = fixture_header_bytes().to_vec();
    buf.resize(0x2000, 0);
    buf[0xF98..0xF9C].copy_from_slice(&1u32.to_le_bytes()); // Full
    let (tmp, _guard) = temp_fixture("hvlab-dump-kind-full.dmp", &buf);

    let h = DumpHeader64::read_from_reader(buf.as_slice()).expect("valid header");
    let kind = h.read_kind(&tmp).expect("kind readable");
    assert_eq!(kind, DumpKind::Full);
}

#[test]
fn dump_kind_reads_live_kernel_type() {
    // Type 6 (live kernel memory) was missed by a hand-written table;
    // this value came from a real 373 MB dump on the authoring machine.
    let mut buf = fixture_header_bytes().to_vec();
    buf.resize(0x2000, 0);
    buf[0xF98..0xF9C].copy_from_slice(&6u32.to_le_bytes());
    let (tmp, _guard) = temp_fixture("hvlab-dump-kind-live.dmp", &buf);

    let h = DumpHeader64::read_from_reader(buf.as_slice()).expect("valid header");
    let kind = h.read_kind(&tmp).expect("kind readable");
    assert_eq!(kind, DumpKind::LiveKernel);
}

#[test]
fn dump_kind_reads_mini_type() {
    // Type 4 (mini, `.dump /m`) also comes from a real dump.
    let mut buf = fixture_header_bytes().to_vec();
    buf.resize(0x2000, 0);
    buf[0xF98..0xF9C].copy_from_slice(&4u32.to_le_bytes());
    let (tmp, _guard) = temp_fixture("hvlab-dump-kind-mini.dmp", &buf);

    let h = DumpHeader64::read_from_reader(buf.as_slice()).expect("valid header");
    let kind = h.read_kind(&tmp).expect("kind readable");
    assert!(matches!(kind, DumpKind::Unknown(4)), "{kind:?}");
}

/// Deletes a fixture file when dropped.
struct Defer(std::path::PathBuf);

impl Drop for Defer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Write a fixture and return a guard that deletes it on scope exit.
fn temp_fixture(name: &str, bytes: &[u8]) -> (std::path::PathBuf, Defer) {
    let path = std::env::temp_dir().join(name);
    std::fs::write(&path, bytes).expect("write fixture");
    let guard = Defer(path.clone());
    (path, guard)
}
