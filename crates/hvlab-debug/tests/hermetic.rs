//! Hermetic tests: fixture parsing, discovery error shape, find and
//! cache behavior. No cdb spawn, no Hyper-V, no network.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use hvlab_core::error::ErrorCode;
use hvlab_debug::analyze::analyze;
use hvlab_debug::cdb::{DBGENG_DIR_ENV, Discovery};
use hvlab_debug::find::find_dumps;
use hvlab_debug::{cache, cdb};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hvlab-debug-it-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// --- fixture parsing -------------------------------------------------

#[test]
fn fixture_kernel_9f_parses() {
    let text = std::fs::read_to_string(fixture("kernel_9f.txt")).unwrap();
    let parsed = hvlab_dump::analyze::parse_analyze_text(&text).unwrap();
    assert_eq!(parsed.bugcheck_code, Some(0x9F));
    assert_eq!(parsed.bugcheck_parameters[0], Some(3));
    assert_eq!(parsed.module_name.as_deref(), Some("mydriver"));
    assert_eq!(parsed.process_name.as_deref(), Some("System"));
    assert_eq!(
        parsed.failure_bucket_id.as_deref(),
        Some("0x9F_3_IMAGE_mydriver.sys")
    );
    assert!(!parsed.user_mode_dump);
    assert_eq!(parsed.stack_frames.len(), 5);
    assert!(
        parsed.stack_frames[3]
            .symbol
            .contains("mydriver!WorkerRoutine")
    );
}

#[test]
fn fixture_kernel_d1_parses() {
    let text = std::fs::read_to_string(fixture("kernel_d1.txt")).unwrap();
    let parsed = hvlab_dump::analyze::parse_analyze_text(&text).unwrap();
    assert_eq!(parsed.bugcheck_code, Some(0xD1));
    assert_eq!(parsed.module_name.as_deref(), Some("fastfat"));
    assert_eq!(
        parsed.default_bucket_id.as_deref(),
        Some("NULL_CLASS_PTR_READ")
    );
    assert_eq!(parsed.stack_frames.len(), 4);
}

#[test]
fn fixture_modules_only_parses() {
    let text = std::fs::read_to_string(fixture("modules_only.txt")).unwrap();
    let parsed = hvlab_dump::analyze::parse_analyze_text(&text).unwrap();
    assert_eq!(parsed.bugcheck_code, Some(0xA));
    assert_eq!(parsed.modules.len(), 3);
    assert_eq!(parsed.modules[0].name, "mydrv");
}

#[test]
fn fixture_user_mode_parses_without_bugcheck() {
    let text = std::fs::read_to_string(fixture("user_mode_fastfail.txt")).unwrap();
    let parsed = hvlab_dump::analyze::parse_analyze_text(&text).unwrap();
    assert!(parsed.user_mode_dump);
    assert_eq!(parsed.module_name.as_deref(), Some("app"));
    assert_eq!(parsed.process_name.as_deref(), Some("app.exe"));
    assert_eq!(
        parsed.failure_bucket_id.as_deref(),
        Some("FAIL_FAST_FATAL_APP_EXIT_c0000409_app.exe!Parse")
    );
    // The dump-crate parser reads the kernel `kv` layout; user-mode
    // reports are address-first, so hvlab-debug's extractor covers them.
    assert_eq!(hvlab_debug::extract_stack(&text).len(), 3);
}

#[test]
fn discovery_missing_reports_search_matrix() {
    let d = Discovery {
        path: None,
        searched: vec![
            PathBuf::from(r"C:\x\one"),
            PathBuf::from(r"C:\x\two"),
            PathBuf::from(r"C:\x\three"),
        ],
    };
    let err = d.into_result().unwrap_err();
    assert_eq!(err.code, ErrorCode::Unsupported);
    let paths = err
        .context
        .get("searched_paths")
        .and_then(|v| v.as_array())
        .unwrap();
    assert_eq!(paths.len(), 3);
}

#[test]
fn discovery_env_override_finds_dir() {
    let dir = temp_dir("envdisc");
    let exe = dir.join("cdb.exe");
    std::fs::write(&exe, b"stub").unwrap();
    // Set the override, then run the uncached discovery logic directly:
    // the process-level cache may already hold a result from another
    // test in the same binary, and env order across tests must not
    // decide who wins.
    // std::env::set_var/remove_var are unsafe (non-const process env)
    // but single-threaded here by test isolation semantics.
    #[allow(unsafe_code)]
    {
        unsafe { std::env::set_var(DBGENG_DIR_ENV, &dir) };
    }
    let disc = cdb::discover_now();
    #[allow(unsafe_code)]
    {
        unsafe { std::env::remove_var(DBGENG_DIR_ENV) };
    }
    assert_eq!(disc.path.as_deref(), Some(exe.as_path()));
    assert_eq!(disc.searched, vec![dir.clone()]);
    let _ = std::fs::remove_dir_all(&dir);
}

// --- find -------------------------------------------------------------

#[test]
fn find_dumps_hermetic_walk() {
    let dir = temp_dir("findit");
    let minidump_dir = dir.join("Minidump");
    std::fs::create_dir_all(&minidump_dir).unwrap();
    std::fs::write(dir.join("MEMORY.DMP"), b"PAGEDU64xxxx").unwrap();
    std::fs::write(minidump_dir.join("102425-01-01.dmp"), b"PAGEDU64y").unwrap();
    std::fs::write(dir.join("notes.log"), b"not a dump").unwrap();

    let res = find_dumps(&[dir.clone(), minidump_dir], 10);
    assert_eq!(res.dumps.len(), 2);
    assert_eq!(res.skipped_by_limit, 0);
    let names: Vec<_> = res
        .dumps
        .iter()
        .map(|d| d.path.file_name().unwrap().to_string_lossy().to_string())
        .collect();
    assert!(names.contains(&"MEMORY.DMP".to_string()));
    assert!(
        names
            .iter()
            .any(|n| n.to_ascii_lowercase().ends_with(".dmp"))
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn find_dumps_limit_counts_skipped() {
    let dir = temp_dir("findlimit");
    std::fs::write(dir.join("a.dmp"), b"1").unwrap();
    std::fs::write(dir.join("b.dmp"), b"22").unwrap();
    std::fs::write(dir.join("c.dmp"), b"333").unwrap();
    let res = find_dumps(std::slice::from_ref(&dir), 2);
    assert_eq!(res.dumps.len(), 2);
    assert_eq!(res.skipped_by_limit, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

// --- cache ------------------------------------------------------------

#[test]
fn cache_respects_env_override_dir() {
    let dir = temp_dir("cachedir");
    #[allow(unsafe_code)]
    {
        unsafe { std::env::set_var(hvlab_debug::cache::CACHE_DIR_ENV, &dir) };
    }
    let resolved = hvlab_debug::default_cache_dir();
    #[allow(unsafe_code)]
    {
        unsafe { std::env::remove_var(hvlab_debug::cache::CACHE_DIR_ENV) };
    }
    assert_eq!(resolved, dir);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cache_round_trip_and_expiry() {
    let dir = temp_dir("cacheit");
    let dump = dir.join("fake.dmp");
    std::fs::write(&dump, b"PAGEDU64fake").unwrap();
    let text = std::fs::read_to_string(fixture("kernel_d1.txt")).unwrap();
    let parsed = hvlab_dump::analyze::parse_analyze_text(&text).unwrap();
    let analysis = hvlab_debug::Analysis {
        parsed,
        raw_log: text,
        truncation: hvlab_debug::analyze::Truncation::default(),
        exit_code: Some(0),
        elapsed_secs: 0.5,
        cdb_path: r"C:\fake\cdb.exe".to_string(),
    };
    cache::store(&dir, &dump, &analysis, cache::default_ttl()).unwrap();
    let (hit, _) = cache::lookup(&dir, &dump, cache::default_ttl()).unwrap();
    assert_eq!(hit.parsed.bugcheck_code, Some(0xD1));
    assert!(cache::lookup(&dir, &dump, Duration::ZERO).is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

// --- analyze entry points (no cdb spawn) ------------------------------

#[test]
fn analyze_missing_dump_not_found() {
    let err = analyze(
        Path::new(r"C:\definitely-missing-31337.dmp"),
        &hvlab_debug::AnalyzeOptions::default(),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::NotFound);
}

// --- T2: real dump via cdb, strictly env-gated -------------------------

#[test]
fn t2_real_dump_analysis() {
    let Ok(dump) = std::env::var("HVLAB_TEST_DUMP_PATH") else {
        eprintln!("T2 skipped: HVLAB_TEST_DUMP_PATH unset");
        return;
    };
    let dump = PathBuf::from(dump);
    if !dump.is_file() {
        eprintln!("T2 skipped: HVLAB_TEST_DUMP_PATH does not exist");
        return;
    }
    if cdb::cdb_path().path.is_none() {
        eprintln!("T2 skipped: cdb.exe not found");
        return;
    }
    // Local symbol cache only: a symbol-server URL makes cdb block on
    // the network for minutes, which is not what this tier is testing.
    let symbols = std::env::var("HVLAB_TEST_SYMBOL_PATH").unwrap_or_else(|_| {
        std::env::var_os("LOCALAPPDATA")
            .map_or_else(
                || PathBuf::from("."),
                |p| PathBuf::from(p).join("hvlab").join("symbols"),
            )
            .display()
            .to_string()
    });
    let opts = hvlab_debug::AnalyzeOptions {
        symbol_path: Some(symbols),
        timeout: Duration::from_secs(120),
        ..hvlab_debug::AnalyzeOptions::default()
    };
    let analysis = analyze(&dump, &opts).expect("analysis succeeds");
    assert!(
        analysis.raw_log.contains("STACK_TEXT"),
        "raw log must contain the !analyze sections, got {} bytes",
        analysis.raw_log.len()
    );
    // H-01: evidence, not exit code — the report must parse.
    assert!(analysis.parsed.bugcheck_code.is_some() || analysis.parsed.user_mode_dump);
}
