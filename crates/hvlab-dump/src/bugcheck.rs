//! Bugcheck code catalog — code → symbolic name, sourced from
//! Microsoft's public bugcheck reference. Facts only; no guidance about
//! whether a given crash matters on any particular system.
//!
//! The mapping is deliberately a `match` over exact integers, never a
//! string or substring test: a substring test like `"0x1A" in text`
//! matches `0x1A0` and produces confident nonsense.

/// A bugcheck code with its documented symbolic name and description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BugcheckInfo {
    /// The numeric stop code.
    pub code: u32,
    /// The symbolic name from Microsoft's bugcheck reference.
    pub name: &'static str,
    /// One-line description, verbatim in spirit from the docs.
    pub description: &'static str,
    /// Path on `learn.microsoft.com` for the full page.
    pub doc_path: &'static str,
}

/// Translate a bugcheck code to its documented name.
///
/// Unknown codes return `None`; callers decide how to present that.
///
/// # Examples
///
/// ```
/// let info = hvlab_dump::bugcheck_name(0x9F).expect("documented code");
/// assert_eq!(info.name, "DRIVER_POWER_STATE_FAILURE");
/// assert!(hvlab_dump::bugcheck_name(0xDEAD_0000).is_none());
/// ```
#[must_use]
pub fn bugcheck_name(code: u32) -> Option<BugcheckInfo> {
    match code {
        0x01 => Some(("APC_INDEX_MISMATCH", "A kernel APC index mismatch.")),
        0x0A => Some(("IRQL_NOT_LESS_OR_EQUAL", "A kernel-mode process or driver accessed paged memory at a process IRQL that was too high.")),
        0x1A => Some(("MEMORY_MANAGEMENT", "A severe memory management error occurred.")),
        0x1E => Some(("KMODE_EXCEPTION_NOT_HANDLED", "A kernel-mode program generated an exception the error handler did not catch.")),
        0x24 => Some(("NTFS_FILE_SYSTEM", "A problem occurred within the NTFS file system driver.")),
        0x3B => Some(("SYSTEM_SERVICE_EXCEPTION", "An exception happened while executing a routine that transitions from non-privileged code to privileged code.")),
        0x44 => Some(("MULTIPLE_IRP_COMPLETE_REQUESTS", "A driver has called `IoCompleteRequest` on an IRP already completed.")),
        0x50 => Some(("PAGE_FAULT_IN_NONPAGED_AREA", "Invalid system memory was referenced, typically in the non-paged pool.")),
        0x7B => Some(("INACCESSIBLE_BOOT_DEVICE", "The OS lost access to the system partition during boot.")),
        0x7E => Some(("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "A system thread generated an exception the error handler did not catch.")),
        0x7F => Some(("UNEXPECTED_KERNEL_MODE_TRAP", "The kernel ran into an unexpected trap or double fault.")),
        0x8E => Some(("KERNEL_MODE_EXCEPTION_NOT_HANDLED", "A kernel-mode program generated an exception the error handler did not catch.")),
        0x9F => Some(("DRIVER_POWER_STATE_FAILURE", "A driver is in an inconsistent or invalid power state.")),
        0xA0 => Some(("INTERNAL_POWER_ERROR", "The power policy manager experienced a severe error.")),
        0xC2 => Some(("BAD_POOL_CALLER", "A pool header was corrupted, typically by a bad pool allocation or free.")),
        0xC5 => Some(("DRIVER_CORRUPTED_EXPOOL", "A driver attempted to access pageable memory at a too-high process IRQL.")),
        0xD1 => Some(("DRIVER_IRQL_NOT_LESS_OR_EQUAL", "A driver attempted to access pageable memory at a too-high process IRQL.")),
        0x101 => Some(("CLOCK_WATCHDOG_TIMEOUT", "An expected clock interrupt was not received on a secondary processor in an SMP system.")),
        0x109 => Some(("CRITICAL_STRUCTURE_CORRUPTION", "The kernel has detected the corruption of a critical data structure.")),
        0x116 => Some(("VIDEO_TDR_FAILURE", "The display driver failed to complete a timed recovery operation.")),
        0x124 => Some(("WHEA_UNCORRECTABLE_ERROR", "Windows Hardware Error Architecture reported an uncorrectable hardware error.")),
        0x133 => Some(("DPC_WATCHDOG_VIOLATION", "The DPC watchdog detected a prolonged run at DISPATCH_LEVEL or above.")),
        0x139 => Some(("KERNEL_SECURITY_CHECK_FAILURE", "The kernel detected the corruption of a critical data structure (fast fail).")),
        0x18B => Some(("SECURE_KERNEL_ERROR", "The secure kernel encountered an error condition.")),
        0x1A0 => Some(("TTM_FATAL_ERROR", "The video memory manager encountered a fatal error.")),
        0x1C7 => Some(("STORE_DATA_STRUCTURE_CORRUPTION", "A data structure in the memory store is corrupted.")),
        _ => None,
    }
    .map(|(name, description)| BugcheckInfo {
        code,
        name,
        description,
        doc_path: "https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2",
    })
}

/// Format a bugcheck code the way `WinDbg` prints it: `0x0000009F`.
#[must_use]
pub fn format_bugcheck_code(code: u32) -> String {
    format!("0x{code:08X}")
}

#[cfg(test)]
mod tests {
    use super::*;

    mod bugcheck_name {
        use super::*;

        #[test]
        fn returns_documented_name_for_known_code() {
            let info = bugcheck_name(0x9F).expect("0x9F is documented");
            assert_eq!(info.name, "DRIVER_POWER_STATE_FAILURE");
            assert_eq!(info.code, 0x9F);
        }

        #[test]
        fn returns_none_for_undocumented_code() {
            assert!(bugcheck_name(0xDEAD_0000).is_none());
        }

        #[test]
        fn exact_codes_only_short_code_never_matches_longer_one() {
            // The classic hazard: a substring test for "0x1A" also
            // matches 0x1A0. Integer matching cannot make that mistake.
            assert_eq!(
                bugcheck_name(0x1A).map(|i| i.name),
                Some("MEMORY_MANAGEMENT")
            );
            assert_eq!(
                bugcheck_name(0x1A0).map(|i| i.name),
                Some("TTM_FATAL_ERROR")
            );
            assert_ne!(
                bugcheck_name(0x1A).map(|i| i.name),
                bugcheck_name(0x1A0).map(|i| i.name)
            );
        }

        #[test]
        fn adjacent_codes_do_not_alias() {
            assert_eq!(
                bugcheck_name(0x50).map(|i| i.name),
                Some("PAGE_FAULT_IN_NONPAGED_AREA")
            );
            assert_eq!(bugcheck_name(0x500).map(|i| i.name), None);
            assert_eq!(
                bugcheck_name(0x7E).map(|i| i.name),
                Some("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED")
            );
            assert_eq!(bugcheck_name(0x7E0).map(|i| i.name), None);
        }
    }

    mod format_bugcheck_code {
        use super::*;

        #[test]
        fn pads_to_eight_digits() {
            assert_eq!(format_bugcheck_code(0x9F), "0x0000009F");
            assert_eq!(format_bugcheck_code(0x1A), "0x0000001A");
        }

        #[test]
        fn uppercase_hex() {
            assert_eq!(format_bugcheck_code(0xAB), "0x000000AB");
        }
    }
}
