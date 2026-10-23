//! The `DUMP_HEADER64` struct, read directly from the first bytes of a
//! dump file.
//!
//! Layout reference: `dbgeng.h` / the Windows crash-dump format, as
//! modelled by `kdmp-parser`. Every field is decoded from a fixed index
//! of a fixed-size buffer, so there is no slicing, no `expect`, and no
//! panic path in the parser.

use std::fmt;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Errors from reading a dump header.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HeaderError {
    /// The path could not be read.
    #[error("io error reading {path}: {source}")]
    Io {
        /// The path that failed.
        path: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The file is smaller than the 64-bit dump header.
    #[error("file too small for DUMP_HEADER64: {size} bytes, need {needed}")]
    TooSmall {
        /// Actual file size in bytes.
        size: u64,
        /// Bytes required for a full header.
        needed: u64,
    },
    /// The `Signature` field does not match the expected value.
    #[error("bad signature {actual:#010x}: not a Windows crash dump")]
    BadSignature {
        /// The value read from offset 0x00.
        actual: u32,
    },
    /// The `ValidDump` field does not match the expected value.
    #[error("bad ValidDump {actual:#010x}: header present but dump data is invalid")]
    BadValidDump {
        /// The value read from offset 0x04.
        actual: u32,
    },
    /// A 32-bit dump header — supported only through the debugger path.
    #[error("32-bit dump header (Signature {signature:#010x}): use the debugger path")]
    ThirtyTwoBit {
        /// The signature that identified it as 32-bit.
        signature: u32,
    },
}

/// Expected `DUMP_HEADER64.Signature` — bytes `50 41 47 45` ("PAGE").
pub const EXPECTED_SIGNATURE: u32 = 0x4547_4150;
/// Expected `DUMP_HEADER64.ValidDump` — bytes `44 55 36 34` ("DU64").
pub const EXPECTED_VALID_DUMP: u32 = 0x3436_5544;

/// Signature marking a 32-bit dump header (different layout entirely).
pub const SIGNATURE_32BIT: u32 = 0x504D_5544; // "PMDU" little-endian

/// Size in bytes of the fields this crate reads: through
/// `KdDebuggerDataBlock` at 0x80 (8 bytes), i.e. 0x88. This is well
/// inside the real 8 KB `DUMP_HEADER64`; only the fields the fast path
/// reports are read.
pub const HEADER_BYTES_NEEDED: usize = 0x88;

/// Byte offset of `MajorVersion`.
pub const OFFSET_MAJOR_VERSION: usize = 0x08;
/// Byte offset of `MinorVersion`.
pub const OFFSET_MINOR_VERSION: usize = 0x0C;
/// Byte offset of `DirectoryTableBase`.
pub const OFFSET_DIRECTORY_TABLE_BASE: usize = 0x10;
/// Byte offset of `PfnDataBase`.
pub const OFFSET_PFN_DATABASE: usize = 0x18;
/// Byte offset of `KdDebuggerDataBlock`.
///
/// Verified against `kdmp_parser::structs::Header64` via
/// `std::mem::offset_of!` (see the `offsets_match_kdmp_parser` test); a real
/// 373 MB dump caught this being 0x28 (which is `PsActiveProcessHead`).
pub const OFFSET_KDDEBUGGER_DATA_BLOCK: usize = 0x80;
/// Byte offset of `BugCheckCode`.
pub const OFFSET_BUGCHECK_CODE: usize = 0x38;
/// Byte offset of `BugCheckCodeParameter[0]`.
pub const OFFSET_BUGCHECK_PARAMS: usize = 0x40;
/// Byte offset of `DumpType` in full and kernel dumps.
pub const OFFSET_DUMP_TYPE: usize = 0xF98;

/// The kind of dump, decided from `DumpType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DumpKind {
    /// Full physical-memory dump.
    Full,
    /// Kernel-memory dump.
    Kernel,
    /// Small/triage dump, or a user-mode minidump.
    Triage,
    /// Bitmap dump.
    Bitmap,
    /// Active-memory dump.
    Active,
    /// Complete-memory dump.
    Complete,
    /// Kernel-and-user memory dump.
    KernelUser,
    /// Live kernel memory dump, produced without a crash (22H2+).
    LiveKernel,
    /// Unrecognized `DumpType`; carried so callers can decide.
    Unknown(u32),
}

impl DumpKind {
    /// Whether kernel-mode triage logic (bugcheck reasoning) applies.
    ///
    /// A user-mode dump has no bugcheck; applying kernel semantics to it
    /// produces confident nonsense.
    #[must_use]
    pub fn is_kernel(self) -> bool {
        !matches!(self, Self::Triage | Self::Unknown(_))
    }

    /// Decode a `DumpType` value.
    ///
    /// The mapping comes from `kdmp-parser`, which is validated against
    /// real dumps. Hand-maintained tables drift: a 373 MB dump on the
    /// authoring machine reported type `6` (live kernel memory) and a
    /// minidump reported `4` (mini), neither of which a guessed
    /// 1/2/3-style table covers.
    #[must_use]
    pub fn from_dump_type(dt: u32) -> Self {
        match kdmp_parser::structs::DumpType::try_from(dt) {
            Ok(kdmp_parser::structs::DumpType::Full) => Self::Full,
            Ok(kdmp_parser::structs::DumpType::Bmp) => Self::Bitmap,
            Ok(kdmp_parser::structs::DumpType::LiveKernelMemory) => Self::LiveKernel,
            Ok(kdmp_parser::structs::DumpType::KernelMemory) => Self::Kernel,
            Ok(kdmp_parser::structs::DumpType::KernelAndUserMemory) => Self::KernelUser,
            Ok(kdmp_parser::structs::DumpType::CompleteMemory) => Self::Complete,
            Err(_) => Self::Unknown(dt),
        }
    }

    /// Whether a raw `DumpType` value is one `kdmp-parser` recognizes.
    #[must_use]
    pub fn is_plausible(dt: u32) -> bool {
        kdmp_parser::structs::DumpType::try_from(dt).is_ok()
    }
}

impl fmt::Display for DumpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Full => "full",
            Self::Kernel => "kernel",
            Self::Triage => "triage",
            Self::KernelUser => "kernel-user",
            Self::Bitmap => "bitmap",
            Self::Active => "active",
            Self::Complete => "complete",
            Self::LiveKernel => "live-kernel",
            Self::Unknown(dt) => return write!(f, "unknown({dt})"),
        };
        f.write_str(name)
    }
}

/// Reads little-endian integers out of a fixed-size buffer by index.
/// Indexing a `[u8; N]` with a constant is infallible; no slicing.
fn le32(buf: &[u8; HEADER_BYTES_NEEDED], o: usize) -> u32 {
    u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]])
}

fn le64(buf: &[u8; HEADER_BYTES_NEEDED], o: usize) -> u64 {
    u64::from_le_bytes([
        buf[o],
        buf[o + 1],
        buf[o + 2],
        buf[o + 3],
        buf[o + 4],
        buf[o + 5],
        buf[o + 6],
        buf[o + 7],
    ])
}

/// The leading bytes of a 64-bit Windows crash dump: everything needed
/// to say *which crash happened* without opening the rest of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DumpHeader64 {
    /// `MajorVersion` / `MinorVersion` — the OS build that wrote the dump.
    pub os_version: (u32, u32),
    /// `DirectoryTableBase` — the kernel `CR3` at crash time.
    pub directory_table_base: u64,
    /// `PfnDataBase`.
    pub pfn_database: u64,
    /// `KdDebuggerDataBlock`.
    pub kd_debugger_data_block: u64,
    /// `BugCheckCode` — the stop code.
    pub bug_check_code: u32,
    /// `BugCheckCodeParameter[0..4]`.
    pub bug_check_parameters: [u64; 4],
}

impl DumpHeader64 {
    /// Read and validate a header from an open reader.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderError::TooSmall`] for files under
    /// [`HEADER_BYTES_NEEDED`], [`HeaderError::BadSignature`] or
    /// [`HeaderError::BadValidDump`] for non-dump files, and
    /// [`HeaderError::ThirtyTwoBit`] for 32-bit headers (whose layout
    /// differs; route those to the debugger path instead).
    pub fn read_from_reader<R: std::io::Read>(mut reader: R) -> Result<Self, HeaderError> {
        let mut buf = [0u8; HEADER_BYTES_NEEDED];
        let mut filled = 0usize;
        while filled < buf.len() {
            let n = reader
                .read(&mut buf[filled..])
                .map_err(|source| HeaderError::Io {
                    path: "<reader>".into(),
                    source,
                })?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled < HEADER_BYTES_NEEDED {
            return Err(HeaderError::TooSmall {
                size: filled as u64,
                needed: HEADER_BYTES_NEEDED as u64,
            });
        }
        Self::from_bytes(&buf)
    }

    /// Decode an already-read header image.
    ///
    /// # Errors
    ///
    /// [`HeaderError::BadSignature`], [`HeaderError::BadValidDump`], or
    /// [`HeaderError::ThirtyTwoBit`].
    pub fn from_bytes(buf: &[u8; HEADER_BYTES_NEEDED]) -> Result<Self, HeaderError> {
        let signature = le32(buf, 0x00);
        if signature == SIGNATURE_32BIT {
            return Err(HeaderError::ThirtyTwoBit { signature });
        }
        if signature != EXPECTED_SIGNATURE {
            return Err(HeaderError::BadSignature { actual: signature });
        }
        let valid_dump = le32(buf, 0x04);
        if valid_dump != EXPECTED_VALID_DUMP {
            return Err(HeaderError::BadValidDump { actual: valid_dump });
        }
        Ok(Self {
            os_version: (
                le32(buf, OFFSET_MAJOR_VERSION),
                le32(buf, OFFSET_MINOR_VERSION),
            ),
            directory_table_base: le64(buf, OFFSET_DIRECTORY_TABLE_BASE),
            pfn_database: le64(buf, OFFSET_PFN_DATABASE),
            kd_debugger_data_block: le64(buf, OFFSET_KDDEBUGGER_DATA_BLOCK),
            bug_check_code: le32(buf, OFFSET_BUGCHECK_CODE),
            bug_check_parameters: [
                le64(buf, OFFSET_BUGCHECK_PARAMS),
                le64(buf, OFFSET_BUGCHECK_PARAMS + 8),
                le64(buf, OFFSET_BUGCHECK_PARAMS + 16),
                le64(buf, OFFSET_BUGCHECK_PARAMS + 24),
            ],
        })
    }

    /// Read and validate a header from a file path.
    ///
    /// # Errors
    ///
    /// Same conditions as [`Self::read_from_reader`], plus I/O failures.
    pub fn read_from(path: impl AsRef<Path>) -> Result<Self, HeaderError> {
        let path = path.as_ref();
        let file = std::fs::File::open(path).map_err(|source| HeaderError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::read_from_reader(std::io::BufReader::new(file)).map_err(|e| match e {
            // Keep the real path in any I/O error from this point on.
            HeaderError::Io { source, .. } => HeaderError::Io {
                path: path.display().to_string(),
                source,
            },
            other => other,
        })
    }

    /// Read the `DumpType` field for a dump at `path`.
    ///
    /// # Errors
    ///
    /// I/O errors reading the type field.
    pub fn read_kind(&self, path: impl AsRef<Path>) -> Result<DumpKind, HeaderError> {
        let path = path.as_ref();
        let display = path.display().to_string();
        let mut file = std::fs::File::open(path).map_err(|source| HeaderError::Io {
            path: display.clone(),
            source,
        })?;
        let mut buf4 = [0u8; 4];
        file.seek(SeekFrom::Start(OFFSET_DUMP_TYPE as u64))
            .map_err(|source| HeaderError::Io {
                path: display.clone(),
                source,
            })?;
        file.read_exact(&mut buf4)
            .map_err(|source| HeaderError::Io {
                path: display.clone(),
                source,
            })?;
        Ok(DumpKind::from_dump_type(u32::from_le_bytes(buf4)))
    }
}

impl fmt::Display for DumpHeader64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "bugcheck {:#x} ({},{}) dtb {:#x}",
            self.bug_check_code, self.os_version.0, self.os_version.1, self.directory_table_base
        )
    }
}
