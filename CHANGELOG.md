# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0, the minor version carries breaking changes. `0.x` releases may change
the tool surface, the error taxonomy, or the CLI between minor versions; patch
releases do not.

## [Unreleased]

### Changed

- `sha2` 0.10 → 0.11 (now on `hybrid-array`). Digest output is unchanged;
  `sha256_hex_matches_published_vectors` pins the FIPS 180-4 known answers so a
  future bump cannot silently alter plan-token digests.
- CI actions moved to their node24 releases (`checkout` v7, `upload-artifact`
  v7, `download-artifact` v8).
- The Ubuntu CI leg runs `hvlab-core` and `hvlab-dump` only; the Windows leg
  runs the full workspace.

### Added

- `sha256_hex_matches_published_vectors`, pinning FIPS 180-4 known answers
  (246 tests on `main`).

## [0.1.0] — 2026-10-24

First public release. An honest `0.1.0`: the host, guest, and dump surfaces are
implemented and tested; live kernel debugging and orchestration are not (see
the Status section of the README).

### Added

**MCP server (`hvlab mcp`, stdio)**

- 42 tools across nine families: `meta`, `host`, `vm`, `checkpoint`, `storage`,
  `network`, `device`, `guest`, `dump`.
- Four safety classes with a single source of truth: 21 read-only, 17 mutating,
  2 destructive, 2 guest-execution.
- Plan tokens for `D`/`X` calls: SHA-256 over the canonicalized action plus the
  exact arguments, single-use, five-minute expiry, enforced centrally before
  dispatch.
- Tool profiles (`HVLAB_TOOLS=core|full|readonly|<names|families>`) and a lean
  listing projection that cuts the advertised payload by ~82% without removing
  any callable tool.
- `hv_tools_search` and `hv_tools_describe` for reaching the long tail under
  any profile.

**Host plane (`hvlab-host`, WMI v2)**

- VM inventory and lifecycle: start, stop (shutdown / save / turnoff), restart,
  reset, pause, resume, wait-for-state, rename.
- VM configuration: read memory, dynamic-memory flag, processors, notes, nested
  virtualization; setters take a `dry_run` that returns a diff without applying.
- Checkpoints: list, create (standard / production / disk-only), restore,
  delete, delete-subtree, rename.
- Storage: VHD/VHDX create, inspect, live state, resize, compact.
- Networking: switch list/create/remove, NIC connect/disconnect. **External
  switches are refused in the backend** — binding a physical adapter can take
  the host offline.
- Devices: attach and detach disks.
- Host facts: computer system, services, default storage roots, default switch.

**Guest execution (`hvlab-guest`, PowerShell Direct)**

- Length-prefixed JSON framing with a hard size cap; malformed frames are
  errors, never salvaged.
- Mandatory identity handshake: a per-session nonce echoed with the guest
  hostname before any payload is sent.
- Out-of-band exit codes; guest stdout can never forge a result.
- SHA-256 verified file transfer in both directions.
- Component-wise guest path allowlist that rejects `..`, substring tricks, and
  case-folded escapes.

**Crash dumps (`hvlab-dump`, `hvlab-debug`)**

- `DUMP_HEADER64` fast path: bugcheck code, name, description, reference, and
  parameters in milliseconds, with no debugger installed. Offsets are asserted
  against `kdmp-parser` so an upstream format change fails a test.
- Full `!analyze -v` analysis through `cdb.exe`, with stack extraction, bounded
  raw log, explicit truncation, and a disk cache keyed by dump fingerprint.
- Dump discovery across the standard roots, newest first, with an explicit
  count of what was skipped.

**CLI (`hvlab`)**

- `hvlab dump inspect <file>`, `hvlab mcp`, `hvlab tools`, `hvlab version`.

**Project**

- 245 tests. CI runs the full suite on Windows, and the portable crates
  (`hvlab-core`, `hvlab-dump`) on Ubuntu as a portability guard, plus `clippy
  -D warnings`, `rustfmt --check`, `cargo-deny`, and `cargo doc` with warnings
  denied.
- No `unsafe` in library code; `unwrap`/`expect` denied outside tests.

### Known limitations

- Live kernel debugging (`hv_kd_*`) is not implemented.
- Guest inspection tools (processes, services, registry, event log) are not
  implemented.
- Console and serial channels are not implemented.
- SSH and Linux guests are not supported.
- Orchestration (`hv_recover`, soak, watchdog, recipes) is not implemented.
- No HTTP transport, artifact server, or metrics endpoint.
- The declarative policy layer (`mode`, `vm_allowlist`) is not built; classes
  and plan tokens are enforced, the TOML policy file is not.
- `hvlab doctor` is a stub.

[Unreleased]: https://github.com/immutex/hvlab-mcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/immutex/hvlab-mcp/releases/tag/v0.1.0
