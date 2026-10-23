# hvlab — Hyper-V control plane for agents and humans

Rust implementation of the [PLAN.md](PLAN.md) design. Workspace layout:

| Crate | Contents | Status |
|---|---|---|
| `crates/hvlab-dump` | `DUMP_HEADER64` fast-path parsing, `!analyze -v` text parser, bugcheck catalog | **M0 — done** |
| `crates/hvlab-core` | ids, error taxonomy, plan tokens, VM state | **M0 — done** |
| `crates/hvlab` | binary: `hvlab dump inspect`, CLI dispatch | **M0 — done** |
| `crates/hvlab-host` | WMI v2 management plane | M1 |
| `crates/hvlab-guest` | PS Direct / SSH / serial channels | M4 |
| `crates/hvlab-debug` | DbgEng: dumps + live KD | M5–M6 |
| `crates/hvlab-mcp` | MCP server (rmcp) | M2 |

## Quick start

```powershell
cargo build --release
./target/release/hvlab.exe dump inspect C:\Windows\MEMORY.DMP
```

Parses the crash header and prints the bugcheck in ~20 ms, no debugger
install required:

```text
path: C:\Windows\MEMORY.DMP
os_version: 15.26100
dump_kind: live-kernel
bugcheck_code: 0x00000050
bugcheck_name: PAGE_FAULT_IN_NONPAGED_AREA
description: Invalid system memory was referenced, ...
reference: https://learn.microsoft.com/...
arg1: 0xffffe702711f8000
...
```

## Development

```powershell
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo nextest run --all-features
cargo test --doc
cargo fmt --all -- --check
```

`unwrap`/`expect` are denied outside `#[cfg(test)]` (workspace lints).
`unsafe` is denied everywhere.

## Layout notes

- `hvlab-dump` offset constants are asserted against
  `kdmp_parser::structs::Header64` via `std::mem::offset_of!` in
  `offsets_match_kdmp_parser`. Real dumps on the authoring machine
  caught a wrong `KdDebuggerDataBlock` offset and two missing dump
  types (6 = live-kernel, 4 = mini) — the cross-check exists so the
  next format surprise is a test failure, not a wrong answer.
- Dump-type decoding delegates to `kdmp-parser` rather than a
  hand-maintained table.
