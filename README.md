<div align="center">
  <img src="docs/icon.svg" width="96" alt="hvlab logo">

  # hvlab

  **A typed control plane for Hyper-V, as an MCP server and a CLI.**

  [![CI](https://img.shields.io/github/actions/workflow/status/immutex/hvlab-mcp/ci.yml?branch=main&style=flat-square&label=ci)](https://github.com/immutex/hvlab-mcp/actions/workflows/ci.yml)
  [![Rust](https://img.shields.io/badge/rust-1.88%2B-3c873a?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org)
  [![MCP](https://img.shields.io/badge/MCP-stdio-6b5bd2?style=flat-square)](https://modelcontextprotocol.io)
  [![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=flat-square)](LICENSE-MIT)
  [![Windows](https://img.shields.io/badge/platform-Windows%2010%2F11%20%7C%20Server-0078d4?style=flat-square&logo=windows&logoColor=white)](#install)

  [Who it's for](#who-its-for) • [Features](#features) • [Install](#install) • [Quick start](#quick-start) • [Tools](#tools) • [Safety](#safety-model) • [Architecture](#architecture) • [Development](#development) • [Status](#status)
</div>

Hyper-V exposes what you need through four unrelated surfaces: the WMI provider under `root\virtualization\v2`, PowerShell Direct, the Windows debugger, and a pile of cmdlets. Each has its own authentication model, its own failure modes, and its own vocabulary. An agent asked to boot a VM, run a build inside it, and explain why it later crashed has to stitch all four together by hand.

`hvlab` does that stitching once. You get one typed tool surface, one error taxonomy, and one safety model, reachable by an agent over MCP (Model Context Protocol) or by a person from the shell.

Drive Hyper-V from Claude, Cursor, VS Code, or any MCP-compatible client. Script VM provisioning in CI. Triage `MEMORY.DMP` and minidumps without opening WinDbg.

## Who it's for

- **Kernel and driver developers.** Boot a test VM, run the driver, crash it, collect the dump, and read the bugcheck without leaving the agent.
- **Security researchers.** Disposable checkpoints, guest execution over VMBus with no guest networking, and dump extraction.
- **CI and test infrastructure.** Deterministic VM state per test, real exit codes from guest processes, and checkpoint rollback between runs.
- **Homelab and small-fleet operators.** Inventory, power operations, storage cleanup, and switch management.
- **MCP client authors.** A worked example of a typed, safety-gated tool surface that stays cheap in the context window.

## Features

- **Observed state.** A Hyper-V method returning `4096` means a job started, so every mutation polls its `Msvm_ConcreteJob` to a terminal state and then reads the object back before reporting success.
- **Cheap in a context window.** The default profile advertises 18 tools at roughly 1.7k tokens. All 42 stay callable by name. See [Context cost](#context-cost).
- **Plan tokens for destructive work.** Class `D` and `X` tools take a digest-bound, single-use token that expires in five minutes, so a boolean `confirm` never authorizes a delete.
- **No `unsafe`, no FFI.** Subprocesses appear only where no API exists, always with redirected stdio and a process tree that can be killed.
- **Typed failures.** One error channel with stable codes, each carrying `retryable`, `context`, and a `correlation_id`.

## Install

Requires **Windows 10/11 or Windows Server with the Hyper-V role** and **Rust 1.88+**.

```powershell
cargo install --path crates/hvlab
```

Prebuilt `hvlab.exe` binaries for x64 and ARM64 are attached to each
[release](https://github.com/immutex/hvlab-mcp/releases), and each zip carries a
SHA-256 next to the binary.

Or build from source:

```powershell
git clone https://github.com/immutex/hvlab-mcp
cd hvlab-mcp
cargo build --release
```

> [!NOTE]
> Inventory and mutation tools need **Hyper-V Administrators** membership or an elevated shell. `hvlab` never attempts to elevate. When the provider filters instances out, it reports `hv.permission` instead of claiming the host has no VMs.

## Quick start

### Inspect a crash dump

This reads the header only. No debugger installed, no symbol download:

```powershell
hvlab dump inspect C:\Windows\MEMORY.DMP
```

Output for a kernel dump with bugcheck `0x50`, in the tool's own field order:

```text
path: C:\Windows\MEMORY.DMP
os_version: 15.26100
dump_kind: kernel
bugcheck_code: 0x00000050
bugcheck_name: PAGE_FAULT_IN_NONPAGED_AREA
description: Invalid system memory was referenced, typically in the non-paged pool.
reference: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2
arg1: 0xffffe702711f8000
arg2: 0x0
arg3: 0xfffff8024a1b2c3d
arg4: 0x2
directory_table_base: 0x1a000
kd_debugger_data_block: 0xfffff8024a3f0000
```

It reads `DUMP_HEADER64` and stops, which is why the cost is milliseconds regardless of dump size. Full `!analyze -v` is a separate tool, `hv_dump_analyze`, that runs `cdb.exe` and caches results by dump fingerprint.

### Run the MCP server

```powershell
hvlab mcp
```

Register it with any MCP host:

```json
{
  "mcpServers": {
    "hvlab": {
      "command": "C:\\path\\to\\hvlab.exe",
      "args": ["mcp"]
    }
  }
}
```

If your guests require a logon password, PowerShell Direct needs a credential. Set `HVLAB_GUEST_USER` to the account name, and put the password in the variable named by `HVLAB_GUEST_PASSWORD_ENV` (default `HVLAB_GUEST_PASSWORD`):

```json
{
  "mcpServers": {
    "hvlab": {
      "command": "C:\\path\\to\\hvlab.exe",
      "args": ["mcp"],
      "env": { "HVLAB_GUEST_USER": "LAB\\Administrator" }
    }
  }
}
```

The password travels inside the framed sidecar channel and becomes a `PSCredential` in the sidecar. It never reaches a command line, a temp file, or a log line. Set both variables or neither: with only one set, the server runs credential-less rather than sending an empty password. Guests that allow credential-free PS Direct behave as before.

Then an agent can do this (shapes shown, values elided):

```text
hv_vm_list                       → [ { id: "vm-<guid>", name: "build-01", state: "running" } ]
hv_vm_stop      { vm, mode: "save" }         → waits for the job, returns observed state
hv_guest_exec   { vm, program: "C:\\tools\\build.exe", argv: ["--release"] }
                                 → { exit_code: 0, stdout: "…", stderr: "" }
hv_dump_find    { limit: 3 }     → newest first, with an explicit skipped count
hv_dump_analyze { path }         → bugcheck, faulting module, stack, cached: true
```

### List what is available

```powershell
hvlab tools
```

```text
R  core  hv_capabilities          meta        Static server info: version, protocol, registered tool count, and …
R  core  hv_vm_list               vm          List all Hyper-V VMs on the host with their states.
M  core  hv_vm_start              vm          Start a VM and wait until it reaches Running (or the deadline).
D  -     hv_checkpoint_delete     checkpoint  Delete a checkpoint (class D). Mint a plan token with hv_plan for these …
X  core  hv_guest_exec            guest       Run a program in a guest via PowerShell Direct. argv form, no shell. …
```

## Tools

42 tools across nine families and four safety classes: 21 read-only, 17 mutating, 2 destructive, 2 guest-execution.

| Class | Meaning | Gate |
|:---:|---|---|
| **R** | Read-only: nothing changes | none |
| **M** | Mutating, reversible | none |
| **D** | Destructive: restore, delete | plan token |
| **X** | Arbitrary code execution in a guest | plan token |

| Family | Count | Highlights |
|---|:---:|---|
| `meta` | 5 | `hv_capabilities`, `hv_plan`, `hv_tools_search`, `hv_tools_describe`, `hv_tools_list` |
| `host` | 4 | host facts, services, storage roots, default switch |
| `vm` | 11 | list/get, start/stop/restart, wait-for-state, config, memory, processors, notes |
| `checkpoint` | 4 | list, create (standard / production / disk-only), restore, delete |
| `storage` | 5 | VHD/VHDX create, inspect, live state, resize, compact |
| `network` | 5 | switch list/create/remove, NIC connect/disconnect |
| `device` | 2 | attach and detach disks |
| `guest` | 3 | PowerShell Direct: ping, exec (argv form), powershell |
| `dump` | 3 | find, inspect (under 5 ms), analyze (cached) |

### Context cost

A harness bills the model for every tool definition it receives. Sending all 42 tools with their output schemas costs about 11k tokens, and roughly half of that is `outputSchema`, which no client needs in order to choose a tool.

So `tools/list` is a discovery surface, and results carry the rest:

| Profile (`HVLAB_TOOLS`) | Advertised | ≈ tokens |
|---|:---:|---:|
| `core` *(default)* | 18 | 1.7k |
| `readonly` | 21 | 1.4k |
| `full` | 42 | 4.5k |
| `guest,dump` or `hv_vm_list,…` | names or families | varies |

Advertised tools are sent lean: no `outputSchema`, no `$schema` URI, and one-line descriptions. Results are unchanged, because callers still receive `structuredContent`.

Tools outside the profile remain callable by name, and that falls out of how dispatch resolves rather than from a convention. The router looks up the tool name and validates arguments from the handler's own type, and neither path consults the advertised list. `hv_tools_search` finds any tool and `hv_tools_describe` returns its exact schema. Tests `unlisted_tools_still_dispatch` and `advertised_listing_stays_within_its_context_budget` pin both properties.

## Safety model

> [!IMPORTANT]
> `hvlab` runs with **your** Hyper-V rights and never widens them. No elevation, no service install, no driver load, no `vmms` restart.

**Plan tokens for destructive work.** Class `D` and `X` tools require `confirm: { plan_id, digest }`. The digest is SHA-256 over the canonicalized action plus the exact arguments. Tokens are single-use and expire after five minutes.

```text
hv_plan { action: "hv_checkpoint_delete",
          args:   { vm: "build-01", checkpoint: "pre-upgrade" } }
     → { plan_id: "plan-<ulid>", digest: "<sha256 hex>", expires_at: "…" }

hv_checkpoint_delete { vm: "build-01", checkpoint: "pre-upgrade",
                       confirm: { plan_id: "plan-<ulid>", digest: "<sha256 hex>" } }
```

A token minted for different arguments is refused, and a consumed token cannot be replayed.

**No tool binds a physical NIC.** An external switch would route the host's traffic through a virtual switch and can take the machine offline. `hv_switch_create` offers only `internal` and `private`, and the backend refuses `External` even when a real adapter is named.

**Guest execution proves where it is.** Before any payload is sent, the channel issues a per-session nonce that the guest must echo with its hostname. Exit codes travel out-of-band in the envelope and are never scraped from stdout, so guest output cannot forge a result.

**Failures are typed.** There is one error channel, with stable codes such as `hv.not_found`, `hv.policy_denied`, `hv.guest_identity`, and `hv.permission`. Each carries `retryable`, `context`, and a `correlation_id`. Truncation is always declared through the `truncated` and `dropped_bytes` fields.

## Architecture

Seven crates, layered so the pure ones stay portable:

| Crate | Responsibility |
|---|---|
| `hvlab-core` | identifiers, error taxonomy, plan tokens, VM state (no platform deps) |
| `hvlab-dump` | `DUMP_HEADER64` parsing, `!analyze -v` text parser, bugcheck catalog (no platform deps) |
| `hvlab-host` | WMI v2 management plane: lifecycle, config, checkpoints, storage, networking, devices |
| `hvlab-guest` | PowerShell Direct channel: framed protocol, identity nonce, path policy, verified transfers |
| `hvlab-debug` | dump analysis through `cdb.exe`, disk cache, dump discovery (no FFI) |
| `hvlab-mcp` | MCP server, tool registry, profiles, plan gate |
| `hvlab` | the CLI |

```text
hvlab (CLI) ──► hvlab-mcp ──► hvlab-host  ──► WMI v2
                    │      ──► hvlab-guest ──► PowerShell Direct
                    │      ──► hvlab-debug ──► cdb.exe
                    └──► hvlab-dump ──► hvlab-core
```

Two implementation details exist to prevent silent wrong answers:

- Dump offsets are cross-checked against `kdmp-parser` through `std::mem::offset_of!`, so an upstream format change fails a test instead of yielding a wrong field.
- A vanished job is not treated as a failure. Completed `Msvm_ConcreteJob` instances are reaped after roughly five minutes, so absence triggers a verification read of the effect.

## Development

```powershell
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo nextest run --all-features --locked
cargo test --doc --locked
cargo fmt --all -- --check
cargo doc --no-deps --all-features
```

There are 246 tests. CI runs the full suite on `windows-latest` and, on `ubuntu-latest`, the two pure crates (`hvlab-core`, `hvlab-dump`). That second leg is what stops them from picking up a Windows dependency unnoticed. `cargo-deny` checks advisories, licenses, and sources.

Lints are strict on purpose. `unsafe_code = "deny"` applies workspace-wide, with tests opting out only to set process environment variables. `unwrap_used` and `expect_used` are denied outside `#[cfg(test)]`, and `clippy::all` is denied.

### Tests that mutate the host

Tests that create real checkpoints, disks, or switches are **off by default** and clean up through RAII guards, so a panic mid-test cannot leak state:

```powershell
$env:HVLAB_ALLOW_HOST_MUTATION_TESTS = "1"
cargo test -p hvlab-host
```

No test binds a physical adapter.

## Status

Implemented: host facts, VM lifecycle and configuration, checkpoints, VHD/VHDX storage, networking, devices, PowerShell Direct execution including credential-bearing guest sessions, and crash-dump triage.

The MCP server is the full surface. The CLI is narrower: it has `dump inspect`, `tools`, `mcp` and a stub `doctor`, so VM lifecycle, checkpoints and guest execution are reachable only over MCP.

Not implemented. These are design targets in [PLAN.md](PLAN.md), not current features:

- Live kernel debugging (`hv_kd_*`): attach, break, step, breakpoints
- Guest inspection (processes, services, registry, event log)
- Console and serial channels
- SSH guest channel and Linux guest support
- Orchestration: `hv_recover`, soak runs, watchdog, recipes
- HTTP transport, artifact server, metrics
- The declarative policy layer (`mode`, `vm_allowlist`). Classes and plan tokens are enforced; the TOML policy file is not built
- Secret storage beyond the environment. Guest credentials are read from environment variables only; Windows Credential Manager support (PLAN.md §7.3) is not built
- `hvlab doctor`, currently a stub

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first, and note that this project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Licensed under either the [Apache License, Version 2.0](LICENSE-APACHE) or the [MIT license](LICENSE-MIT), at your option. See [NOTICE](NOTICE) for attribution.
