# Contributing to hvlab

Thanks for taking the time to contribute. This document is short on ceremony
and specific about what makes a patch land smoothly.

## Ways to contribute

- **Bug reports** — the most useful thing you can send. Include the command,
  the exact output, your Windows build (`winver`), and whether you are in
  **Hyper-V Administrators** or elevated.
- **Triage notes** — if you hit a Hyper-V quirk and found the cause, open an
  issue even without a fix. The hazard ledger in [PLAN.md](PLAN.md) §9 exists
  because these traps get rediscovered constantly.
- **Code** — see below.
- **Docs** — corrections to the README or crate docs are welcome as small PRs.

## Before you open a pull request

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo nextest run --all-features --locked    # or: cargo test
cargo test --doc --locked
cargo doc --no-deps --all-features           # RUSTDOCFLAGS="-D warnings"
```

All five must pass. CI runs the same set, plus `cargo-deny` for advisories,
licenses, and sources.

## Ground rules

### No `unsafe`

The workspace sets `unsafe_code = "deny"`. If you believe you need `unsafe`,
open an issue first — the answer is usually a different design, and the
subprocess boundary in `hvlab-debug` is the precedent for how to avoid FFI.

### No `unwrap` / `expect` outside tests

Also denied workspace-wide. Tests opt out with
`#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]`
at the crate root.

### Errors are typed, never invented

Return `hvlab_core::error::HvError` with a code from the existing taxonomy.
Do not add a new code without updating the table in [PLAN.md](PLAN.md) §6 — an
unmapped code is worse than a generic one, because clients branch on it.

Never return a success-shaped object carrying a failure. If something failed,
return `Err`. If a result is partial, attach it via `HvError::partial` and
declare truncation explicitly.

### Report observed state, not intent

After any mutation, read the object back and return what the host reports.
A Hyper-V method returning `4096` means *a job was created*, not that it
worked — poll `Msvm_ConcreteJob` to a terminal state first.

### Tests must be able to fail

A test that cannot fail for a real reason is removed in review. Specifically
avoid: asserting a value equals itself, `assert!(x.is_ok())` with no behaviour
assertion, re-pinning incidental formatting, and count assertions of the form
`>= N` where `N` can only ratchet upward.

### Host-mutating tests are opt-in

Any test that creates a real checkpoint, disk, or switch must:

1. Be gated behind `HVLAB_ALLOW_HOST_MUTATION_TESTS=1`, and
2. Clean up through an RAII guard, so a mid-test panic cannot leak state.

> [!WARNING]
> **Never write a test that binds a physical network adapter** — that is, never
> create an *external* virtual switch. It reroutes the host's traffic and takes
> the machine offline. `hvlab` refuses external switches in the backend for
> exactly this reason; do not work around it.

## Adding a tool

The tool registry is a single table; adding a tool in only one place is a
build failure by design.

1. Add the argument and result types to `crates/hvlab-mcp/src/tools.rs`
   (`serde` + `schemars::JsonSchema` derives, doc comments on every field —
   they become the schema descriptions).
2. Add a `#[tool]` method to the `#[tool_router] impl HvlabServer` in
   `crates/hvlab-mcp/src/lib.rs`.
3. Register it in `crates/hvlab-mcp/src/registry.rs` with its safety class,
   family, and whether it belongs to the `core` profile.
4. Update the pinned name set in the `registry_and_router_agree` /
   `registry_count_is_exact_and_names_match` tests.

Tests enforce that the registry and the router agree exactly, so step 3 cannot
be forgotten.

### Choosing a safety class

| Class | Use when | Gate |
|---|---|---|
| `R` | Nothing changes. Safe to call in a loop. | none |
| `M` | Reversible change to a VM, disk, or switch. | none |
| `D` | Destroys data or discards state (delete, restore). | plan token |
| `X` | Executes arbitrary code in a guest. | plan token |

When in doubt, choose the more restrictive class. An unregistered tool name
defaults to `D`, so a mistake fails closed.

### Keep the context budget

The `core` profile has a byte budget enforced by
`advertised_listing_stays_within_its_context_budget`. If your tool belongs in
`core`, check that the budget still holds; if it does not, the tool probably
belongs in the long tail, reachable via `hv_tools_search`.

## Commit messages

Present tense, imperative, and specific about *why*:

```text
Poll Msvm_ConcreteJob instead of sleeping after VM start

A fixed sleep reported whatever state happened to be visible, which made
start look successful while the VM was still transitioning.
```

One logical change per commit. If a commit needs "and" in its subject, it is
probably two commits.

## Reporting a security issue

Please do **not** open a public issue for a vulnerability. Use GitHub's
[private vulnerability reporting](https://github.com/immutex/hvlab-mcp/security/advisories/new) on this
repository. We will acknowledge within a few days.

## License

By contributing, you agree that your contributions are licensed under
MIT OR Apache-2.0, at your option, as described in [LICENSE-MIT](LICENSE-MIT)
and [LICENSE-APACHE](LICENSE-APACHE).
