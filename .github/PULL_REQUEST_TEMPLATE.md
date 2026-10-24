<!--
Thanks for the pull request. Keep this short; delete anything that does not
apply.
-->

## What this changes

<!-- One paragraph. What is different after this PR, and why it matters. -->

## Why

<!-- The problem this solves. Link the issue if there is one: Closes #123 -->

## Type

- [ ] Bug fix
- [ ] New tool (registry + router + types)
- [ ] Behaviour change to an existing tool
- [ ] Internal refactor (no observable change)
- [ ] Docs only
- [ ] CI / build

## Safety impact

<!-- Delete if the PR cannot change host, guest, or data state. -->

- [ ] Touches a `D` or `X` tool
- [ ] Adds or changes a WMI mutation
- [ ] Touches guest execution, path policy, or the identity handshake
- [ ] Creates or modifies a test that mutates the host

If any of the above: describe the worst outcome if the code is wrong, and what
prevents it.

> [!WARNING]
> No PR may create an **external** virtual switch or bind a physical adapter.
> That reroutes the host's traffic and can take the machine offline.

## Checklist

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets --all-features --locked -- -D warnings`
- [ ] `cargo test` (or `cargo nextest run --all-features --locked`)
- [ ] `cargo test --doc --locked`
- [ ] `cargo doc --no-deps --all-features` with no warnings
- [ ] New tool registered in `crates/hvlab-mcp/src/registry.rs` (tests enforce this)
- [ ] No `unsafe`, no `unwrap`/`expect` outside `#[cfg(test)]`
- [ ] Host-mutating tests gated behind `HVLAB_ALLOW_HOST_MUTATION_TESTS` and use an RAII guard
- [ ] Docs updated if behaviour or the tool surface changed

## Verification

<!--
How did you confirm this works? "Tests pass" is not verification for a
behavioural change — say what you ran against a real host or guest and what
you observed.
-->
