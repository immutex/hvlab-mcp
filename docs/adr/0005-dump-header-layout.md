# ADR 0005 — dump header layout authority

## Status

Accepted (M0)

## Context

`hvlab-dump` reads `DUMP_HEADER64` fields by constant offset for the
sub-5-millisecond fast path. Two sources of truth are possible:

1. Hand-maintained offset constants in this crate.
2. `kdmp_parser::structs::Header64`'s `repr(C)` field layout, checked
   via `std::mem::offset_of!`.

A hand-maintained table already went wrong once: `KdDebuggerDataBlock`
was placed at `0x28` (that is `PsActiveProcessHead`); the real offset is
`0x80`. Two real dumps on the authoring machine also exposed dump types
`6` (live-kernel memory) and `4` (mini) missing from a guessed
`DumpType` decode table.

## Decision

1. `kdmp-parser`'s `Header64` is the **layout authority**. Every offset
   constant in `hvlab-dump::header` is asserted equal to
   `offset_of!(Header64, field)` in `offsets_match_kdmp_parser`. A
   layout change upstream is a compile/test failure here, not a wrong
   answer in production.
2. `DumpType` decoding **delegates** to `kdmp_parser::structs::DumpType`
   rather than a hand-written table. `hvlab-dump` maps the upstream
   variants to its own `DumpKind` enum.
3. The header read window is `0x88` bytes — through
   `KdDebuggerDataBlock` — not the `0x60` the first draft assumed.

## Consequences

- A synthetic fixture alone cannot validate offsets; the regression
  suite must keep at least one real-dump byte comparison (the two
  fixture dumps in `tests/`).
- New upstream dump types surface as `DumpKind::Unknown(n)` and are
  reported verbatim, never guessed into a real kind.
