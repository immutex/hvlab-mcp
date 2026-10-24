# Security Policy

## Supported versions

`hvlab` is pre-1.0. Security fixes land on `main` and are released as patch
versions. Only the latest release is supported.

| Version | Supported |
|---|:---:|
| latest `0.x` | yes |
| older `0.x` | no |

## Reporting a vulnerability

**Do not open a public issue.**

Use GitHub's [private vulnerability reporting](https://github.com/immutex/hvlab-mcp/security/advisories/new)
for this repository. Please include:

- The affected version or commit
- What an attacker gains, and what they need to start with
- Reproduction steps, ideally a failing test
- Whether the issue is reachable from the MCP surface, the CLI, or only from
  the library API

We aim to acknowledge within a few days and to ship a fix or a mitigation
plan within 30 days for issues reachable over the MCP surface.

## Threat model

The full model is in [PLAN.md](PLAN.md) §7.4. The short version, because it
determines what counts as a vulnerability:

| Boundary | Assumption | Control |
|---|---|---|
| **MCP client → server** | The client is trusted to *make requests*, not to be correct. Text an agent reads inside a guest can be attacker-controlled. | Plan tokens for `D`/`X`; per-tool safety classes; typed refusals |
| **Server → guest** | Guest output is untrusted: it may contain a forged exit code, forged metadata, ANSI escapes, or megabytes of garbage. | Out-of-band exit codes with a session nonce; framed metadata; output caps |
| **Server → host** | The server runs with the invoking user's Hyper-V rights and must never widen them. | No elevation, no service install, no driver load anywhere in the code |
| **Server → network** | The host may be on an untrusted network. | No listeners, no telemetry, no phone-home; symbol downloads are opt-in |
| **Secrets** | Passwords and keys must not reach logs, argv, temp files, or error payloads. | Environment or credential store only; structural redaction |

### In scope

- Escaping the plan-token gate: executing a `D`/`X` tool without a valid,
  correctly bound, unconsumed token.
- Command or argument injection into a guest (the design forbids shell
  interpolation; a path that interpolates is a bug).
- Path-allowlist bypass in guest file operations (`..`, symlinks, substring
  tricks, case folding).
- Forging a guest exit code or identity handshake result.
- Binding a physical network adapter, or any operation that can take the
  host's network offline.
- Privilege escalation beyond the invoking user's existing rights.

### Out of scope

- An attacker who already has Hyper-V Administrator rights on the host. Plan
  tokens stop *accidental* and *injected* destructive calls; they are not a
  sandbox against the account running the process.
- Denial of service by a local user with the same rights as the server
  process.
- Vulnerabilities in Hyper-V, WMI, `cdb.exe`, or Windows itself — report those
  to Microsoft.
- The absence of an unimplemented feature listed under "Status" in the README.

## Design commitments

These are properties the project intends to keep. A regression in any of them
is a security bug:

1. No `unsafe` in library code.
2. No elevation attempt, service install, or driver load.
3. No external (physical-adapter) virtual switch creation.
4. Guest payloads never travel through a shell; argv and scripts are
   transported as data.
5. Every `D`/`X` call is authorized against the exact arguments it will run
   with, before it runs.
