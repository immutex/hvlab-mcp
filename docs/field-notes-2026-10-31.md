# Field notes — hvlab against a real kernel-driver lab (2026-10-31)

**Scope of these notes.** Observations from using hvlab (release build of
`aac6a92`, plus the earlier debug build) side-by-side with a hand-rolled
Hyper-V lab harness (Python + `labctl` over Hyper-V cmdlets, PowerShell
Direct, and kd-over-COM-pipe) while developing a kernel driver against a
Windows 11 26100 guest. Every item is stated generally: it should apply
to any user automating Hyper-V guest work, not just this lab. Items are
tagged VERIFIED (reproduced here), INHERITED (read in the source, not
exercised), or PROPOSAL.

## 1. Guest sessions cannot carry a credential (VERIFIED blocker for password guests)

`hvlab-guest`'s sidecar creates the PowerShell Direct session with
`New-PSSession -VMName $vmName` and no `-Credential`
(`crates/hvlab-guest/src/sidecar.rs:57`); `PsDirectSession::open` takes
only a VM name and an optional expected hostname
(`crates/hvlab-guest/src/psdirect.rs:329`). On any guest whose logon
requires a password — the normal case for a provisioned test VM —
session creation fails and the whole guest family (`hv_guest_ping`,
`hv_guest_exec`, `hv_guest_powershell`, file transfer) is unusable,
because PS Direct always prompts for / requires credentials.

PLAN.md §8 already describes the intended shape (`[guest] username`,
`password_env = "HVLAB_GUEST_PASSWORD"`, `HVLAB_GUEST_USER`), but no
code reads those environment variables yet (INHERITED: no match for
`HVLAB_GUEST` under `crates/`).

General improvement: thread an optional credential (user + secret from
env or Credential Manager, per PLAN.md §7.3) into
`PsDirectSession::open` and the sidecar, building a `PSCredential` in
the sidecar from values passed over the framed channel — never in
argv, never in a temp file. Guests that allow credential-less PS
Direct keep working unchanged.

**Update (same day): implemented.** `GuestCredential` +
`PsDirectSession::open_with_credential` / `open_with_command_and_credential`;
the sidecar creates its session lazily (on `auth`, else on `ident`)
and reports the real session flag; the MCP layer reads
`HVLAB_GUEST_USER` plus the password env (`HVLAB_GUEST_PASSWORD`,
overridable via `HVLAB_GUEST_PASSWORD_ENV`). Hermetic tests cover
auth-before-identity ordering, refused-credential failure, Debug
redaction, and absence of the password from the sidecar command
line. Clippy/fmt/workspace tests green (246+3). Credential Manager
storage (§7.3) remains open.

## 2. The CLI ships three verbs; the other 39 tools are MCP-only (VERIFIED)

`hvlab` (release build) implements `dump inspect`, `tools`, `mcp`, and
a stub `doctor`. VM lifecycle, checkpoints, and guest execution exist
only behind the MCP server. PLAN.md §0.1/§1 states "every capability
is reachable both as an MCP tool and as a CLI verb, with the same
schema and the same result", and the README quick-start shows
`hvlab vm list`-style usage that the binary does not accept (it
prints USAGE). This is the correct long-term shape — it is also the
single most surprising first-run experience: a scripted user who
cannot run an MCP host today has no hvlab at all.

General improvement: either generate thin CLI verbs from the same
registry (the schemas already exist), or mark the gap explicitly in
the README/PLAN until the CLI catches up. The registry-driven option
is preferable: it prevents the two surfaces drifting.

## 3. `hv_vm_list` as an elevation probe (VERIFIED behavior, PROPOSAL)

From a medium-integrity shell, Hyper-V's WMI/cmdlet surface filters
VMs out silently: `Get-VM` errors, and a naive list returns empty.
hvlab's README already promises the right taxonomy (`hv.permission`
rather than "no VMs"). Worth pinning with a test: run `hv_vm_list`
un-elevated on a host that has VMs and assert the typed permission
error (or an explicit `visible: 0, reason: permission` shape) instead
of `[]`. An agent that believes "no VMs exist" will happily "fix"
the wrong problem — in our harness this misread cost real time.

## 4. `doctor` is a stub (VERIFIED)

`hvlab doctor` prints "not yet implemented (milestone M2)" and exits
non-zero. The PLAN.md §0.5 sample output (Hyper-V role, vmms,
Hyper-V Administrators membership, debugger presence, symbol cache,
VM visibility) is exactly the checklist a first-run user needs
*before* the first guest command — several of our lab failures
(un-elevated shell, guest credentials unset, debugger missing) are
doctor-shaped facts discoverable in seconds. Implementing even the
read-only half would remove a whole class of "tool X failed" reports.

## 5. No KDNET/COM attach means crash *cause* questions still leave hvlab (INHERITED)

README already lists live kernel debugging (`hv_kd_*`) as not
implemented; recording the field evidence for prioritization: in a
driver lab, the recurring question "what is this thread doing right
now, and why won't this process die" cannot be answered from dumps
alone when the machine has not crashed. Today's fallback is
kd.exe-over-pipe driven by hand, which is the most failure-prone
surface we used (attach only succeeds at a halted target; scripting
`g` vs. break-in state by stdin is a recurring trap). The PLAN.md
§5.12 design (DbgEng in-process, `target_running: true` instead of a
hang) addresses precisely this. No change requested beyond noting
that, empirically, this is the gap users will hit first after guest
execution.

## 5a. `hv_vm_list` fails on a healthy Hyper-V host (VERIFIED 2026-10-31, later same day)

From an elevated shell (High integrity, Hyper-V Administrators), the
MCP call `hv_vm_list` returns `hv.transport: WMI query failed:
HRESULT Call failed with: 0x80041002` (WBEM_E_NOT_FOUND). The host is
provably healthy: the identical WQL
(`SELECT Name, ElementName, EnabledState FROM Msvm_ComputerSystem
WHERE Caption = 'Virtual Machine'`) returns the VM via
`Get-WmiObject`, and `Msvm_VirtualSystemManagementService` resolves.
The failure is therefore inside hvlab's own WMI layer (the
`check_management_visible` -> `service_path` ->
`SELECT * FROM Msvm_VirtualSystemManagementService` path, or the
`wmi` crate's handling of that singleton), not the host or the
caller's rights. The typed error also misleads: this is the H-38
surface, and it reported `transport` where the caller can act on
neither transport nor permission. Worth a host-mutation-gated test
that opens a real session and lists, so the WMI layer cannot regress
behind the hermetic suite.

## 6. Verified working, for the record (VERIFIED)

- Release build (`cargo build --release`, Rust 1.99.1): builds clean
  with the workspace's denied lints.
- MCP stdio: `initialize` + `tools/list` handshake correct;
  `HVLAB_TOOLS=full` advertises all 42 tools; server instructions
  describe the profile system accurately.
- `hvlab tools`: 42 registered, classes/families as documented.
- `hvlab dump inspect` on a missing path fails with a typed IO error
  and exit code 1 (no panic, no success-shaped payload).

## Not proposed (deliberately out of hvlab's scope)

- Anything specific to one guest workload (driver installation,
  kernel-debug BCD editing inside a guest, product-specific test
  recipes). PLAN.md §0.1 already assigns these to user recipes; the
  `hv_guest_powershell` + checkpoint surface is sufficient once
  item 1 lands.
