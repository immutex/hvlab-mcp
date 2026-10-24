//! The tool registry: one table describing every tool.
//!
//! This is the single source of truth for a tool's safety class, its
//! family, and the profiles that list it. Everything else — the
//! `hvlab tools` listing, the plan gate, profile filtering, and the
//! `hv_tools_search` index — is derived from [`REGISTRY`], so a tool
//! cannot be half-registered (the H-42 "two sources of truth" hazard).
//!
//! A test asserts the registry names equal the router's registered names
//! exactly, so adding a `#[tool]` without describing it here fails.

/// Safety class, which is what decides whether a plan token is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Read-only: nothing about the host, guest, or devices changes.
    Read,
    /// Mutating but reversible.
    Mutate,
    /// Destructive: needs a plan token.
    Destructive,
    /// Arbitrary code execution in a guest: needs a plan token.
    Execute,
}

impl Class {
    /// The single-letter form used on the wire and in `hvlab tools`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "R",
            Self::Mutate => "M",
            Self::Destructive => "D",
            Self::Execute => "X",
        }
    }

    /// Whether this class requires a plan token.
    #[must_use]
    pub const fn needs_plan(self) -> bool {
        matches!(self, Self::Destructive | Self::Execute)
    }
}

/// Tool family, used for grouping, profile selection, and search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// Server metadata, plans, and tool discovery.
    Meta,
    /// Host facts and services.
    Host,
    /// VM inventory, lifecycle, and configuration.
    Vm,
    /// Checkpoints.
    Checkpoint,
    /// Virtual disks (VHD/VHDX).
    Storage,
    /// Virtual switches and adapters.
    Network,
    /// DVD drives and disk attachment.
    Device,
    /// Guest execution over a channel.
    Guest,
    /// Crash dumps.
    Dump,
}

impl Family {
    /// Lowercase name used in filters and output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Meta => "meta",
            Self::Host => "host",
            Self::Vm => "vm",
            Self::Checkpoint => "checkpoint",
            Self::Storage => "storage",
            Self::Network => "network",
            Self::Device => "device",
            Self::Guest => "guest",
            Self::Dump => "dump",
        }
    }

    /// Every family, for validation of user-supplied filters.
    pub const ALL: &'static [Family] = &[
        Self::Meta,
        Self::Host,
        Self::Vm,
        Self::Checkpoint,
        Self::Storage,
        Self::Network,
        Self::Device,
        Self::Guest,
        Self::Dump,
    ];

    /// Parse a family name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|f| f.as_str() == s)
    }
}

/// One tool's metadata.
#[derive(Debug, Clone, Copy)]
pub struct ToolMeta {
    /// Registered tool name.
    pub name: &'static str,
    /// Safety class.
    pub class: Class,
    /// Family.
    pub family: Family,
    /// True when the tool is listed under the default `core` profile.
    pub core: bool,
}

/// `hvlab core` — the tools an agent needs to be useful on its first
/// call: discovery, host/VM inventory, VM lifecycle, guest execution,
/// dumps, and checkpoint basics.
///
/// The long tail (storage, networking, devices, VM configuration) is
/// intentionally absent from the listing so a harness is not billed for
/// schemas it will not use. Those tools remain **callable by name** —
/// discover them with `hv_tools_search`, then read one with
/// `hv_tools_describe`.
const fn meta(name: &'static str, class: Class, family: Family, core: bool) -> ToolMeta {
    ToolMeta {
        name,
        class,
        family,
        core,
    }
}

/// Every registered tool. Order is irrelevant; lookups are by name.
pub const REGISTRY: &[ToolMeta] = &[
    // ── Meta ──────────────────────────────────────────────────────────
    meta("hv_capabilities", Class::Read, Family::Meta, true),
    meta("hv_plan", Class::Read, Family::Meta, true),
    meta("hv_tools_describe", Class::Read, Family::Meta, true),
    meta("hv_tools_list", Class::Read, Family::Meta, true),
    meta("hv_tools_search", Class::Read, Family::Meta, true),
    // ── Host ──────────────────────────────────────────────────────────
    meta("hv_host_default_switch", Class::Read, Family::Host, false),
    meta("hv_host_info", Class::Read, Family::Host, true),
    meta("hv_host_services", Class::Read, Family::Host, false),
    meta("hv_host_storage_roots", Class::Read, Family::Host, false),
    // ── VM ────────────────────────────────────────────────────────────
    meta("hv_vm_get", Class::Read, Family::Vm, true),
    meta("hv_vm_get_config", Class::Read, Family::Vm, false),
    meta("hv_vm_list", Class::Read, Family::Vm, true),
    meta("hv_vm_rename", Class::Mutate, Family::Vm, false),
    meta("hv_vm_restart", Class::Mutate, Family::Vm, false),
    meta("hv_vm_set_memory", Class::Mutate, Family::Vm, false),
    meta("hv_vm_set_notes", Class::Mutate, Family::Vm, false),
    meta("hv_vm_set_processor", Class::Mutate, Family::Vm, false),
    meta("hv_vm_start", Class::Mutate, Family::Vm, true),
    meta("hv_vm_stop", Class::Mutate, Family::Vm, true),
    meta("hv_vm_wait_state", Class::Read, Family::Vm, true),
    // ── Checkpoint ────────────────────────────────────────────────────
    meta(
        "hv_checkpoint_create",
        Class::Mutate,
        Family::Checkpoint,
        true,
    ),
    meta(
        "hv_checkpoint_delete",
        Class::Destructive,
        Family::Checkpoint,
        false,
    ),
    meta("hv_checkpoint_list", Class::Read, Family::Checkpoint, true),
    meta(
        "hv_checkpoint_restore",
        Class::Destructive,
        Family::Checkpoint,
        false,
    ),
    // ── Storage ───────────────────────────────────────────────────────
    meta("hv_vhd_compact", Class::Mutate, Family::Storage, false),
    meta("hv_vhd_create", Class::Mutate, Family::Storage, false),
    meta("hv_vhd_get", Class::Read, Family::Storage, false),
    meta("hv_vhd_inspect", Class::Read, Family::Storage, false),
    meta("hv_vhd_resize", Class::Mutate, Family::Storage, false),
    // ── Network ───────────────────────────────────────────────────────
    meta("hv_nic_connect", Class::Mutate, Family::Network, false),
    meta("hv_nic_disconnect", Class::Mutate, Family::Network, false),
    meta("hv_switch_create", Class::Mutate, Family::Network, false),
    meta("hv_switch_list", Class::Read, Family::Network, false),
    meta("hv_switch_remove", Class::Mutate, Family::Network, false),
    // ── Device ────────────────────────────────────────────────────────
    meta("hv_device_add_disk", Class::Mutate, Family::Device, false),
    meta(
        "hv_device_remove_disk",
        Class::Mutate,
        Family::Device,
        false,
    ),
    // ── Guest ─────────────────────────────────────────────────────────
    meta("hv_guest_exec", Class::Execute, Family::Guest, true),
    meta("hv_guest_ping", Class::Read, Family::Guest, true),
    meta("hv_guest_powershell", Class::Execute, Family::Guest, false),
    // ── Dump ──────────────────────────────────────────────────────────
    meta("hv_dump_analyze", Class::Read, Family::Dump, true),
    meta("hv_dump_find", Class::Read, Family::Dump, true),
    meta("hv_dump_inspect", Class::Read, Family::Dump, true),
];

/// Look up a tool's metadata.
#[must_use]
pub fn get(name: &str) -> Option<&'static ToolMeta> {
    REGISTRY.iter().find(|m| m.name == name)
}

/// Safety class for a tool, defaulting to the most restrictive class for
/// an unregistered name so a mistake fails closed.
#[must_use]
pub fn class_of(name: &str) -> Class {
    get(name).map_or(Class::Destructive, |m| m.class)
}

/// Whether a tool requires a plan token.
#[must_use]
pub fn needs_plan(name: &str) -> bool {
    get(name).is_none_or(|m| m.class.needs_plan())
}

/// Every family present in the registry.
#[must_use]
pub fn families() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = REGISTRY.iter().map(|m| m.family.as_str()).collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// Case-insensitive substring match over name and family, for
/// `hv_tools_search`.
#[must_use]
pub fn search(query: &str) -> Vec<&'static ToolMeta> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return REGISTRY.iter().collect();
    }
    REGISTRY
        .iter()
        .filter(|m| {
            m.name.to_lowercase().contains(&q)
                || m.family.as_str().contains(&q)
                || m.class.as_str().eq_ignore_ascii_case(&q)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn registry_names_are_unique() {
        let mut seen = HashSet::new();
        for m in REGISTRY {
            assert!(seen.insert(m.name), "duplicate registry entry: {}", m.name);
        }
    }

    #[test]
    fn every_tool_is_plan_gated_iff_its_class_says_so() {
        for m in REGISTRY {
            assert_eq!(
                needs_plan(m.name),
                m.class.needs_plan(),
                "{} class/plan mismatch",
                m.name
            );
        }
    }

    #[test]
    fn guest_execution_is_class_x_and_plan_gated() {
        for name in ["hv_guest_exec", "hv_guest_powershell"] {
            assert_eq!(class_of(name), Class::Execute, "{name}");
            assert!(needs_plan(name), "{name} must need a plan");
        }
    }

    #[test]
    fn unknown_tool_fails_closed() {
        assert_eq!(class_of("hv_no_such_tool"), Class::Destructive);
        assert!(needs_plan("hv_no_such_tool"));
    }

    #[test]
    fn core_profile_is_a_strict_small_subset() {
        let core = REGISTRY.iter().filter(|m| m.core).count();
        assert!(core >= 12, "core must cover the basic workflows: {core}");
        // The point of the profile is that it is much smaller than the
        // registry; if it ever grows to match, the tiering is pointless.
        assert!(
            core * 2 <= REGISTRY.len(),
            "core ({core}) must stay well under half the registry ({})",
            REGISTRY.len()
        );
    }

    #[test]
    fn discovery_tools_are_always_in_core() {
        // Otherwise a slim listing could not reach the long tail.
        for name in ["hv_tools_search", "hv_tools_describe", "hv_tools_list"] {
            assert!(get(name).expect("registered").core, "{name} must be core");
        }
    }

    #[test]
    fn search_matches_name_and_family() {
        assert!(search("guest").iter().any(|m| m.name == "hv_guest_exec"));
        assert!(search("vhd").iter().any(|m| m.name == "hv_vhd_create"));
        assert_eq!(search("").len(), REGISTRY.len());
        assert!(search("zzzz-no-match").is_empty());
    }

    #[test]
    fn family_filter_values_are_valid() {
        for f in families() {
            assert!(Family::parse(f).is_some(), "unparseable family {f}");
        }
        assert!(Family::parse("nope").is_none());
    }
}
