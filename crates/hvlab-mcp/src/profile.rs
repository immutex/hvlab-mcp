//! Tool profiles and the lean `tools/list` projection.
//!
//! # Why this exists
//!
//! A harness bills the model for every tool definition it is handed at
//! startup. Measured on this server, a full 40-tool listing is ~9.5k
//! tokens, of which **52% is `outputSchema`** — schemas the client rarely
//! validates against and that carry no information the model needs in
//! order to *choose* a tool. At the catalogue's full size that would be
//! ~48k tokens resident before any work starts.
//!
//! So the listing is treated as a *discovery* surface, not the API:
//!
//! * A **profile** decides which tools are advertised (default `core`).
//! * Advertised tools are sent **lean**: no `outputSchema`, no `$schema`
//!   key, one-line descriptions. The full result payload is unchanged —
//!   callers still get `structuredContent`.
//! * Tools outside the profile remain **dispatchable by name**. This is
//!   the property that keeps the surface lossless, and it holds because
//!   rmcp resolves a call through `ToolRouter::call` (a name lookup) and
//!   validates arguments from the handler type — neither path consults
//!   the advertised listing. `unlisted_tools_still_dispatch` pins it.
//! * `hv_tools_search` / `hv_tools_describe` let a caller find and read
//!   any tool's full schema on demand, so nothing is unreachable.

use std::collections::BTreeSet;

use rmcp::model::{JsonObject, Tool};

use crate::registry::{self, Family};

/// Which set of tools a server instance advertises.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Profile {
    /// The default: the small set needed to be useful on a first call.
    #[default]
    Core,
    /// Every registered tool.
    Full,
    /// Every class-`R` tool (monitoring, dashboards, read-only agents).
    ReadOnly,
    /// An explicit set of tool names.
    Custom(BTreeSet<String>),
}

impl Profile {
    /// Environment variable selecting the profile.
    pub const ENV: &'static str = "HVLAB_TOOLS";

    /// Parse a profile name, or a comma-separated list of tool names /
    /// families.
    ///
    /// Accepts `core`, `full`, `readonly`, or a list such as
    /// `guest,dump` / `hv_vm_list,hv_guest_exec`.
    #[must_use]
    pub fn parse(spec: &str) -> Self {
        match spec.trim().to_lowercase().as_str() {
            "" | "core" => Self::Core,
            "full" | "all" => Self::Full,
            "readonly" | "ro" => Self::ReadOnly,
            _ => {
                let mut set = BTreeSet::new();
                for part in spec.split(',') {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    if let Some(family) = Family::parse(&part.to_lowercase()) {
                        set.extend(
                            registry::REGISTRY
                                .iter()
                                .filter(|m| m.family == family)
                                .map(|m| m.name.to_owned()),
                        );
                    } else {
                        set.insert(part.to_owned());
                    }
                }
                // Discovery must always be present, or a slim profile
                // could not reach the rest of the surface.
                for name in DISCOVERY_TOOLS {
                    set.insert((*name).to_owned());
                }
                Self::Custom(set)
            }
        }
    }

    /// The active profile from the environment, defaulting to `core`.
    #[must_use]
    pub fn from_env() -> Self {
        std::env::var(Self::ENV).map_or(Self::Core, |v| Self::parse(&v))
    }

    /// Name for reporting.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Full => "full",
            Self::ReadOnly => "readonly",
            Self::Custom(_) => "custom",
        }
    }

    /// Whether a tool is advertised under this profile.
    #[must_use]
    pub fn advertises(&self, name: &str) -> bool {
        match self {
            Self::Core => registry::get(name).is_some_and(|m| m.core),
            Self::Full => registry::get(name).is_some(),
            Self::ReadOnly => registry::class_of(name) == registry::Class::Read,
            Self::Custom(set) => set.contains(name),
        }
    }
}

/// Tools that must be reachable in every profile, because they are how
/// a caller discovers everything else.
pub const DISCOVERY_TOOLS: &[&str] = &[
    "hv_capabilities",
    "hv_tools_list",
    "hv_tools_describe",
    "hv_tools_search",
];

/// Project a registered tool into the lean wire shape.
///
/// Drops `outputSchema` (half the payload, and the client re-reads the
/// real values from `structuredContent` anyway), drops the `$schema`
/// URI, and collapses the description to its first sentence — which is
/// where the "what is this for" clause lives.
#[must_use]
pub fn lean(tool: &Tool) -> Tool {
    let mut out = tool.clone();
    out.output_schema = None;
    let mut schema: JsonObject = (*tool.input_schema).clone();
    schema.remove("$schema");
    out.input_schema = std::sync::Arc::new(schema);
    if let Some(desc) = tool.description.as_deref() {
        out.description = Some(first_sentence(desc).into());
    }
    out
}

/// The first sentence of a description, which is the part that says what
/// the tool is for. Descriptions are written as `what it does` followed
/// by `extra caveats`, so this keeps the useful clause and drops the rest.
#[must_use]
pub fn first_sentence_public(s: &str) -> String {
    first_sentence(s)
}

fn first_sentence(s: &str) -> String {
    let trimmed = s.trim();
    // Cut at the first '. ' so "e.g. foo" and version numbers survive.
    match trimmed.find(". ") {
        Some(i) => trimmed[..=i].trim_end().to_owned(),
        None => trimmed.to_owned(),
    }
}

/// Approximate token cost of a tool listing (JSON bytes / 4), used by the
/// budget test that keeps this server from bloating a harness again.
#[must_use]
pub fn approx_tokens(tools: &[Tool]) -> usize {
    tools
        .iter()
        .map(|t| {
            serde_json::to_string(t)
                .map(|s| s.len())
                .unwrap_or_default()
        })
        .sum::<usize>()
        / 4
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn parses_names_and_families() {
        assert_eq!(Profile::parse("core"), Profile::Core);
        assert_eq!(Profile::parse(""), Profile::Core);
        assert_eq!(Profile::parse("FULL"), Profile::Full);
        assert_eq!(Profile::parse("readonly"), Profile::ReadOnly);
        match Profile::parse("guest") {
            Profile::Custom(s) => {
                assert!(s.contains("hv_guest_exec"));
                // Discovery is force-included so the rest stays reachable.
                assert!(s.contains("hv_tools_search"));
            }
            other => panic!("expected custom, got {other:?}"),
        }
    }

    #[test]
    fn core_advertises_far_fewer_than_full() {
        let core = registry::REGISTRY
            .iter()
            .filter(|m| Profile::Core.advertises(m.name))
            .count();
        let full = registry::REGISTRY.len();
        assert!(core < full, "core must not advertise everything");
    }

    #[test]
    fn first_sentence_keeps_the_purpose_clause() {
        assert_eq!(
            first_sentence("List a VM's checkpoints, newest first. Extra detail here."),
            "List a VM's checkpoints, newest first."
        );
        assert_eq!(first_sentence("One line only"), "One line only");
        // A version number must not be mistaken for a sentence break.
        assert_eq!(
            first_sentence("Runs on v1.2 of the thing"),
            "Runs on v1.2 of the thing"
        );
    }
}
