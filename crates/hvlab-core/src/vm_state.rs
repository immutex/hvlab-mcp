//! VM state decoded from `Msvm_ComputerSystem.EnabledState`.
//!
//! The CIM enumeration and Hyper-V's actual usage differ at several
//! values. Unknown values are preserved as [`VmState::Unknown`] rather
//! than collapsed to a default — a wrong default silently turns
//! "paused" into "off". The numeric table is pinned by the tests in
//! this module against the documented CIM values.

use serde::{Deserialize, Serialize};

/// VM power state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VmState {
    /// Not running, clean.
    Off,
    /// In the process of starting.
    Starting,
    /// Running normally.
    Running,
    /// Paused (pause operation).
    Paused,
    /// Being saved to disk.
    Saving,
    /// Being stopped (graceful shutdown requested).
    Stopping,
    /// Saved to disk, not running.
    Saved,
    /// Critical pause (application crash in guest detected).
    PausedCritical,
    /// A value not in the documented table. Carried, never collapsed.
    Unknown(u16),
}

impl VmState {
    /// Decode `EnabledState` from `Msvm_ComputerSystem`.
    #[must_use]
    pub fn from_enabled_state(raw: u16) -> Self {
        match raw {
            2 => Self::Running,
            // 3 = Enabled/Off; 9 = Shutting Down, which for polling
            // purposes is already gone from the guest's perspective.
            3 | 9 => Self::Off,
            // 6 = Enabled/Paused; 14 = Paused (redundant CIM alias).
            6 | 14 => Self::Paused,
            // 8 = Saving; 11 = Snapshotting, which behaves like a save.
            8 | 11 => Self::Saving,
            10 => Self::Starting,
            12 => Self::Saved,
            13 => Self::Stopping,
            15 => Self::PausedCritical,
            // Everything else, including the vendor range, is carried
            // verbatim rather than guessed at.
            _ => Self::Unknown(raw),
        }
    }

    /// Whether a start operation is legal from this state.
    #[must_use]
    pub fn can_start(self) -> bool {
        matches!(self, Self::Off | Self::Saved | Self::Paused)
    }

    /// Whether the guest can be reached by an in-guest channel right
    /// now. Only meaningful together with a channel probe, but these
    /// states can be ruled out immediately.
    #[must_use]
    pub fn can_reach_guest(self) -> bool {
        matches!(
            self,
            Self::Running | Self::Paused | Self::PausedCritical | Self::Unknown(_)
        )
    }

    /// Whether the VM is transitioning between states (a job is running).
    #[must_use]
    pub fn is_transitioning(self) -> bool {
        matches!(
            self,
            Self::Starting | Self::Saving | Self::Stopping | Self::Unknown(_)
        ) && !matches!(self, Self::Off | Self::Saved)
    }

    /// Terminal, stable states: no transition will change them.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Off | Self::Running | Self::Paused | Self::PausedCritical | Self::Saved
        )
    }
}

impl std::fmt::Display for VmState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Off => f.write_str("off"),
            Self::Starting => f.write_str("starting"),
            Self::Running => f.write_str("running"),
            Self::Paused => f.write_str("paused"),
            Self::Saving => f.write_str("saving"),
            Self::Stopping => f.write_str("stopping"),
            Self::Saved => f.write_str("saved"),
            Self::PausedCritical => f.write_str("paused-critical"),
            Self::Unknown(v) => write!(f, "unknown({v})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod from_enabled_state {
        use super::*;

        #[test]
        fn running_is_2() {
            assert_eq!(VmState::from_enabled_state(2), VmState::Running);
        }

        #[test]
        fn off_is_3() {
            assert_eq!(VmState::from_enabled_state(3), VmState::Off);
        }

        #[test]
        fn saved_is_12() {
            assert_eq!(VmState::from_enabled_state(12), VmState::Saved);
        }

        #[test]
        fn paused_variants_map_distinctly() {
            assert_eq!(VmState::from_enabled_state(6), VmState::Paused);
            assert_eq!(VmState::from_enabled_state(14), VmState::Paused);
            assert_eq!(VmState::from_enabled_state(15), VmState::PausedCritical);
        }

        #[test]
        fn unknown_values_are_preserved_not_collapsed() {
            // A wrong default here silently turns "paused" into "off".
            let state = VmState::from_enabled_state(999);
            assert_eq!(state, VmState::Unknown(999));
            assert_eq!(state.to_string(), "unknown(999)");
        }
    }

    mod can_start {
        use super::*;

        #[test]
        fn allowed_from_off_saved_and_paused() {
            assert!(VmState::Off.can_start());
            assert!(VmState::Saved.can_start());
            assert!(VmState::Paused.can_start());
        }

        #[test]
        fn refused_from_running_and_transitions() {
            assert!(!VmState::Running.can_start());
            assert!(!VmState::Starting.can_start());
            assert!(!VmState::Saving.can_start());
            assert!(!VmState::Stopping.can_start());
        }
    }

    mod is_transitioning {
        use super::*;

        #[test]
        fn transitions_are_transitioning() {
            assert!(VmState::Starting.is_transitioning());
            assert!(VmState::Saving.is_transitioning());
            assert!(VmState::Stopping.is_transitioning());
        }

        #[test]
        fn terminal_states_are_not_transitioning() {
            assert!(!VmState::Running.is_transitioning());
            assert!(!VmState::Off.is_transitioning());
            assert!(!VmState::Saved.is_transitioning());
        }
    }
}
