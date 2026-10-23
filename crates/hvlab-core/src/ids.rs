//! Strongly-typed identifiers. Constructing one from the wrong field is
//! a type error, not a runtime bug.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

macro_rules! id_type {
    ($(#[$doc:meta])* $name:ident, $prefix:literal) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub uuid::Uuid);

        impl $name {
            /// Generate a new random identifier.
            #[must_use]
            pub fn generate() -> Self {
                Self(uuid::Uuid::now_v7())
            }

            /// Build from an uppercase braced-or-plain GUID string, as
            /// WMI returns them (e.g. `64A20E96-BA68-...`).
            ///
            /// # Errors
            ///
            /// uuid parse failure.
            pub fn from_str_guid(s: &str) -> std::result::Result<Self, uuid::Error> {
                Ok(Self(uuid::Uuid::parse_str(s)?))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}-{}", $prefix, self.0.simple())
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                // Accept both the prefixed display form and a bare
                // UUID; the prefix is presentation, not identity.
                let raw = s.strip_prefix(concat!($prefix, "-")).unwrap_or(s);
                Ok(Self(uuid::Uuid::parse_str(raw)?))
            }
        }
    };
}

id_type!(
    /// Identifies a VM by its `Msvm_ComputerSystem.Name` GUID — never the
    /// display name, so a rename cannot retarget a cached plan.
    VmId,
    "vm"
);
id_type!(
    /// Identifies a tracked job.
    JobId,
    "job"
);
id_type!(
    /// Identifies a plan (a pending destructive operation).
    PlanId,
    "plan"
);

#[cfg(test)]
mod tests {
    use super::*;

    mod vm_id {
        use super::*;

        #[test]
        fn display_includes_prefix() {
            let id = VmId::generate();
            let s = id.to_string();
            assert!(s.starts_with("vm-"), "{s}");
            assert_eq!(s.len(), 3 + 32);
        }

        #[test]
        fn roundtrips_through_display_and_parse() {
            let id = VmId::generate();
            let parsed: VmId = id.to_string().parse().expect("parses own display");
            assert_eq!(id, parsed);
        }

        #[test]
        fn parses_bare_uuid_too() {
            let id = VmId::generate();
            let bare = id.0.to_string();
            let parsed: VmId = bare.parse().expect("bare uuid parses");
            assert_eq!(id, parsed);
        }

        #[test]
        fn rejects_garbage() {
            assert!(VmId::from_str("vm-not-a-uuid").is_err());
        }
    }

    mod distinct_types {
        use super::*;

        #[test]
        fn vm_and_job_ids_are_not_interchangeable() {
            // A JobId is not a VmId even with the same inner value — the
            // type error is the point.
            let vm = VmId::generate();
            let job = JobId(vm.0);
            assert_ne!(
                std::any::TypeId::of::<VmId>(),
                std::any::TypeId::of::<JobId>()
            );
            assert_eq!(vm.0, job.0, "same inner uuid is fine");
        }
    }
}
