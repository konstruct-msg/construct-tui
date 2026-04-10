pub mod channel;
pub mod client;

/// Proto-generated types. Module hierarchy mirrors the proto package structure
/// so that `super::super::core::v1::*` cross-references resolve correctly.
pub mod shared {
    pub mod proto {
        pub mod services {
            pub mod v1 {
                tonic::include_proto!("shared.proto.services.v1");
            }
        }
        pub mod core {
            pub mod v1 {
                tonic::include_proto!("shared.proto.core.v1");
            }
        }
        pub mod messaging {
            pub mod v1 {
                tonic::include_proto!("shared.proto.messaging.v1");
            }
        }
        pub mod signaling {
            pub mod v1 {
                tonic::include_proto!("shared.proto.signaling.v1");
            }
        }
    }
}

// Convenience re-exports
pub use shared::proto::services::v1 as services;
pub use shared::proto::core::v1 as core_types;pub use client::ConstructClient;
