//! Bidirectional sync bridge - coordinates inbound (IdP → ZeroClaw) and outbound (ZeroClaw → downstreams) provisioning.

pub mod outbound;
pub mod conflict;
pub mod bidirectional;

pub use outbound::{OutboundBridge, OutboundPusher};
pub use conflict::{ConflictResolver, LastWriteWinsResolver, SyncConflict, ConflictResolution};
pub use bidirectional::BidirectionalBridge;