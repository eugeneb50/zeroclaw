//! Conflict resolution for bidirectional SCIM sync.

use std::sync::Arc;
use async_trait::async_trait;
use crate::scim::schema::ScimUser;

/// Conflict between inbound (IdP → ZeroClaw) and outbound (ZeroClaw → downstream) changes.
#[derive(Debug, Clone)]
pub struct SyncConflict {
    pub principal_id: String,
    pub inbound_change: Option<ScimUser>,
    pub outbound_change: Option<ScimUser>,
    pub inbound_timestamp: chrono::DateTime<chrono::Utc>,
    pub outbound_timestamp: chrono::DateTime<chrono::Utc>,
}

/// Resolution of a sync conflict.
#[derive(Debug, Clone)]
pub enum ConflictResolution {
    UseInbound(ScimUser),
    UseOutbound(ScimUser),
    Merge(ScimUser),
    DeferForReview,
}

/// Trait for conflict resolution strategies.
#[async_trait]
pub trait ConflictResolver: Send + Sync {
    async fn resolve(&self, conflict: SyncConflict) -> ConflictResolution;
}

/// Default last-write-wins resolver based on timestamps.
#[derive(Debug, Default)]
pub struct LastWriteWinsResolver;

#[async_trait]
impl ConflictResolver for LastWriteWinsResolver {
    async fn resolve(&self, conflict: SyncConflict) -> ConflictResolution {
        if conflict.inbound_timestamp > conflict.outbound_timestamp {
            ConflictResolution::UseInbound(conflict.inbound_change.unwrap())
        } else {
            ConflictResolution::UseOutbound(conflict.outbound_change.unwrap())
        }
    }
}