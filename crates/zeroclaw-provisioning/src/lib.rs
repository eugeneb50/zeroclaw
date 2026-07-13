//! zeroclaw-provisioning — SCIM provisioning, workspace resolution, and multi-tenant identity management.
//!
//! This crate provides:
//! - SCIM 2.0 (RFC 7643/7644) client for inbound provisioning from IdPs
//! - Workspace membership index shared across auth, memory, and gateway
//! - Multi-tenant middleware for request-scoped tenant/workspace context
//! - Outbound SCIM provider endpoints for downstream applications
//! - Bidirectional sync bridge with configurable conflict resolution

pub mod config;
pub mod error;
pub mod scim;
pub mod workspace;
pub mod sync;
pub mod gateway;
pub mod bridge;
pub mod middleware;

pub use config::{ProvisioningConfig, DownstreamConfig, MultiTenantConfig, ConflictConfig, ConflictStrategy};
pub use error::{ProvisioningError, Result};
pub use workspace::{WorkspaceIndex, WorkspaceResolver, TenantContext, WorkspaceChanges};
pub use scim::{ScimClient, ScimUser, ScimGroup, ScimListResponse, ScimMeta, ScimFilter, parse_filter};
pub use sync::{SyncEngine, SyncCursor, SyncEvent, SyncStats, SyncCursorStore};
pub use gateway::{scim_routes, validate_downstream};
pub use bridge::{OutboundBridge, OutboundPusher, ConflictResolver, LastWriteWinsResolver, BidirectionalBridge, SyncConflict, ConflictResolution};
pub use middleware::{TenantResolutionMiddleware, get_tenant_context, extract_tenant_id};