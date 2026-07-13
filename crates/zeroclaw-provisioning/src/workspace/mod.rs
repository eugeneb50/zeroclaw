//! Workspace membership index and resolution.
//!
//! Provides a thread-safe in-memory index mapping WorkspaceId <-> PrincipalId,
//! plus tenant context support for multi-tenant deployments.

pub mod index;
pub mod resolver;
pub mod tenant;

pub use index::{WorkspaceIndex, WorkspaceChanges, WorkspaceIndexStats, PrincipalId, WorkspaceId};
pub use resolver::{WorkspaceResolver, AttributePathParser};
pub use tenant::TenantContext;