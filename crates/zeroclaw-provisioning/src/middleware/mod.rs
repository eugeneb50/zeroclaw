//! Multi-tenant middleware for tenant/workspace context extraction.

pub mod tenant;

pub use crate::workspace::tenant::TenantContext;
pub use tenant::{TenantResolutionMiddleware, get_tenant_context, extract_tenant_id};
