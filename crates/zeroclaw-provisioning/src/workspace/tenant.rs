//! Tenant context types for multi-tenant support.

use zeroclaw_api::principal::WorkspaceId;

/// Tenant context extracted from request and available to downstream handlers.
#[derive(Clone, Debug)]
pub struct TenantContext {
    /// Raw tenant ID from header/hostname
    pub tenant_id: String,
    /// Resolved workspace ID
    pub workspace_id: WorkspaceId,
    /// Whether this was resolved from a real tenant or is the default
    pub is_default: bool,
}

impl TenantContext {
    /// Create context for default/single-tenant mode.
    pub fn default() -> Self {
        Self {
            tenant_id: "default".to_string(),
            workspace_id: WorkspaceId::DEFAULT.into(),
            is_default: true,
        }
    }

    /// Create context for a specific tenant.
    pub fn new(tenant_id: String, workspace_id: WorkspaceId) -> Self {
        Self {
            tenant_id,
            workspace_id,
            is_default: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroclaw_api::principal::WorkspaceId;

    #[test]
    fn test_default_context() {
        let ctx = TenantContext::default();
        assert_eq!(ctx.tenant_id, "default");
        assert_eq!(ctx.workspace_id.as_str(), "default");
        assert!(ctx.is_default);
    }

    #[test]
    fn test_custom_context() {
        let ctx = TenantContext::new("acme-corp".into(), WorkspaceId("eng".into()));
        assert_eq!(ctx.tenant_id, "acme-corp");
        assert_eq!(ctx.workspace_id.as_str(), "eng");
        assert!(!ctx.is_default);
    }
}