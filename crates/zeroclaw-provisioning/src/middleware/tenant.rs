//! Multi-tenant context and middleware.

use std::sync::Arc;
use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpRequest,
};
use futures_util::future::{ok, Ready, LocalBoxFuture};
use tracing::{debug, warn};

use crate::config::MultiTenantConfig;
use crate::workspace::WorkspaceResolver;
use crate::workspace::tenant::TenantContext;
use zeroclaw_api::principal::WorkspaceId;

/// Extract tenant ID from request headers or hostname fallback.
pub fn extract_tenant_id(req: &ServiceRequest, config: &MultiTenantConfig) -> Option<String> {
    // 1. Check explicit tenant header
    if let Some(header_val) = req.headers().get(&config.tenant_header) {
        if let Ok(s) = header_val.to_str() {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }

    // 2. Check fallback header (e.g., X-Forwarded-Host for hostname-based routing)
    if let Some(header_val) = req.headers().get(&config.tenant_header_fallback) {
        if let Ok(s) = header_val.to_str() {
            if !s.is_empty() {
                return Some(extract_tenant_from_host(s));
            }
        }
    }

    // 3. Fallback to Host header
    if let Some(host) = req.headers().get("host") {
        if let Ok(s) = host.to_str() {
            return Some(extract_tenant_from_host(s));
        }
    }

    None
}

fn extract_tenant_from_host(host: &str) -> String {
    // Extract subdomain: tenant.example.com -> tenant
    host.split('.').next().unwrap_or("default").to_string()
}

/// Middleware to extract tenant context from incoming requests.
/// Runs BEFORE authentication to provide tenant/workspace context to auth providers.
pub struct TenantResolutionMiddleware {
    config: MultiTenantConfig,
    workspace_resolver: Arc<WorkspaceResolver>,
}

impl TenantResolutionMiddleware {
    pub fn new(config: MultiTenantConfig, workspace_resolver: Arc<WorkspaceResolver>) -> Self {
        Self { config, workspace_resolver }
    }
}

impl<S, B> Transform<S, ServiceRequest> for TenantResolutionMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = TenantResolutionMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(TenantResolutionMiddlewareService {
            service,
            config: self.config.clone(),
            workspace_resolver: self.workspace_resolver.clone(),
        })
    }
}

pub struct TenantResolutionMiddlewareService<S> {
    service: S,
    config: MultiTenantConfig,
    workspace_resolver: Arc<WorkspaceResolver>,
}

impl<S, B> Service<ServiceRequest> for TenantResolutionMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Extract tenant ID
        let tenant_id = extract_tenant_id(&req, &self.config)
            .unwrap_or_else(|| self.config.default_tenant.clone());

        let is_default = tenant_id == self.config.default_tenant;

        // Resolve workspace for this tenant
        let workspace_id = if self.config.enabled && !is_default {
            self.workspace_resolver.resolve_for_tenant(&tenant_id)
        } else {
            WorkspaceId::DEFAULT.into()
        };

        // Insert tenant context into request extensions
        let ctx = TenantContext {
            tenant_id: tenant_id.clone(),
            workspace_id: workspace_id.clone(),
            is_default,
        };
        req.extensions_mut().insert(ctx);

        debug!("Tenant context: tenant_id={}, workspace_id={}, is_default={}", 
               tenant_id, workspace_id.as_str(), is_default);

        // Continue to next service
        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}

/// Helper to extract TenantContext from request extensions.
pub fn get_tenant_context(req: &ServiceRequest) -> Option<TenantContext> {
    req.extensions().get::<TenantContext>().cloned()
}

/// Helper to extract TenantContext from actix-web HttpRequest.
pub fn get_tenant_context_from_req(req: &HttpRequest) -> Option<TenantContext> {
    req.extensions().get::<TenantContext>().cloned()
}

/// Resolve WorkspaceId for a principal in the current tenant context.
pub async fn resolve_workspace_for_principal(
    req: &ServiceRequest,
    _principal_id: &zeroclaw_api::principal::PrincipalId,
) -> WorkspaceId {
    if let Some(ctx) = get_tenant_context(req) {
        if !ctx.is_default {
            return ctx.workspace_id.clone();
        }
    }
    // Fallback to workspace resolver
    WorkspaceId::DEFAULT.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App, HttpResponse, web};
    use crate::workspace::index::WorkspaceIndex;
    use crate::workspace::resolver::WorkspaceResolver;
    use crate::config::ProvisioningConfig;

    #[actix_web::test]
    async fn test_tenant_middleware_extracts_header() {
        let config = MultiTenantConfig {
            enabled: true,
            tenant_header: "X-Tenant-ID".to_string(),
            tenant_header_fallback: "X-Forwarded-Host".to_string(),
            default_tenant: "default".to_string(),
        };
        let index = Arc::new(WorkspaceIndex::new());
        let resolver = Arc::new(WorkspaceResolver::new(index, ProvisioningConfig::default()));
        let _middleware = TenantResolutionMiddleware::new(config, resolver);

        let req = test::TestRequest::default()
            .insert_header(("X-Tenant-ID", "acme-corp"))
            .to_srv_request();

        let tenant_id = extract_tenant_id(&req, &MultiTenantConfig {
            enabled: true,
            tenant_header: "X-Tenant-ID".to_string(),
            tenant_header_fallback: "X-Forwarded-Host".to_string(),
            default_tenant: "default".to_string(),
        });
        assert_eq!(tenant_id, Some("acme-corp".to_string()));
    }

    #[actix_web::test]
    async fn test_tenant_middleware_fallback_to_host() {
        let config = MultiTenantConfig {
            enabled: true,
            tenant_header: "X-Tenant-ID".to_string(),
            tenant_header_fallback: "X-Forwarded-Host".to_string(),
            default_tenant: "default".to_string(),
        };
        let index = Arc::new(WorkspaceIndex::new());
        let resolver = Arc::new(WorkspaceResolver::new(index, ProvisioningConfig::default()));
        let _middleware = TenantResolutionMiddleware::new(config.clone(), resolver);

        let req = test::TestRequest::default()
            .insert_header(("host", "acme.example.com"))
            .to_srv_request();

        let tenant_id = extract_tenant_id(&req, &config);
        assert_eq!(tenant_id, Some("acme".to_string()));
    }

    #[actix_web::test]
    async fn test_default_tenant_when_no_header() {
        let config = MultiTenantConfig {
            enabled: true,
            tenant_header: "X-Tenant-ID".to_string(),
            tenant_header_fallback: "X-Forwarded-Host".to_string(),
            default_tenant: "default".to_string(),
        };
        let index = Arc::new(WorkspaceIndex::new());
        let resolver = Arc::new(WorkspaceResolver::new(index, ProvisioningConfig::default()));
        let _middleware = TenantResolutionMiddleware::new(config.clone(), resolver);

        let req = test::TestRequest::default().to_srv_request();
        let tenant_id = extract_tenant_id(&req, &config);
        assert_eq!(tenant_id, None); // Returns None, middleware uses default
    }
}