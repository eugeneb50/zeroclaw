//! Authentication middleware for the gateway.
//!
//! Extracts bearer tokens, validates them via the ProviderRegistry,
//! and attaches the Principal as an Axum Extension.

use axum::{
    body::Body,
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use zeroclaw_api::principal::{AuthOutcome, DenyReason, Principal};
use zeroclaw_runtime::security::auth_provider::Credential;

use super::api::extract_bearer_token;

/// Request extension key for the authenticated Principal.
#[derive(Clone, Debug)]
pub struct AuthPrincipal(pub Principal);

impl std::ops::Deref for AuthPrincipal {
    type Target = Principal;
    fn deref(&self) -> &Principal {
        &self.0
    }
}

/// Middleware that validates bearer tokens and attaches Principal.
///
/// Applied to routes that require authentication. Public routes
/// (/health, /metrics, /pair, /admin/*) should NOT use this middleware.
pub async fn auth_middleware(
    State(state): State<crate::AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let registry = state.auth_registry.clone();

    // If no providers registered, auth is effectively disabled (allow all)
    if registry.is_empty() {
        return next.run(req).await;
    }

    let token = extract_bearer_token(req.headers()).unwrap_or("");

    let credential = Credential::Bearer(token.to_string());
    let outcome = registry.resolve(&credential).await;

    match outcome {
        AuthOutcome::Authenticated(p) | AuthOutcome::Trusted(p) => {
            req.extensions_mut().insert(AuthPrincipal(p));
            next.run(req).await
        }
        AuthOutcome::Denied { reason } => {
            let (status, msg) = match reason {
                DenyReason::NoCredential => (
                    StatusCode::UNAUTHORIZED,
                    "Unauthorized — missing Authorization: Bearer <token>",
                ),
                DenyReason::MfaRequired => (
                    StatusCode::UNAUTHORIZED,
                    "Unauthorized — MFA required",
                ),
                DenyReason::TokenExpired => (
                    StatusCode::UNAUTHORIZED,
                    "Unauthorized — token expired",
                ),
                DenyReason::AliasNotEntitled => (
                    StatusCode::FORBIDDEN,
                    "Forbidden — not entitled to this agent alias",
                ),
                DenyReason::Misconfigured => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error — auth provider misconfigured",
                ),
                DenyReason::BadCredential => (
                    StatusCode::UNAUTHORIZED,
                    "Unauthorized — invalid token",
                ),
            };
            (status, Json(serde_json::json!({ "error": msg }))).into_response()
        }
    }
}

/// Helper to extract Principal from request extensions in handlers.
#[must_use]
pub fn principal_from_request<B>(req: &Request<B>) -> Option<&Principal> {
    req.extensions().get::<AuthPrincipal>().map(|p| &p.0)
}