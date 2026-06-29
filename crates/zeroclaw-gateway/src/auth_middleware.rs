//! Tower middleware for route-level authentication. Extracts
//! `Authorization: Bearer <token>` headers, verifies them through a registered
//! [`AuthRegistry`], and injects the resolved [`Principal`] as a request
//! extension. Three policy variants cover the gateway's route-group needs:
//!
//! - [`AuthPolicy::Required`] — 401 if no valid credential.
//! - [`AuthPolicy::Optional`] — proceed without auth; verify if present.
//! - [`AuthPolicy::AgentScoped`] — like `Required`; handler calls
//!   `Principal::ensure_entitled_to(alias)` for the 403 decision.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    extract::{FromRequestParts, Request},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use tower::Layer;
use zeroclaw_api::principal::{AuthOutcome, DenyReason, Principal};

pub use zeroclaw_runtime::security::AuthRegistry;

// ── AuthPolicy ──────────────────────────────────────────────────────────

/// Per-route-group authentication policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthPolicy {
    /// All requests must present a valid credential. Invalid/missing → 401
    /// with structured JSON body.
    Required,
    /// Requests MAY proceed without a credential. If one is present it is
    /// verified; invalid → 401; valid → `Principal` injected as extension.
    Optional,
    /// Like `Required` — the middleware guarantees a valid `Principal` is
    /// injected (or 401). Handlers on `AgentScoped` routes are expected to
    /// call `Principal::ensure_entitled_to(alias)` for the agent-level
    /// authorization check that returns 403 when the principal lacks
    /// entitlement.
    AgentScoped,
}

// ── AuthLayer ───────────────────────────────────────────────────────────

/// Tower [`Layer`] producing [`AuthMiddleware`] services.
#[derive(Clone)]
pub struct AuthLayer {
    registry: Arc<dyn AuthRegistry>,
    policy: AuthPolicy,
}

impl AuthLayer {
    /// Routes that always require authentication.
    #[must_use]
    pub fn required(registry: Arc<dyn AuthRegistry>) -> Self {
        Self {
            registry,
            policy: AuthPolicy::Required,
        }
    }

    /// Routes where authentication is optional (e.g., public discovery).
    #[must_use]
    pub fn optional(registry: Arc<dyn AuthRegistry>) -> Self {
        Self {
            registry,
            policy: AuthPolicy::Optional,
        }
    }

    /// Routes that require authentication AND the caller is expected to
    /// hold a specific agent-alias entitlement (checked in the handler).
    #[must_use]
    pub fn agent_scoped(registry: Arc<dyn AuthRegistry>) -> Self {
        Self {
            registry,
            policy: AuthPolicy::AgentScoped,
        }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthMiddleware {
            inner,
            registry: self.registry.clone(),
            policy: self.policy,
        }
    }
}

// ── AuthMiddleware ──────────────────────────────────────────────────────

/// The middleware service produced by [`AuthLayer`].
#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
    registry: Arc<dyn AuthRegistry>,
    policy: AuthPolicy,
}

impl<S, ReqBody> tower::Service<Request<ReqBody>> for AuthMiddleware<S>
where
    S: tower::Service<Request<ReqBody>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    ReqBody: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let mut this = self.clone();
        let (mut parts, body) = req.into_parts();

        Box::pin(async move {
            let credential = credential_from_headers(&parts.headers);

            match this.policy {
                AuthPolicy::Optional => {
                    if matches!(credential, zeroclaw_runtime::security::auth_provider::Credential::None)
                        || !this.registry.accepts(&credential)
                    {
                        let req = Request::from_parts(parts, body);
                        return this.inner.call(req).await;
                    }
                    match this.registry.verify(&credential).await {
                        AuthOutcome::Authenticated(p) | AuthOutcome::Trusted(p) => {
                            parts.extensions.insert(p);
                            let req = Request::from_parts(parts, body);
                            this.inner.call(req).await
                        }
                        AuthOutcome::Denied { .. } => Ok(auth_error_response(
                            StatusCode::UNAUTHORIZED,
                            "unauthorized",
                            "Invalid or expired authentication",
                        )),
                    }
                }
                AuthPolicy::Required => {
                    match this.registry.verify(&credential).await {
                        AuthOutcome::Authenticated(p) | AuthOutcome::Trusted(p) => {
                            parts.extensions.insert(p);
                            let req = Request::from_parts(parts, body);
                            this.inner.call(req).await
                        }
                        AuthOutcome::Denied { reason } => {
                            let (status, error, detail) = deny_to_response_parts(reason);
                            Ok(auth_error_response(status, error, detail))
                        }
                    }
                }
                AuthPolicy::AgentScoped => {
                    match this.registry.verify(&credential).await {
                        AuthOutcome::Authenticated(p) => {
                            parts.extensions.insert(p);
                            let req = Request::from_parts(parts, body);
                            this.inner.call(req).await
                        }
                        AuthOutcome::Trusted(_) => Ok(auth_error_response(
                            StatusCode::UNAUTHORIZED,
                            "unauthorized",
                            "Agent-scoped routes require peer authentication",
                        )),
                        AuthOutcome::Denied { reason } => {
                            let (status, error, detail) = deny_to_response_parts(reason);
                            Ok(auth_error_response(status, error, detail))
                        }
                    }
                }
            }
        })
    }
}

// ── Principal extractors for handlers ──────────────────────────────────

/// Extractor for handlers that require an authenticated principal.
///
/// Returns 401 with a structured JSON body if the middleware did not inject
/// a `Principal` into request extensions (e.g., the route is not protected
/// by `AuthMiddleware` or `Optional` policy skipped auth).
///
/// # Panics
///
/// In test code that constructs requests without going through the middleware
/// chain, this extractor returns a rejection response instead of panicking.
#[derive(Debug)]
pub struct AuthPrincipal(pub Principal);

impl<S> FromRequestParts<S> for AuthPrincipal
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Principal>()
            .cloned()
            .map(AuthPrincipal)
            .ok_or_else(|| {
                auth_error_response(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "Authentication required",
                )
            })
    }
}

/// Extractor for handlers that optionally use principal info.
///
/// Returns `None` when no `Principal` was injected (anonymous access on
/// `Optional` routes), or `Some(Principal)` when the middleware verified the
/// credential.
#[derive(Debug)]
pub struct OptPrincipal(pub Option<Principal>);

impl<S> FromRequestParts<S> for OptPrincipal
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(OptPrincipal(parts.extensions.get::<Principal>().cloned()))
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Build a JSON error response for auth failures.
fn auth_error_response(status: StatusCode, error: &'static str, detail: &'static str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": error,
            "detail": detail,
            "status": status.as_u16(),
        })),
    )
        .into_response()
}

/// Map a [`DenyReason`] to the response tuple (status, error-code, detail).
#[must_use]
fn deny_to_response_parts(reason: DenyReason) -> (StatusCode, &'static str, &'static str) {
    match reason {
        DenyReason::NoCredential => {
            (StatusCode::UNAUTHORIZED, "unauthorized", "Missing authentication")
        }
        DenyReason::BadCredential => {
            (StatusCode::UNAUTHORIZED, "unauthorized", "Invalid authentication credentials")
        }
        DenyReason::TokenExpired => {
            (StatusCode::UNAUTHORIZED, "unauthorized", "Authentication token has expired")
        }
        DenyReason::MfaRequired => (
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Multi-factor authentication required",
        ),
        DenyReason::AliasNotEntitled => {
            (StatusCode::FORBIDDEN, "forbidden", "Not entitled for the requested agent alias")
        }
        DenyReason::Misconfigured => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "misconfigured",
            "Authentication provider is misconfigured",
        ),
    }
}

/// Extract a [`Credential`] from the request headers.
fn credential_from_headers(
    headers: &HeaderMap,
) -> zeroclaw_runtime::security::auth_provider::Credential {
    crate::api::extract_bearer_token(headers)
        .map(|token| zeroclaw_runtime::security::auth_provider::Credential::Bearer(token.to_owned()))
        .unwrap_or(zeroclaw_runtime::security::auth_provider::Credential::None)
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, http::Request, routing::get};
    use std::sync::Arc;
    use tower::ServiceExt;
    use zeroclaw_api::principal::AuthMethod;
    use zeroclaw_runtime::security::{
        LiveAuthRegistry, ProviderRegistry,
        auth_provider::{AuthProvider, Credential},
    };
    use async_trait::async_trait;

    /// A stub provider that accepts one fixed bearer token.
    struct StubProvider;

    #[async_trait]
    impl AuthProvider for StubProvider {
        fn name(&self) -> &str { "stub" }
        fn method(&self) -> AuthMethod { AuthMethod::A2aPeer }
        fn accepts(&self, credential: &Credential) -> bool {
            matches!(credential, Credential::Bearer(_))
        }
        async fn verify(&self, credential: &Credential) -> AuthOutcome {
            match credential {
                Credential::Bearer(t) if t == "valid-token" => {
                    AuthOutcome::Authenticated(
                        Principal::new("peer-1", "Peer One", AuthMethod::A2aPeer)
                            .with_allowed_aliases(vec![
                                zeroclaw_api::principal::AgentAlias::new("agent1"),
                            ]),
                    )
                }
                Credential::Bearer(t) if t == "trusted-token" => {
                    AuthOutcome::Trusted(Principal::shared_operator())
                }
                _ => AuthOutcome::Denied { reason: DenyReason::BadCredential },
            }
        }
    }

    fn registry_with_stub() -> Arc<dyn AuthRegistry> {
        let mut reg = ProviderRegistry::new();
        reg.register(Arc::new(StubProvider));
        Arc::new(LiveAuthRegistry::new(reg))
    }

    fn make_request(token: Option<&str>) -> Request<Body> {
        let mut req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        if let Some(t) = token {
            req.headers_mut().insert(
                "authorization",
                format!("Bearer {t}").parse().unwrap(),
            );
        }
        req
    }

    #[tokio::test]
    async fn required_missing_token_returns_401() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(AuthLayer::required(registry_with_stub()));

        let resp = app.oneshot(make_request(None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn required_valid_token_returns_200() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(AuthLayer::required(registry_with_stub()));

        let resp = app.oneshot(make_request(Some("valid-token"))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn required_invalid_token_returns_401() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(AuthLayer::required(registry_with_stub()));

        let resp = app.oneshot(make_request(Some("wrong-token"))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn optional_no_token_passes_through() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(AuthLayer::optional(registry_with_stub()));

        let resp = app.oneshot(make_request(None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn optional_valid_token_injects_principal() {
        async fn handler(principal: OptPrincipal) -> impl IntoResponse {
            match principal.0 {
                Some(p) => {
                    assert!(p.is_authenticated());
                    "authenticated"
                }
                None => "no-principal",
            }
        }

        let app = Router::new()
            .route("/test", get(handler))
            .layer(AuthLayer::optional(registry_with_stub()));

        let resp = app.oneshot(make_request(Some("valid-token"))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn optional_invalid_token_returns_401() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(AuthLayer::optional(registry_with_stub()));

        let resp = app.oneshot(make_request(Some("wrong-token"))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn agent_scoped_valid_token_returns_200() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(AuthLayer::agent_scoped(registry_with_stub()));

        let resp = app.oneshot(make_request(Some("valid-token"))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn agent_scoped_missing_token_returns_401() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(AuthLayer::agent_scoped(registry_with_stub()));

        let resp = app.oneshot(make_request(None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_principal_extractor_injects_principal() {
        async fn handler(AuthPrincipal(p): AuthPrincipal) -> impl IntoResponse {
            assert_eq!(p.id.as_str(), "peer-1");
            "ok"
        }

        let app = Router::new()
            .route("/test", get(handler))
            .layer(AuthLayer::required(registry_with_stub()));

        let resp = app.oneshot(make_request(Some("valid-token"))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_principal_extractor_rejects_no_auth() {
        async fn handler(_: AuthPrincipal) -> impl IntoResponse { "ok" }

        let app = Router::new()
            .route("/test", get(handler))
            .layer(AuthLayer::required(registry_with_stub()));

        let resp = app.oneshot(make_request(None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn opt_principal_returns_none_when_no_auth() {
        async fn handler(OptPrincipal(p): OptPrincipal) -> impl IntoResponse {
            assert!(p.is_none());
            "ok"
        }

        let app = Router::new()
            .route("/test", get(handler))
            .layer(AuthLayer::optional(registry_with_stub()));

        let resp = app.oneshot(make_request(None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn opt_principal_returns_some_when_authenticated() {
        async fn handler(OptPrincipal(p): OptPrincipal) -> impl IntoResponse {
            assert!(p.is_some());
            "ok"
        }

        let app = Router::new()
            .route("/test", get(handler))
            .layer(AuthLayer::optional(registry_with_stub()));

        let resp = app.oneshot(make_request(Some("valid-token"))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn trusted_principal_is_injected_on_optional() {
        async fn handler(OptPrincipal(p): OptPrincipal) -> impl IntoResponse {
            let principal = p.expect("should have principal");
            assert!(!principal.is_authenticated());
            assert_eq!(principal.auth_method, AuthMethod::SharedOperator);
            "trusted"
        }

        let app = Router::new()
            .route("/test", get(handler))
            .layer(AuthLayer::optional(registry_with_stub()));

        let resp = app.oneshot(make_request(Some("trusted-token"))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn response_body_is_structured_json_on_deny() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(AuthLayer::required(registry_with_stub()));

        let resp = app.oneshot(make_request(Some("wrong-token"))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["error"], "unauthorized");
        assert_eq!(body["status"], 401);
    }

    #[tokio::test]
    async fn middleware_setup_does_not_panic_with_empty_registry() {
        let empty: Arc<dyn AuthRegistry> = Arc::new(LiveAuthRegistry::new(ProviderRegistry::new()));
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(AuthLayer::required(empty));

        let resp = app.oneshot(make_request(Some("any-token"))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
