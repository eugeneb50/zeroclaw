use axum::{
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::AppState;
use zeroclaw_log::{record, Action, Event, EventCategory, EventOutcome};

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
}

fn token_grants_access(scopes: &[String], resource_type: &str, method: &Method) -> bool {
    for scope in scopes {
        let s = scope.to_lowercase();
        if s == "all" {
            return true;
        }
        if s == "readonly" {
            if method == Method::GET {
                return true;
            }
            continue;
        }
        if s.split(',').any(|p| p.trim().eq_ignore_ascii_case(resource_type)) {
            return true;
        }
    }
    false
}

fn extract_resource_type(path: &str) -> Option<&str> {
    let parts: Vec<&str> = path.trim_start_matches("/scim/v2/").split('/').collect();
    parts.first().copied()
}

fn validate_provisioning_token(presented_token: &str, token_hash: &str) -> bool {
    let hash = hex::encode(Sha256::digest(presented_token.as_bytes()));
    hash.len() == token_hash.len() && hash.as_bytes().iter()
        .zip(token_hash.as_bytes())
        .fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub async fn scim_auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let resource_type = match extract_resource_type(&path) {
        Some(rt) => rt,
        None => {
            record!(WARN, Event::new(module_path!(), Action::Reject)
                .with_category(EventCategory::System)
                .with_outcome(EventOutcome::Failure)
                .with_attrs(json!({"method": method.as_str(), "path": path, "verdict": "no_resource_type"})),
                "SCIM auth: could not extract resource type from path"
            );
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid SCIM path"}))).into_response();
        }
    };

    let token = match extract_bearer_token(&headers) {
        Some(t) if !t.is_empty() => t,
        _ => {
            record!(WARN, Event::new(module_path!(), Action::Reject)
                .with_category(EventCategory::System)
                .with_outcome(EventOutcome::Failure)
                .with_attrs(json!({"method": method.as_str(), "path": path, "verdict": "no_token"})),
                "SCIM auth: missing bearer token"
            );
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": "Unauthorized — provisioning token required"}))).into_response();
        }
    };

    let token_entry = {
        let config = state.config.read();
        config.gateway.provisioning_tokens.iter()
            .find(|t| validate_provisioning_token(token, &t.token_hash))
            .cloned()
    };

    let token_entry = match token_entry {
        Some(t) => t,
        None => {
            record!(WARN, Event::new(module_path!(), Action::Reject)
                .with_category(EventCategory::System)
                .with_outcome(EventOutcome::Failure)
                .with_attrs(json!({"method": method.as_str(), "path": path, "verdict": "invalid_token"})),
                "SCIM auth: invalid provisioning token"
            );
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": "Unauthorized — invalid provisioning token"}))).into_response();
        }
    };

    if let Some(expires_at_str) = &token_entry.expires_at {
        if let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(expires_at_str) {
            if chrono::Utc::now() > expires_at {
                record!(WARN, Event::new(module_path!(), Action::Reject)
                    .with_category(EventCategory::System)
                    .with_outcome(EventOutcome::Failure)
                    .with_attrs(json!({"method": method.as_str(), "path": path, "verdict": "expired_token"})),
                    "SCIM auth: provisioning token expired"
                );
                return (StatusCode::UNAUTHORIZED, Json(json!({"error": "Unauthorized — provisioning token expired"}))).into_response();
            }
        }
    }

    if !token_grants_access(&token_entry.scopes, resource_type, &method) {
        record!(WARN, Event::new(module_path!(), Action::Reject)
            .with_category(EventCategory::System)
            .with_outcome(EventOutcome::Failure)
            .with_attrs(json!({
                "method": method.as_str(),
                "path": path,
                "resource_type": resource_type,
                "verdict": "insufficient_scope",
                "token_scopes": token_entry.scopes
            })),
            "SCIM auth: insufficient scope for resource type"
        );
        return (StatusCode::FORBIDDEN, Json(json!({"error": "Forbidden — token scope does not permit this resource type"}))).into_response();
    }

    next.run(req).await
}
