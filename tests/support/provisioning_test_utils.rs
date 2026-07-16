//! Shared test utilities for OIDC auth and SCIM provisioning integration tests.
//!
//! This module provides:
//! - Mock OIDC Identity Provider using wiremock + ring (ECDSA P-256)
//! - Helper functions for creating test data
//! - Assertion helpers for auth outcomes

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SystemRandom, SecureRandom};
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use reqwest::Client;
use serde_json::{Value, json, Map};
use tempfile::TempDir;
use tokio::sync::broadcast;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};
use zeroclaw_api::grants::{ResolvedGrants, Resource, Verb};
use zeroclaw_api::principal::{AuthMethod, AuthOutcome, Credential, DenyReason, Principal, PrincipalId, WorkspaceId};
use zeroclaw_config::schema::{OidcConfig, OidcValidation};
use zeroclaw_runtime::security::auth_provider::{AuthProvider, OidcAuthProvider, ProviderRegistry};

/// Test OIDC Identity Provider simulator using wiremock + ring (ECDSA P-256)
pub struct TestIdP {
    pub server: MockServer,
    pub issuer: String,
    pub key: EcdsaKeyPair,
}

impl TestIdP {
    /// Start a new test IdP with JWKS endpoint
    pub async fn new() -> Result<Self> {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();

        let public = key.public_key().as_ref();
        let x = URL_SAFE_NO_PAD.encode(&public[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&public[33..65]);
        let jwks = json!({
            "keys": [{
                "kid": "test-key",
                "kty": "EC",
                "crv": "P-256",
                "alg": "ES256",
                "x": x,
                "y": y,
            }]
        });

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jwks_uri": format!("{issuer}/jwks"),
                "introspection_endpoint": format!("{issuer}/introspect"),
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&server)
            .await;

        Ok(Self { server, issuer, key })
    }

    /// Start a new test IdP with introspection endpoint
    pub async fn new_with_introspection() -> Result<Self> {
        let mut idp = Self::new().await?;

        Mock::given(method("POST"))
            .and(path("/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "active": true,
                "iss": idp.issuer.clone(),
                "sub": "test-user",
                "aud": "zeroclaw",
                "exp": chrono::Utc::now().timestamp() + 3600,
                "scope": "openid",
                "realm_access": {"roles": ["ops"]},
            })))
            .mount(&idp.server)
            .await;

        Ok(idp)
    }

    /// Generate a valid JWT with given claims using ECDSA P-256
    pub fn mint(&self, mut claims: Value) -> String {
        let obj = claims.as_object_mut().unwrap();
        if obj.get("iss").is_none() {
            obj.insert("iss".to_string(), json!(self.issuer.clone()));
        }
        if obj.get("aud").is_none() {
            obj.insert("aud".to_string(), json!("zeroclaw"));
        }
        if obj.get("sub").is_none() {
            obj.insert("sub".to_string(), json!("test-user"));
        }
        if obj.get("exp").is_none() {
            obj.insert("exp".to_string(), json!(chrono::Utc::now().timestamp() + 3600));
        }
        if obj.get("iat").is_none() {
            obj.insert("iat".to_string(), json!(chrono::Utc::now().timestamp()));
        }

        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","kid":"test-key"}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
        let signed = format!("{header}.{payload}");
        let rng = SystemRandom::new();
        let sig = self.key.sign(&rng, signed.as_bytes()).unwrap();
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
    }

    /// Generate standard claims for testing
    pub fn good_claims(&self) -> Value {
        json!({
            "sub": "test-user",
            "realm_access": {"roles": ["ops"]},
            "scope": "openid",
        })
    }

    /// Create OIDC config for this test IdP
    pub fn oidc_config(&self, validation: OidcValidation) -> OidcConfig {
        let mut role_map = HashMap::new();
        role_map.insert("ops".to_string(), "operator".to_string());
        role_map.insert("admin".to_string(), "superadmin".to_string());

        OidcConfig {
            issuer: self.issuer.clone(),
            audience: "zeroclaw".into(),
            client_id: "zeroclaw".into(),
            client_secret: Some("s3cret".into()),
            validation,
            claim_path: "realm_access.roles".to_string(),
            role_map,
            require_mfa: false,
            skip_issuer_check: false,
        }
    }

    /// Create an OIDC auth provider for testing
    pub fn provider(&self, validation: OidcValidation) -> OidcAuthProvider {
        let config = self.oidc_config(validation);
        let mut grants = ResolvedGrants::none();
        grants.resources.insert(Resource::System, [Verb::Read].into());
        let mut profiles = HashMap::new();
        profiles.insert("operator".to_string(), grants);
        OidcAuthProvider::new("oidc.test".into(), config, Arc::new(profiles)).unwrap()
    }
}

/// Create a test Principal with OIDC auth method using builder pattern
pub fn make_oidc_principal(id: &str, workspace_id: &str, roles: Vec<&str>) -> Principal {
    let mut grants = ResolvedGrants::none();
    grants.resources.insert(Resource::System, [Verb::Read].into());
    
    Principal::new(id, id, AuthMethod::Oidc)
        .with_roles(roles.into_iter().map(|s| s.to_string()).collect())
        .with_scopes(vec!["openid".to_string()])
        .with_workspace_id(workspace_id)
        .with_mfa_verified(false)
        .with_grants(grants)
}

/// Create a test Principal with shared operator auth
pub fn make_operator_principal(id: &str, workspace_id: &str) -> Principal {
    let mut p = Principal::shared_operator();
    p.workspace_id = WorkspaceId(workspace_id.to_string());
    p
}

/// Wait for sync event with timeout
pub async fn wait_for_sync_event(
    rx: &mut broadcast::Receiver<zeroclaw_provisioning::sync::SyncEvent>,
    timeout: Duration,
) -> Option<zeroclaw_provisioning::sync::SyncEvent> {
    tokio::time::timeout(timeout, rx.recv()).await.ok().flatten()
}

/// Assert AuthOutcome is authenticated with expected principal
pub fn assert_authenticated(outcome: &AuthOutcome, expected_id: &str, expected_workspace: &str) {
    match outcome {
        AuthOutcome::Authenticated(principal) => {
            assert_eq!(principal.id.as_str(), expected_id);
            assert_eq!(principal.workspace_id.as_str(), expected_workspace);
        }
        AuthOutcome::Trusted(principal) => {
            assert_eq!(principal.id.as_str(), expected_id);
            assert_eq!(principal.workspace_id.as_str(), expected_workspace);
        }
        other => panic!("Expected authenticated, got: {:?}", other),
    }
}

/// Assert AuthOutcome is denied with expected reason
pub fn assert_denied(outcome: &AuthOutcome, expected_reason: DenyReason) {
    match outcome {
        AuthOutcome::Denied { reason } => assert_eq!(*reason, expected_reason),
        other => panic!("Expected denied with {:?}, got: {:?}", expected_reason, other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_testidp_creation() {
        let idp = TestIdP::new().await.unwrap();
        assert!(!idp.issuer.is_empty());
    }

    #[tokio::test]
    async fn test_testidp_mint_token() {
        let idp = TestIdP::new().await.unwrap();
        let token = idp.mint(idp.good_claims());
        assert!(!token.is_empty());
        assert_eq!(token.split('.').count(), 3); // JWT has 3 parts
    }

    #[test]
    fn test_make_oidc_principal() {
        let p = make_oidc_principal("user123", "ws-eng", vec!["ops"]);
        assert_eq!(p.id.as_str(), "user123");
        assert_eq!(p.workspace_id.as_str(), "ws-eng");
        assert_eq!(p.roles, vec!["ops"]);
        assert_eq!(p.auth_method, AuthMethod::Oidc);
    }

    #[test]
    fn test_assert_helpers() {
        let p = make_oidc_principal("user123", "ws-eng", vec!["ops"]);
        let outcome = AuthOutcome::Authenticated(p);
        assert_authenticated(&outcome, "user123", "ws-eng");
    }
}