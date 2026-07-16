//! Shared test utilities for OIDC auth and SCIM provisioning integration tests.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use reqwest::Client;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::broadcast;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};
use zeroclaw_api::grants::ResolvedGrants;
use zeroclaw_api::principal::{AuthMethod, AuthOutcome, Credential, DenyReason, Principal, PrincipalId, WorkspaceId};
use zeroclaw_config::schema::{OidcConfig, OidcValidation};
use zeroclaw_provisioning::{
    config::ProvisioningConfig,
    scim::{ScimClient, ScimUser, ScimGroup, ScimEnterpriseUser},
    sync::{SyncEngine, SyncCursorStore, SyncCursor},
    workspace::{WorkspaceIndex, WorkspaceChanges},
};

use super::{AuthProvider, OidcAuthProvider};

/// Test OIDC Identity Provider simulator
pub struct TestIdP {
    pub server: MockServer,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub audience: String,
    pub signing_key: EncodingKey,
    pub signing_alg: Algorithm,
}

impl TestIdP {
    /// Start a new test IdP with JWKS endpoint
    pub async fn new() -> Result<Self> {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let client_id = "zeroclaw-test".to_string();
        let client_secret = "test-secret".to_string();
        let audience = "zeroclaw".to_string();
        let signing_key = EncodingKey::from_rsa_pem(include_bytes!("../../../../testdata/rsa_private.pem"))?;
        let signing_alg = Algorithm::RS256;

        // Setup JWKS endpoint
        let jwks = Self::generate_jwks(&signing_key)?;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&server)
            .await;

        // Setup OpenID configuration
        let discovery = json!({
            "issuer": issuer,
            "jwks_uri": format!("{}/.well-known/jwks.json", issuer),
            "introspection_endpoint": format!("{}/introspect", issuer),
        });
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(discovery))
            .mount(&server)
            .await;

        Ok(Self {
            server,
            issuer,
            client_id,
            client_secret,
            audience,
            signing_key,
            signing_alg,
        })
    }

    /// Start a new test IdP with introspection endpoint
    pub async fn new_with_introspection() -> Result<Self> {
        let mut idp = Self::new().await?;

        // Setup introspection endpoint
        Mock::given(method("POST"))
            .and(path("/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "active": true,
                "iss": idp.issuer.clone(),
                "sub": "test-user",
                "aud": idp.audience.clone(),
                "exp": chrono::Utc::now().timestamp() + 3600,
                "scope": "openid",
                "realm_access": {"roles": ["ops"]},
            })))
            .mount(&idp.server)
            .await;

        Ok(idp)
    }

    fn generate_jwks(key: &EncodingKey) -> Result<Value> {
        // Extract public key components for JWKS
        let rsa_key = match key {
            EncodingKey::Rsa { key, .. } => key,
            _ => anyhow::bail!("Only RSA keys supported for JWKS"),
        };

        let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa_key.n()?);
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa_key.e()?);

        Ok(json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "kid": "test-key-1",
                "alg": "RS256",
                "n": n,
                "e": e,
            }]
        }))
    }

    /// Generate a valid JWT with given claims
    pub fn mint(&self, mut claims: Value) -> String {
        // Ensure required claims
        if !claims.contains_key("iss") {
            claims["iss"] = json!(self.issuer.clone());
        }
        if !claims.contains_key("aud") {
            claims["aud"] = json!(self.audience.clone());
        }
        if !claims.contains_key("sub") {
            claims["sub"] = json!("test-user");
        }
        if !claims.contains_key("exp") {
            claims["exp"] = json!(chrono::Utc::now().timestamp() + 3600);
        }
        if !claims.contains_key("iat") {
            claims["iat"] = json!(chrono::Utc::now().timestamp());
        }

        let mut header = Header::new(self.signing_alg);
        header.kid = Some("test-key-1".to_string());

        encode(&header, &claims, &self.signing_key).unwrap()
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
        OidcConfig {
            issuer: self.issuer.clone(),
            audience: self.audience.clone(),
            client_id: self.client_id.clone(),
            client_secret: Some(self.client_secret.clone()),
            validation,
            claim_path: "realm_access.roles".to_string(),
            role_map: {
                let mut map = HashMap::new();
                map.insert("ops".to_string(), "operator".to_string());
                map.insert("admin".to_string(), "superadmin".to_string());
                map
            },
            require_mfa: false,
            skip_issuer_check: false,
        }
    }

    /// Create an OIDC auth provider for testing
    pub fn provider(&self, validation: OidcValidation) -> OidcAuthProvider {
        let config = self.oidc_config(validation);
        let profiles = Arc::new({
            let mut map = HashMap::new();
            map.insert("operator".to_string(), ResolvedGrants::operator());
            map.insert("superadmin".to_string(), ResolvedGrants::superadmin());
            map
        });
        OidcAuthProvider::new("test".to_string(), config, profiles).unwrap()
    }
}

/// Test provisioning environment with all components wired together
pub struct TestProvisioningEnv {
    pub temp_dir: TempDir,
    pub workspace_index: Arc<WorkspaceIndex>,
    pub cursor_store: Arc<SyncCursorStore>,
    pub sync_engine: Arc<SyncEngine>,
    pub event_rx: broadcast::Receiver<zeroclaw_provisioning::sync::SyncEvent>,
    pub provisioning_config: ProvisioningConfig,
    pub http_client: Client,
}

impl TestProvisioningEnv {
    /// Create a complete test provisioning environment
    pub async fn new() -> Result<Self> {
        let temp_dir = TempDir::new()?;
        let workspace_index = Arc::new(WorkspaceIndex::new());
        let cursor_store = Arc::new(SyncCursorStore::new(temp_dir.path())?);

        let (event_tx, event_rx) = broadcast::channel(100);

        let provisioning_config = ProvisioningConfig {
            scim_endpoint: "http://localhost:8080/scim/v2".to_string(),
            scim_token: "test-token".to_string(),
            workspace_attribute: "urn:scim:schemas:extension:enterprise:2.0:User:department".to_string(),
            full_sync_on_startup: true,
            sync_interval_seconds: 300,
            static_workspace_mapping: {
                let mut map = HashMap::new();
                map.insert("engineering".to_string(), "ws-eng".to_string());
                map.insert("sales".to_string(), "ws-sales".to_string());
                map.insert("default".to_string(), WorkspaceId::DEFAULT.to_string());
                map
            },
            downstream: vec![],
            multi_tenant: Default::default(),
            conflict: Default::default(),
        };

        let scim_client = ScimClient::new(
            provisioning_config.scim_endpoint.clone(),
            provisioning_config.scim_token.clone(),
            Client::new(),
        )?;

        let sync_engine = Arc::new(SyncEngine::new(
            scim_client,
            workspace_index.clone(),
            cursor_store.clone(),
            provisioning_config.clone(),
            event_tx,
        )?);

        Ok(Self {
            temp_dir,
            workspace_index,
            cursor_store,
            sync_engine,
            event_rx,
            provisioning_config,
            http_client: Client::new(),
        })
    }

    /// Create test SCIM user
    pub fn make_user(
        &self,
        id: &str,
        user_name: &str,
        department: &str,
    ) -> ScimUser {
        ScimUser {
            id: Some(id.to_string()),
            user_name: user_name.to_string(),
            display_name: Some(user_name.to_string()),
            emails: None,
            groups: None,
            active: Some(true),
            enterprise_user: Some(ScimEnterpriseUser {
                department: Some(department.to_string()),
                organization: None,
                division: None,
                cost_center: None,
                employee_number: None,
                manager: None,
            }),
            meta: None,
            custom: Default::default(),
        }
    }

    /// Create test SCIM group
    pub fn make_group(&self, id: &str, display_name: &str) -> ScimGroup {
        ScimGroup {
            id: Some(id.to_string()),
            display_name: Some(display_name.to_string()),
            members: None,
            meta: None,
        }
    }

    /// Populate workspace index with test data
    pub fn seed_workspace(&self, workspace_id: &str, principal_ids: &[&str]) {
        let ws = WorkspaceId(workspace_id.to_string());
        let changes = WorkspaceChanges {
            added: principal_ids
                .iter()
                .map(|p| (ws.clone(), PrincipalId(p.to_string())))
                .collect(),
            ..Default::default()
        };
        self.workspace_index.apply_changes(changes);
    }
}

/// Create a test Principal with OIDC auth method
pub fn make_oidc_principal(
    id: &str,
    workspace_id: &str,
    roles: Vec<&str>,
) -> Principal {
    Principal {
        id: PrincipalId(id.to_string()),
        roles: roles.into_iter().map(|s| s.to_string()).collect(),
        scopes: vec!["openid".to_string()],
        grants: ResolvedGrants::operator(),
        workspace_id: Some(WorkspaceId(workspace_id.to_string())),
        mfa_verified: false,
        auth_method: AuthMethod::Oidc,
        ..Default::default()
    }
}

/// Create a test Principal with shared operator auth
pub fn make_operator_principal(id: &str, workspace_id: &str) -> Principal {
    Principal {
        id: PrincipalId(id.to_string()),
        roles: vec!["operator".to_string()],
        scopes: vec![],
        grants: ResolvedGrants::operator(),
        workspace_id: Some(WorkspaceId(workspace_id.to_string())),
        mfa_verified: true,
        auth_method: AuthMethod::SharedOperator,
        ..Default::default()
    }
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
            assert_eq!(principal.workspace_id.as_ref().map(|w| w.as_str()), Some(expected_workspace));
        }
        AuthOutcome::Trusted(principal) => {
            assert_eq!(principal.id.as_str(), expected_id);
            assert_eq!(principal.workspace_id.as_ref().map(|w| w.as_str()), Some(expected_workspace));
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

/// Create a minimal ProvisioningConfig for testing
pub fn test_provisioning_config() -> ProvisioningConfig {
    let mut static_mapping = HashMap::new();
    static_mapping.insert("engineering".to_string(), "ws-eng".to_string());
    static_mapping.insert("sales".to_string(), "ws-sales".to_string());
    static_mapping.insert("default".to_string(), WorkspaceId::DEFAULT.to_string());

    ProvisioningConfig {
        scim_endpoint: "http://test.example.com/scim/v2".to_string(),
        scim_token: "test-token".to_string(),
        workspace_attribute: "urn:scim:schemas:extension:enterprise:2.0:User:department".to_string(),
        full_sync_on_startup: true,
        sync_interval_seconds: 300,
        static_workspace_mapping: static_mapping,
        downstream: vec![],
        multi_tenant: Default::default(),
        conflict: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_testidp_creation() {
        let idp = TestIdP::new().await.unwrap();
        assert!(!idp.issuer.is_empty());
        assert_eq!(idp.audience, "zeroclaw");
    }

    #[tokio::test]
    async fn test_testidp_mint_token() {
        let idp = TestIdP::new().await.unwrap();
        let token = idp.mint(idp.good_claims());
        assert!(!token.is_empty());
        assert_eq!(token.split('.').count(), 3); // JWT has 3 parts
    }

    #[tokio::test]
    async fn test_provisioning_env_creation() {
        let env = TestProvisioningEnv::new().await.unwrap();
        assert!(env.workspace_index.stats().workspace_count == 0);
    }

    #[test]
    fn test_make_oidc_principal() {
        let p = make_oidc_principal("user123", "ws-eng", vec!["ops"]);
        assert_eq!(p.id.as_str(), "user123");
        assert_eq!(p.workspace_id.unwrap().as_str(), "ws-eng");
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