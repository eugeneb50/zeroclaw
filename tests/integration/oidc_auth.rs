//! OIDC Authentication Integration Tests
//!
//! Tests the full OIDC authentication flow with a mock IdP (wiremock + ring),
//! covering JWKS validation, introspection, MFA, role mapping, and error cases.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use wiremock::{
    matchers::{method, path, body_json},
    Mock, ResponseTemplate,
};
use zeroclaw_api::grants::{ResolvedGrants, Resource, Verb};
use zeroclaw_api::principal::{AuthMethod, AuthOutcome, DenyReason, Principal, PrincipalId, WorkspaceId};
use zeroclaw_config::schema::{OidcConfig, OidcValidation};
use zeroclaw_runtime::security::auth_provider::{AuthProvider, Credential, OidcAuthProvider, ProviderRegistry};
use base64::Engine as _;
use serde_json::json;

use crate::support::test_utils::{TestIdP, make_oidc_principal, assert_authenticated, assert_denied, make_operator_grants};

/// Helper to create a test environment with mock IdP and provider
async fn setup_oidc_env() -> (TestIdP, OidcAuthProvider) {
    let idp = TestIdP::new().await.unwrap();
    let provider = idp.provider(OidcValidation::Jwks);
    (idp, provider)
}

#[tokio::test]
async fn oidc_jwks_valid_token_authenticates_with_mapped_grants() {
    let (idp, provider) = setup_oidc_env().await;

    let token = idp.mint(idp.good_claims());
    let outcome = provider.verify(&Credential::Bearer(token)).await;

    assert_authenticated(&outcome, "test-user", "default");
    let principal = outcome.principal().unwrap();
    assert_eq!(principal.auth_method, AuthMethod::Oidc);
    assert!(principal.grants.permits(Resource::System, Verb::Read));
    assert!(!principal.grants.permits(Resource::Config, Verb::Update));
}

#[tokio::test]
async fn oidc_jwks_tampered_signature_is_denied() {
    let (idp, provider) = setup_oidc_env().await;

    let mut token = idp.mint(idp.good_claims());
    token.push('x'); // tamper with signature

    let outcome = provider.verify(&Credential::Bearer(token)).await;
    assert_denied(&outcome, DenyReason::BadCredential);
}

#[tokio::test]
async fn oidc_jwks_expired_token_is_denied() {
    let (idp, provider) = setup_oidc_env().await;

    let mut claims = idp.good_claims();
    claims["exp"] = json!(chrono::Utc::now().timestamp() - 100);
    let token = idp.mint(claims);

    let outcome = provider.verify(&Credential::Bearer(token)).await;
    assert_denied(&outcome, DenyReason::TokenExpired);
}

#[tokio::test]
async fn oidc_jwks_wrong_audience_is_denied() {
    let (idp, provider) = setup_oidc_env().await;

    let mut claims = idp.good_claims();
    claims["aud"] = json!("wrong-audience");
    let token = idp.mint(claims);

    let outcome = provider.verify(&Credential::Bearer(token)).await;
    assert_denied(&outcome, DenyReason::BadCredential);
}

#[tokio::test]
async fn oidc_jwks_unmapped_role_is_not_entitled() {
    let (idp, provider) = setup_oidc_env().await;

    let mut claims = idp.good_claims();
    claims["realm_access"] = json!({"roles": ["unmapped-role"]});
    let token = idp.mint(claims);

    let outcome = provider.verify(&Credential::Bearer(token)).await;
    assert_denied(&outcome, DenyReason::NotEntitled);
}

#[tokio::test]
async fn oidc_jwks_mfa_required_without_amr_is_denied() {
    let (idp, provider) = setup_oidc_env().await;

    let mut config = idp.oidc_config(OidcValidation::Jwks);
    config.require_mfa = true;
    let mut grants = ResolvedGrants::none();
    grants.resources.insert(Resource::System, [Verb::Read].into());
    let mut profiles = HashMap::new();
    profiles.insert("operator".to_string(), grants);
    let provider = OidcAuthProvider::new("oidc.test".into(), config, Arc::new(profiles)).unwrap();

    let token = idp.mint(idp.good_claims());
    let outcome = provider.verify(&Credential::Bearer(token)).await;
    assert_denied(&outcome, DenyReason::MfaRequired);
}

#[tokio::test]
async fn oidc_jwks_mfa_required_with_valid_amr_succeeds() {
    let (idp, provider) = setup_oidc_env().await;

    let mut config = idp.oidc_config(OidcValidation::Jwks);
    config.require_mfa = true;
    let mut grants = ResolvedGrants::none();
    grants.resources.insert(Resource::System, [Verb::Read].into());
    let mut profiles = HashMap::new();
    profiles.insert("operator".to_string(), grants);
    let provider = OidcAuthProvider::new("oidc.test".into(), config, Arc::new(profiles)).unwrap();

    let mut claims = idp.good_claims();
    claims["amr"] = json!(["mfa"]);
    let token = idp.mint(claims);

    let outcome = provider.verify(&Credential::Bearer(token)).await;
    assert_authenticated(&outcome, "test-user", "default");
    let principal = outcome.principal().unwrap();
    assert!(principal.mfa_verified);
}

#[tokio::test]
async fn oidc_jwks_opaque_token_rejected() {
    let (idp, provider) = setup_oidc_env().await;

    let opaque_token = "this-is-not-a-jwt-token";
    let outcome = provider.verify(&Credential::Bearer(opaque_token.into())).await;
    assert_denied(&outcome, DenyReason::BadCredential);
}

#[tokio::test]
async fn oidc_jwks_foreign_issuer_not_accepted() {
    let (idp, provider) = setup_oidc_env().await;

    let foreign_issuer = "https://evil.com/";
    let mut claims = idp.good_claims();
    claims["iss"] = json!(foreign_issuer);
    let token = idp.mint(claims);

    let outcome = provider.verify(&Credential::Bearer(token)).await;
    assert_denied(&outcome, DenyReason::BadCredential);
}

#[tokio::test]
async fn oidc_introspection_active_token_authenticates() {
    let idp = TestIdP::new_with_introspection().await.unwrap();
    let provider = idp.provider(OidcValidation::Introspection);

    let token = "valid-introspection-token";
    let outcome = provider.verify(&Credential::Bearer(token.into())).await;
    assert_authenticated(&outcome, "test-user", "default");
}

#[tokio::test]
async fn oidc_introspection_inactive_token_is_denied() {
    let mut idp = TestIdP::new().await.unwrap();

    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "active": false,
        })))
        .mount(&idp.server)
        .await;

    let provider = OidcAuthProvider::new(
        "oidc.test".into(),
        idp.oidc_config(OidcValidation::Introspection),
        Arc::new(HashMap::new()),
    ).unwrap();

    let outcome = provider.verify(&Credential::Bearer("inactive-token".into())).await;
    assert_denied(&outcome, DenyReason::TokenExpired);
}

#[tokio::test]
async fn oidc_introspection_unreachable_idp_fails_closed() {
    let mut idp = TestIdP::new().await.unwrap();

    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&idp.server)
        .await;

    let provider = OidcAuthProvider::new(
        "oidc.test".into(),
        idp.oidc_config(OidcValidation::Introspection),
        Arc::new(HashMap::new()),
    ).unwrap();

    let outcome = provider.verify(&Credential::Bearer("any-token".into())).await;
    assert_denied(&outcome, DenyReason::Misconfigured);
}

#[tokio::test]
async fn oidc_claim_path_walks_nested_and_flat_shapes() {
    let idp = TestIdP::new().await.unwrap();

    // Test nested object path: realm_access.roles
    let mut config = idp.oidc_config(OidcValidation::Jwks);
    config.claim_path = "realm_access.roles".to_string();
    config.role_map = HashMap::from([("ops".to_string(), "operator".to_string())]);
    let mut grants = ResolvedGrants::none();
    grants.resources.insert(Resource::System, [Verb::Read].into());
    let mut profiles = HashMap::new();
    profiles.insert("operator".to_string(), grants);
    let provider = OidcAuthProvider::new("oidc.test".into(), config, Arc::new(profiles)).unwrap();

    let token = idp.mint(idp.good_claims());
    let outcome = provider.verify(&Credential::Bearer(token)).await;
    assert_authenticated(&outcome, "test-user", "default");

    // Test flat array path: groups
    let mut config2 = idp.oidc_config(OidcValidation::Jwks);
    config2.claim_path = "groups".to_string();
    config2.role_map = HashMap::from([("admins".to_string(), "operator".to_string())]);
    let mut grants2 = ResolvedGrants::none();
    grants2.resources.insert(Resource::System, [Verb::Read].into());
    let mut profiles2 = HashMap::new();
    profiles2.insert("operator".to_string(), grants2);
    let provider2 = OidcAuthProvider::new("oidc.test2".into(), config2, Arc::new(profiles2)).unwrap();

    let mut claims = idp.good_claims();
    claims["groups"] = json!(["admins"]);
    let token = idp.mint(claims);
    let outcome = provider2.verify(&Credential::Bearer(token)).await;
    assert_authenticated(&outcome, "test-user", "default");
}

#[tokio::test]
async fn oidc_claim_path_extracts_object_keys_for_zitadel_role_shape() {
    let idp = TestIdP::new().await.unwrap();
    let mut config = idp.oidc_config(OidcValidation::Jwks);
    config.claim_path = "urn:zitadel:iam:org:project:roles".to_string();
    config.role_map = {
        let mut map = HashMap::new();
        map.insert("zeroclaw-admin".to_string(), "superadmin".to_string());
        map.insert("zeroclaw-operator".to_string(), "operator".to_string());
        map
    };
    let profiles = Arc::new({
        let mut map = HashMap::new();
        map.insert("operator".to_string(), make_operator_grants());
        let mut super_grants = ResolvedGrants::none();
        super_grants.resources.insert(Resource::Config, [Verb::Update].into());
        map.insert("superadmin".to_string(), super_grants);
        map
    });
    let provider = OidcAuthProvider::new("test".into(), config, profiles).unwrap();

    let mut claims = idp.good_claims();
    claims["urn:zitadel:iam:org:project:roles"] = json!({
        "zeroclaw-admin": {},
        "zeroclaw-operator": {}
    });
    let token = idp.mint(claims);

    let outcome = provider.verify(&Credential::Bearer(token)).await;
    assert_authenticated(&outcome, "test-user", "default");
    let principal = outcome.principal().unwrap();
    assert!(principal.grants.permits(Resource::Config, Verb::Update));
    assert!(principal.grants.permits(Resource::System, Verb::Read));
}

#[tokio::test]
async fn provider_registry_default_deny() {
    let reg = ProviderRegistry::new();
    assert!(reg.is_empty());
    let out = reg.resolve(&Credential::Bearer("anything".into())).await;
    assert!(!out.is_allowed());
}

#[tokio::test]
async fn provider_registry_no_credential_is_denied() {
    let mut reg = ProviderRegistry::new();
    reg.register(Arc::new(FixedBearer("secret")));
    let out = reg.resolve(&Credential::None).await;
    assert!(matches!(
        out,
        AuthOutcome::Denied {
            reason: DenyReason::NoCredential
        }
    ));
}

#[tokio::test]
async fn provider_registry_matching_provider_authenticates() {
    let mut reg = ProviderRegistry::new();
    reg.register(Arc::new(FixedBearer("secret")));
    assert_eq!(reg.advertised_methods(), vec![AuthMethod::Native]);
    assert_eq!(reg.names(), vec!["fixed-bearer"]);

    let out = reg.resolve(&Credential::Bearer("secret".into())).await;
    assert!(matches!(out, AuthOutcome::Trusted(_)));
}

#[tokio::test]
async fn provider_registry_wrong_credential_falls_through() {
    let mut reg = ProviderRegistry::new();
    reg.register(Arc::new(FixedBearer("secret")));

    let out = reg.resolve(&Credential::Bearer("wrong".into())).await;
    assert!(matches!(
        out,
        AuthOutcome::Denied {
            reason: DenyReason::BadCredential
        }
    ));
}

#[tokio::test]
async fn provider_registry_specific_deny_is_not_bypassed_by_later_provider() {
    let mut reg = ProviderRegistry::new();
    reg.register(Arc::new(SpecificDenyProvider));
    reg.register(Arc::new(FixedBearer("secret")));

    let out = reg.resolve(&Credential::Bearer("secret".into())).await;
    assert!(matches!(
        out,
        AuthOutcome::Denied {
            reason: DenyReason::MfaRequired
        }
    ));
}

#[tokio::test]
async fn provider_registry_first_match_wins() {
    let mut reg = ProviderRegistry::new();
    reg.register(Arc::new(FixedBearer("first")));
    reg.register(Arc::new(FixedBearer("second")));

    let out = reg.resolve(&Credential::Bearer("first".into())).await;
    assert!(matches!(out, AuthOutcome::Trusted(_)));
    let out = reg.resolve(&Credential::Bearer("second".into())).await;
    assert!(matches!(out, AuthOutcome::Trusted(_)));
}

#[tokio::test]
async fn provider_registry_multiple_oidc_providers_registered() {
    let idp = TestIdP::new().await.unwrap();
    let mut reg = ProviderRegistry::new();
    reg.register(Arc::new(idp.provider(OidcValidation::Jwks)));
    assert_eq!(reg.names(), vec!["oidc.test"]);
    assert_eq!(reg.advertised_methods(), vec![AuthMethod::Oidc]);
}

/// Simple fixed-token provider for testing registry behavior
struct FixedBearer(&'static str);

#[async_trait::async_trait]
impl AuthProvider for FixedBearer {
    fn name(&self) -> &str {
        "fixed-bearer"
    }
    fn method(&self) -> AuthMethod {
        AuthMethod::Native
    }
    fn accepts(&self, credential: &Credential) -> bool {
        matches!(credential, Credential::Bearer(_))
    }
    async fn verify(&self, credential: &Credential) -> AuthOutcome {
        match credential {
            Credential::Bearer(t) if t == self.0 => {
                AuthOutcome::Trusted(Principal::shared_operator())
            }
            _ => AuthOutcome::Denied {
                reason: DenyReason::BadCredential,
            },
        }
    }
}

/// Provider that always returns a specific deny reason (not BadCredential)
struct SpecificDenyProvider;

#[async_trait::async_trait]
impl AuthProvider for SpecificDenyProvider {
    fn name(&self) -> &str {
        "specific-deny"
    }
    fn method(&self) -> AuthMethod {
        AuthMethod::Oidc
    }
    fn accepts(&self, credential: &Credential) -> bool {
        matches!(credential, Credential::Bearer(_))
    }
    async fn verify(&self, _credential: &Credential) -> AuthOutcome {
        AuthOutcome::Denied {
            reason: DenyReason::MfaRequired,
        }
    }
}

// Azure AD / skip_issuer_check integration tests

#[tokio::test]
async fn azure_ad_skip_issuer_check_accepts_mismatched_iss() {
    let idp = TestIdP::new().await.unwrap();

    let custom_issuer = "https://sts.windows.net/different-tenant/";
    let token = idp.mint_with_custom_issuer(idp.good_claims(), custom_issuer);

    let config = OidcConfig {
        issuer: idp.issuer.clone(),
        audience: "zeroclaw".into(),
        client_id: "zeroclaw".into(),
        client_secret: Some("s3cret".into()),
        validation: OidcValidation::Jwks,
        claim_path: "realm_access.roles".into(),
        role_map: HashMap::from([("ops".to_string(), "operator".to_string())]),
        require_mfa: false,
        skip_issuer_check: true,
    };
    let mut grants = ResolvedGrants::none();
    grants.resources.insert(Resource::System, [Verb::Read].into());
    let mut profiles = HashMap::new();
    profiles.insert("operator".to_string(), grants);
    let provider = OidcAuthProvider::new("oidc.azure".into(), config, Arc::new(profiles)).unwrap();

    let outcome = provider.verify(&Credential::Bearer(token)).await;
    assert_authenticated(&outcome, "test-user", "default");
}

#[tokio::test]
async fn azure_ad_skip_issuer_check_false_rejects_mismatched_iss() {
    let idp = TestIdP::new().await.unwrap();
    let custom_issuer = "https://sts.windows.net/different-tenant/";
    let token = idp.mint_with_custom_issuer(idp.good_claims(), custom_issuer);

    let config = OidcConfig {
        issuer: idp.issuer.clone(),
        audience: "zeroclaw".into(),
        client_id: "zeroclaw".into(),
        client_secret: Some("s3cret".into()),
        validation: OidcValidation::Jwks,
        claim_path: "realm_access.roles".into(),
        role_map: HashMap::from([("ops".to_string(), "operator".to_string())]),
        require_mfa: false,
        skip_issuer_check: false,
    };
    let mut grants = ResolvedGrants::none();
    grants.resources.insert(Resource::System, [Verb::Read].into());
    let mut profiles = HashMap::new();
    profiles.insert("operator".to_string(), grants);
    let provider = OidcAuthProvider::new("oidc.azure".into(), config, Arc::new(profiles)).unwrap();

    let outcome = provider.verify(&Credential::Bearer(token)).await;
    assert_denied(&outcome, DenyReason::BadCredential);
}

#[tokio::test]
async fn azure_ad_skip_issuer_check_still_checks_audience() {
    let idp = TestIdP::new().await.unwrap();
    let token = idp.mint(idp.good_claims());

    let config = OidcConfig {
        issuer: idp.issuer.clone(),
        audience: "different-audience".into(),
        client_id: "zeroclaw".into(),
        client_secret: Some("s3cret".into()),
        validation: OidcValidation::Jwks,
        claim_path: "realm_access.roles".into(),
        role_map: HashMap::from([("ops".to_string(), "operator".to_string())]),
        require_mfa: false,
        skip_issuer_check: true,
    };
    let mut grants = ResolvedGrants::none();
    grants.resources.insert(Resource::System, [Verb::Read].into());
    let mut profiles = HashMap::new();
    profiles.insert("operator".to_string(), grants);
    let provider = OidcAuthProvider::new("oidc.azure".into(), config, Arc::new(profiles)).unwrap();

    let outcome = provider.verify(&Credential::Bearer(token)).await;
    assert_denied(&outcome, DenyReason::BadCredential);
}

#[tokio::test]
async fn azure_ad_skip_issuer_check_still_checks_signature() {
    let idp = TestIdP::new().await.unwrap();
    let token = idp.mint(idp.good_claims());

    let mut tampered = token;
    tampered.push('x');

    let config = OidcConfig {
        issuer: idp.issuer.clone(),
        audience: "zeroclaw".into(),
        client_id: "zeroclaw".into(),
        client_secret: Some("s3cret".into()),
        validation: OidcValidation::Jwks,
        claim_path: "realm_access.roles".into(),
        role_map: HashMap::from([("ops".to_string(), "operator".to_string())]),
        require_mfa: false,
        skip_issuer_check: true,
    };
    let mut grants = ResolvedGrants::none();
    grants.resources.insert(Resource::System, [Verb::Read].into());
    let mut profiles = HashMap::new();
    profiles.insert("operator".to_string(), grants);
    let provider = OidcAuthProvider::new("oidc.azure".into(), config, Arc::new(profiles)).unwrap();

    let outcome = provider.verify(&Credential::Bearer(tampered)).await;
    assert_denied(&outcome, DenyReason::BadCredential);
}

#[tokio::test]
async fn azure_ad_skip_issuer_check_still_checks_expiry() {
    let idp = TestIdP::new().await.unwrap();
    let mut claims = idp.good_claims();
    claims["exp"] = json!(chrono::Utc::now().timestamp() - 100);
    let token = idp.mint(claims);

    let config = OidcConfig {
        issuer: idp.issuer.clone(),
        audience: "zeroclaw".into(),
        client_id: "zeroclaw".into(),
        client_secret: Some("s3cret".into()),
        validation: OidcValidation::Jwks,
        claim_path: "realm_access.roles".into(),
        role_map: HashMap::from([("ops".to_string(), "operator".to_string())]),
        require_mfa: false,
        skip_issuer_check: true,
    };
    let mut grants = ResolvedGrants::none();
    grants.resources.insert(Resource::System, [Verb::Read].into());
    let mut profiles = HashMap::new();
    profiles.insert("operator".to_string(), grants);
    let provider = OidcAuthProvider::new("oidc.azure".into(), config, Arc::new(profiles)).unwrap();

    let outcome = provider.verify(&Credential::Bearer(token)).await;
    assert_denied(&outcome, DenyReason::TokenExpired);
}

#[tokio::test]
async fn azure_ad_skip_issuer_check_accepts_any_bearer_in_accepts() {
    let idp = TestIdP::new().await.unwrap();
    let token = idp.mint(idp.good_claims());

    let config = OidcConfig {
        issuer: idp.issuer.clone(),
        audience: "zeroclaw".into(),
        client_id: "zeroclaw".into(),
        client_secret: Some("s3cret".into()),
        validation: OidcValidation::Jwks,
        claim_path: "realm_access.roles".into(),
        role_map: HashMap::from([("ops".to_string(), "operator".to_string())]),
        require_mfa: false,
        skip_issuer_check: true,
    };
    let mut grants = ResolvedGrants::none();
    grants.resources.insert(Resource::System, [Verb::Read].into());
    let mut profiles = HashMap::new();
    profiles.insert("operator".to_string(), grants);
    let provider = OidcAuthProvider::new("oidc.azure".into(), config, Arc::new(profiles)).unwrap();

    assert!(provider.accepts(&Credential::Bearer(token)));
    assert!(provider.accepts(&Credential::Bearer("any-random-bearer".into())));
    assert!(!provider.accepts(&Credential::None));
    assert!(!provider.accepts(&Credential::Peercred { uid: 1000 }));
}