//! OIDC authentication provider — integrates with any OIDC-compliant IdP
//! (authentik, Keycloak, etc.) for bearer token validation and identity resolution.

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, TokenData, jwk::JwkSet};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use url::Url;

use crate::security::auth_provider::{AuthProvider, Credential};
use zeroclaw_api::principal::{AuthMethod, AuthOutcome, DenyReason, Principal, PrincipalId, AgentAlias};
use zeroclaw_config::schema::{Config, OidcConfig, OidcRoleMapping};

/// OIDC discovery document structure.
#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
    issuer: String,
}

/// Cached JWKS with expiry.
struct CachedJwks {
    keys: JwkSet,
    expires_at: Instant,
}

/// OIDC authentication provider.
///
/// Validates JWT tokens locally using cached JWKS, extracts claims,
/// maps IdP groups to allowed agent aliases, and emits a Principal.
pub struct OidcAuthProvider {
    config: Arc<OidcConfig>,
    http_client: Client,
    jwks_cache: RwLock<Option<CachedJwks>>,
}

impl OidcAuthProvider {
    /// Create a new OIDC auth provider from the global config.
    pub fn new(config: &Config) -> Result<Self> {
        let oidc_config = config.security.oidc.clone();
        let http_client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("failed to create HTTP client for OIDC provider")?;

        Ok(Self {
            config: Arc::new(oidc_config),
            http_client,
            jwks_cache: RwLock::new(None),
        })
    }

    /// Get or fetch JWKS, caching for the configured TTL.
    async fn get_jwks(&self) -> Result<JwkSet> {
        let mut cache = self.jwks_cache.write().await;

        // Return cached if still valid
        if let Some(cached) = cache.as_ref() {
            if Instant::now() < cached.expires_at {
                return Ok(cached.keys.clone());
            }
        }

        // Determine JWKS URL: explicit override or discover from issuer
        let jwks_url = if let Some(url) = &self.config.jwks_url {
            url.clone()
        } else {
            let issuer = self.config.issuer_url.trim_end_matches('/');
            let discovery_url = format!("{issuer}/.well-known/openid-configuration");
            let discovery: OidcDiscovery = self.http_client
                .get(&discovery_url)
                .send()
                .await
                .context("failed to fetch OIDC discovery document")?
                .json()
                .await
                .context("failed to parse OIDC discovery document")?;
            discovery.jwks_uri
        };

        let jwks: JwkSet = self.http_client
            .get(&jwks_url)
            .send()
            .await
            .context("failed to fetch JWKS")?
            .json()
            .await
            .context("failed to parse JWKS")?;

        let ttl = Duration::from_secs(self.config.jwks_cache_ttl_secs);
        *cache = Some(CachedJwks {
            keys: jwks.clone(),
            expires_at: Instant::now() + ttl,
        });

        Ok(jwks)
    }

    /// Validate a JWT token and extract claims.
    async fn validate_token(&self, token: &str) -> Result<TokenData<OidcClaims>> {
        let jwks = self.get_jwks().await?;

        // Find the matching key by kid
        let header = jsonwebtoken::decode_header(token)
            .context("failed to decode JWT header")?;
        let kid = header.kid
            .ok_or_else(|| anyhow::anyhow!("JWT missing kid header"))?;

        let jwk = jwks.find(&kid)
            .ok_or_else(|| anyhow::anyhow!("no matching JWKS key for kid: {}", kid))?;

        let decoding_key = DecodingKey::from_jwk(jwk)
            .context("failed to create decoding key from JWK")?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[self.config.client_id.clone()]);
        validation.set_issuer(&[self.config.issuer_url.trim_end_matches('/').to_string()]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = 60; // 60 seconds clock skew tolerance

        let token_data = jsonwebtoken::decode::<OidcClaims>(token, &decoding_key, &validation)
            .context("JWT validation failed")?;

        Ok(token_data)
    }

    /// Map IdP groups to allowed agent aliases.
    fn resolve_allowed_aliases(&self, groups: &[String]) -> Vec<AgentAlias> {
        let mut aliases = Vec::new();
        for group in groups {
            for mapping in &self.config.role_mapping {
                if mapping.group == *group {
                    for alias in &mapping.allowed_aliases {
                        if alias == "*" {
                            return vec![AgentAlias::new("*")]; // wildcard means all
                        }
                        aliases.push(AgentAlias::new(alias));
                    }
                }
            }
        }
        // Deduplicate
        aliases.sort();
        aliases.dedup();
        aliases
    }

    /// Check MFA requirement via amr claim.
    fn check_mfa(&self, claims: &OidcClaims) -> bool {
        if !self.config.require_mfa {
            return true;
        }
        // Check for mfa in amr (authentication methods references)
        claims.amr.as_ref().map_or(false, |amr| {
            amr.iter().any(|m| m == "mfa" || m == "fido" || m == "webauthn")
        })
    }
}

#[derive(Debug, Deserialize)]
struct OidcClaims {
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default, rename = "amr")]
    amr: Option<Vec<String>>,
    exp: u64,
    #[serde(default)]
    iat: Option<u64>,
}

#[async_trait]
impl AuthProvider for OidcAuthProvider {
    fn name(&self) -> &str {
        "oidc"
    }

    fn method(&self) -> AuthMethod {
        AuthMethod::Oidc
    }

    fn accepts(&self, credential: &Credential) -> bool {
        matches!(credential, Credential::Bearer(_))
    }

    async fn verify(&self, credential: &Credential) -> AuthOutcome {
        let Credential::Bearer(token) = credential else {
            return AuthOutcome::Denied {
                reason: DenyReason::BadCredential,
            };
        };

        // Validate token and extract claims
        let token_data = match self.validate_token(token).await {
            Ok(data) => data,
            Err(e) => {
                ::zeroclaw_log::record!(
                    WARN,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                        .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                        .with_attrs(::serde_json::json!({"error": e.to_string()})),
                    "OIDC token validation failed"
                );
                return AuthOutcome::Denied {
                    reason: DenyReason::BadCredential,
                };
            }
        };

        let claims = token_data.claims;

        // Check token expiry
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if claims.exp < now {
            return AuthOutcome::Denied {
                reason: DenyReason::TokenExpired,
            };
        }

        // Check MFA
        if !self.check_mfa(&claims) {
            return AuthOutcome::Denied {
                reason: DenyReason::MfaRequired,
            };
        }

        // Combine groups and roles for mapping
        let mut all_groups = claims.groups.clone();
        all_groups.extend(claims.roles.clone());

        let allowed_aliases = self.resolve_allowed_aliases(&all_groups);

        if allowed_aliases.is_empty() && !self.config.role_mapping.is_empty() {
            // Explicit role mapping configured but no matches — deny
            return AuthOutcome::Denied {
                reason: DenyReason::AliasNotEntitled,
            };
        }

        // Build Principal
        let user_id = claims.email.unwrap_or_else(|| claims.sub.clone());
        let principal = Principal::new(
            PrincipalId::new(claims.sub.clone()),
            user_id.clone(),
            AuthMethod::Oidc,
        )
        .with_roles(all_groups)
        .with_allowed_aliases(allowed_aliases)
        .with_mfa_verified(self.config.require_mfa)
        .with_expires_at(claims.exp);

        AuthOutcome::Authenticated(principal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroclaw_config::schema::Config;

    #[tokio::test]
    async fn oidc_provider_name_and_method() {
        let config = Config::default();
        let provider = OidcAuthProvider::new(&config).unwrap();
        assert_eq!(provider.name(), "oidc");
        assert_eq!(provider.method(), AuthMethod::Oidc);
    }

    #[test]
    fn accepts_only_bearer_credentials() {
        let config = Config::default();
        let provider = OidcAuthProvider::new(&config).unwrap();
        assert!(provider.accepts(&Credential::Bearer("token".into())));
        assert!(!provider.accepts(&Credential::None));
    }
}