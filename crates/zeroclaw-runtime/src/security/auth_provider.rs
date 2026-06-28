//! RFC #7141 inbound authentication seam: the [`AuthProvider`] trait + a
//! default-deny [`ProviderRegistry`].
//!
//! Each provider verifies ONE credential kind (OIDC token, SSH signature, peer
//! uid, native pairing bearer) and emits a uniform
//! [`zeroclaw_api::principal::Principal`] carrying the identity / claim inputs
//! (the resolved ZeroClaw grants are added additively in the later
//! IamPolicy-wiring step, not in this slice). Dispatch,
//! audit, and per-principal isolation read that `Principal` and never see the
//! credential, so they are provider-agnostic.
//!
//! NOTE — name distinction: this `AuthProvider` (an *inbound auth* trait) is
//! unrelated to [`zeroclaw_providers::auth`]'s `AuthProvider` enum, which names
//! *outbound LLM-provider* OAuth kinds. They live in different crates and never
//! coexist in one import scope.
//!
//! This module is the foundational seam: it has no production call sites yet (the
//! registry is empty until providers are constructed at gateway/RPC boot in a
//! later phase), so it changes no runtime behaviour. Default-deny means an empty
//! registry rejects everything — wiring it on is a deliberate, later step.

use std::sync::Arc;

use async_trait::async_trait;
use sha2::Digest;
use zeroclaw_api::principal::{AuthMethod, AuthOutcome, DenyReason, Principal};

/// A credential presented for verification (the input to the #7141 `initialize`
/// handshake). Secret material is **redacted** in `Debug` — never log it raw.
///
/// Scoped to the accepted RFC #7141 provider set (bearer for native/OIDC, SSH
/// signature, peer uid). Not-yet-accepted credential kinds (e.g. a local
/// username/password) are added by their own scoped change, so this seam never
/// silently carries an unaccepted credential shape.
///
/// SECURITY follow-up (#7141): the secret-bearing arms are redacted in `Debug`
/// and never `Eq`-compared here, but the plaintext is not yet zeroized on drop.
/// In-memory secret scrubbing is currently absent tree-wide (even the encrypted
/// `config::secrets` store keeps plaintext un-scrubbed), so a `Zeroizing`/
/// `SecretString` convention is a separate, repo-wide hardening tracked under the
/// auth-provider work, not bolted onto this one type.
#[derive(Clone)]
#[non_exhaustive]
pub enum Credential {
    /// No credential was presented.
    None,
    /// A bearer token (native pairing token, or an OIDC access/ID token).
    Bearer(String),
    /// An SSH challenge signature over a server-issued nonce.
    SshSignature {
        username: String,
        nonce: Vec<u8>,
        signature: Vec<u8>,
    },
    /// A local transport peer credential (Unix-socket uid).
    Peercred { uid: u32 },
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "Credential::None"),
            Self::Bearer(_) => write!(f, "Credential::Bearer(<redacted>)"),
            Self::SshSignature { username, .. } => f
                .debug_struct("Credential::SshSignature")
                .field("username", username)
                .field("signature", &"<redacted>")
                .finish(),
            Self::Peercred { uid } => f
                .debug_struct("Credential::Peercred")
                .field("uid", uid)
                .finish(),
        }
    }
}

/// An RFC #7141 authentication provider: verifies one credential kind and emits a
/// uniform [`AuthOutcome`]. Implementations live beside their identity source
/// (e.g. `oidc` next to the IdP introspection code, `native` over `PairingGuard`).
///
/// Fail-closed contract: `verify` returns [`AuthOutcome::Denied`] for anything it
/// cannot positively authenticate — never a silent allow.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Stable provider name = its config key (e.g. `"oidc"`, `"native"`,
    /// `"ssh-key"`). Used for enumeration and diagnostics.
    fn name(&self) -> &str;

    /// The [`AuthMethod`] this provider attests on success (also what it
    /// advertises in the handshake).
    fn method(&self) -> AuthMethod;

    /// Whether this provider can attempt the given credential kind. Lets the
    /// registry skip providers that don't apply without burning a `verify`.
    fn accepts(&self, credential: &Credential) -> bool;

    /// Verify the credential and resolve grants. Fail-closed.
    async fn verify(&self, credential: &Credential) -> AuthOutcome;
}

/// The configured set of providers, consulted in order. **Default-deny**: if no
/// provider accepts-and-authenticates the credential, the outcome is
/// [`AuthOutcome::Denied`]. An empty registry rejects everything.
#[derive(Default)]
pub struct ProviderRegistry {
    providers: Vec<Arc<dyn AuthProvider>>,
}

impl ProviderRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a provider (boot-time wiring).
    pub fn register(&mut self, provider: Arc<dyn AuthProvider>) {
        self.providers.push(provider);
    }

    /// `true` if no provider is configured (default-deny will reject all).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    /// The methods this registry advertises (for the handshake `authMethods`).
    #[must_use]
    pub fn advertised_methods(&self) -> Vec<AuthMethod> {
        self.providers.iter().map(|p| p.method()).collect()
    }

    /// The configured provider names, in registration order — the enumeration
    /// surface #7141 exposes over RPC (no hardcoded provider lists).
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.providers.iter().map(|p| p.name()).collect()
    }

    /// Resolve a presented credential to an [`AuthOutcome`], **default-deny and
    /// authoritative-deny**.
    ///
    /// The first accepting provider that authenticates wins. The key safety rule:
    /// a provider that *accepts* a credential but rejects it with a **specific**
    /// [`DenyReason`] (anything other than the generic [`DenyReason::BadCredential`]
    /// — e.g. [`DenyReason::MfaRequired`], [`DenyReason::TokenExpired`],
    /// [`DenyReason::Misconfigured`], [`DenyReason::AliasNotEntitled`]) is
    /// **authoritative**: that outcome is returned immediately so a later,
    /// more broadly-`accept`ing provider can NOT authenticate the same presented
    /// credential past it (e.g. an OIDC provider returning `MfaRequired` for a
    /// bearer token can't be bypassed by a later catch-all bearer provider). Only
    /// the generic `BadCredential` ("not my credential / wrong secret") lets the
    /// registry fall through to the next accepting provider. `None` is denied
    /// before any provider runs. An empty registry denies everything.
    pub async fn resolve(&self, credential: &Credential) -> AuthOutcome {
        if matches!(credential, Credential::None) {
            return AuthOutcome::Denied {
                reason: DenyReason::NoCredential,
            };
        }
        for provider in &self.providers {
            if provider.accepts(credential) {
                match provider.verify(credential).await {
                    allowed @ (AuthOutcome::Authenticated(_) | AuthOutcome::Trusted(_)) => {
                        return allowed;
                    }
                    // Specific deny = authoritative; only generic BadCredential
                    // lets a later accepting provider try the same credential.
                    AuthOutcome::Denied { reason } if reason != DenyReason::BadCredential => {
                        return AuthOutcome::Denied { reason };
                    }
                    AuthOutcome::Denied { .. } => {}
                }
            }
        }
        AuthOutcome::Denied {
            reason: DenyReason::BadCredential,
        }
    }
}

// ── A2A Peer Provider ────────────────────────────────────────────────

/// A2A peer authentication provider.
///
/// Authenticates A2A callers via bearer token or OIDC token, resolving to
/// a peer identity that may be bound to a peer group for scoped discovery.
pub struct A2aPeerProvider {
    /// Resolved peer configurations from config.
    peers: std::collections::HashMap<String, zeroclaw_config::multi_agent::A2aPeerConfig>,
    /// Peer group configurations for resolving allowed aliases.
    peer_groups: std::collections::HashMap<String, zeroclaw_config::multi_agent::PeerGroupConfig>,
}

impl A2aPeerProvider {
    /// Create from config's `[a2a.peers]` map and `[peer_groups]` map.
    pub fn from_config(
        config: &zeroclaw_config::multi_agent::A2aServerSection,
        peer_groups: &std::collections::HashMap<String, zeroclaw_config::multi_agent::PeerGroupConfig>,
    ) -> Self {
        Self {
            peers: config.peers.clone(),
            peer_groups: peer_groups.clone(),
        }
    }

    /// Create an empty provider with no configured peers — every credential
    /// is denied. Useful for unit/scaffold tests that don't exercise A2A
    /// auth, so they can construct `Arc<dyn AuthProvider>` without standing up
    /// a full `[a2a.peers]` config.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            peers: std::collections::HashMap::new(),
            peer_groups: std::collections::HashMap::new(),
        }
    }
}

#[async_trait]
impl AuthProvider for A2aPeerProvider {
    fn name(&self) -> &str {
        "a2a-peer"
    }

    fn method(&self) -> AuthMethod {
        AuthMethod::A2aPeer
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

        for peer in self.peers.values() {
            match &peer.auth {
                zeroclaw_config::multi_agent::A2aPeerAuth::Bearer { token_hash } => {
                    // Compare SHA-256 hash of presented token
                    let presented_hash = hex::encode(sha2::Sha256::digest(token.as_bytes()));
                    if constant_time_eq(&presented_hash, token_hash) {
                        // Resolve allowed_aliases from peer's peer_group
                        let allowed_aliases = if let Some(ref pg) = peer.peer_group {
                            if let Some(group_config) = self.peer_groups.get(pg) {
                                group_config.agents.iter().map(|a| a.clone()).collect()
                            } else {
                                Vec::new()
                            }
                        } else {
                            Vec::new()
                        };

                        let peer_group_value = peer.peer_group.clone().unwrap_or_default();

                        return AuthOutcome::Authenticated(
                            Principal::new(
                                zeroclaw_api::principal::PrincipalId::from(peer.name.clone()),
                                peer.name.clone(),
                                AuthMethod::A2aPeer,
                            )
                            .with_peer_group(peer_group_value)
                            .with_allowed_aliases(allowed_aliases),
                        );
                    }
                }
                zeroclaw_config::multi_agent::A2aPeerAuth::Oidc { issuer, subject } => {
                    // OIDC bearer token verification would happen here
                    // For now, return denied - OIDC verification is a follow-up
                    let _ = (issuer, subject);
                }
                zeroclaw_config::multi_agent::A2aPeerAuth::OidcAny { issuer: _ } => {
                    // OIDC any - would verify token against issuer
                    // For now, return denied - OIDC verification is a follow-up
                }
            }
        }

        AuthOutcome::Denied {
            reason: DenyReason::BadCredential,
        }
    }
}

// Expose constant_time_eq from pairing module for credential comparison
pub use crate::security::pairing::constant_time_eq;

/// Verify a credential through a provider and emit a structured audit
/// record of the outcome through the canonical `zeroclaw_log::record!`
/// channel. Never logs raw tokens (`obs-no-sensitive-data`): only the
/// authentication method, the resolved peer identity (when known), and
/// the deny reason are recorded.
///
/// The heavyweight hash-chained `AuditLogger` (`security::audit::AuditLogger`)
/// is reserved for the future provider-registry rail in PR-D; this lighter
/// path is enough for per-request audit coverage while keeping the helper
/// itself allocation-free and file-free so it can sit on the verify hot
/// path. `subagent: provider` implementation integrates here.
pub async fn verify_with_audit<P>(
    provider: &P,
    credential: &Credential,
    method_name: &'static str,
) -> AuthOutcome
where
    P: AuthProvider + ?Sized,
{
    let outcome = provider.verify(credential).await;
    match &outcome {
        AuthOutcome::Authenticated(p) => {
            zeroclaw_log::record!(
                INFO,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                    .with_attrs(::serde_json::json!({
                        "provider": method_name,
                        "outcome": "authenticated",
                        "user_id": crate::security::redact(&p.user_id),
                        "auth_method": format!("{:?}", p.auth_method),
                    })),
                "AuthProvider::verify success"
            );
        }
        AuthOutcome::Trusted(p) => {
            zeroclaw_log::record!(
                INFO,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                    .with_attrs(::serde_json::json!({
                        "provider": method_name,
                        "outcome": "trusted",
                        "user_id": crate::security::redact(&p.user_id),
                    })),
                "AuthProvider::verify trusted (shared-operator)"
            );
        }
        AuthOutcome::Denied { reason } => {
            zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({
                        "provider": method_name,
                        "outcome": "denied",
                        "reason": format!("{reason:?}"),
                    })),
                "AuthProvider::verify denied"
            );
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroclaw_api::principal::Principal;

    /// A trivial provider that accepts one fixed bearer token.
    struct FixedBearer(&'static str);

    #[async_trait]
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

    #[tokio::test]
    async fn empty_registry_is_default_deny() {
        let reg = ProviderRegistry::new();
        assert!(reg.is_empty());
        let out = reg.resolve(&Credential::Bearer("anything".into())).await;
        assert!(!out.is_allowed());
    }

    #[tokio::test]
    async fn no_credential_is_denied() {
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
    async fn matching_provider_authenticates() {
        let mut reg = ProviderRegistry::new();
        reg.register(Arc::new(FixedBearer("secret")));
        assert_eq!(reg.advertised_methods(), vec![AuthMethod::Native]);
        assert_eq!(reg.names(), vec!["fixed-bearer"]);

        let ok = reg.resolve(&Credential::Bearer("secret".into())).await;
        assert!(ok.is_allowed());

        let bad = reg.resolve(&Credential::Bearer("wrong".into())).await;
        assert!(!bad.is_allowed());
    }

    /// A provider that accepts any bearer but always rejects with a specific reason.
    struct AlwaysMfa;

    #[async_trait]
    impl AuthProvider for AlwaysMfa {
        fn name(&self) -> &str {
            "always-mfa"
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

    #[tokio::test]
    async fn resolve_preserves_specific_deny_reason() {
        let mut reg = ProviderRegistry::new();
        reg.register(Arc::new(AlwaysMfa));
        // A matching provider that rejects with MfaRequired must NOT be flattened
        // to the generic BadCredential fallback.
        let out = reg.resolve(&Credential::Bearer("tok".into())).await;
        assert!(matches!(
            out,
            AuthOutcome::Denied {
                reason: DenyReason::MfaRequired
            }
        ));
    }

    #[tokio::test]
    async fn resolve_falls_back_to_bad_credential_when_no_provider_accepts() {
        let mut reg = ProviderRegistry::new();
        reg.register(Arc::new(FixedBearer("secret")));
        // No provider accepts a Peercred credential → generic BadCredential.
        let out = reg.resolve(&Credential::Peercred { uid: 1000 }).await;
        assert!(matches!(
            out,
            AuthOutcome::Denied {
                reason: DenyReason::BadCredential
            }
        ));
    }

    /// Regression (review #8063): a provider that accepts a credential and rejects
    /// it with a SPECIFIC reason (MfaRequired) must not be bypassed by a later
    /// provider that would authenticate the same credential.
    #[tokio::test]
    async fn specific_deny_is_not_bypassed_by_a_later_provider() {
        let mut reg = ProviderRegistry::new();
        reg.register(Arc::new(AlwaysMfa)); // accepts Bearer → MfaRequired
        reg.register(Arc::new(FixedBearer("tok"))); // would Trust Bearer("tok")
        let out = reg.resolve(&Credential::Bearer("tok".into())).await;
        assert!(
            matches!(
                out,
                AuthOutcome::Denied {
                    reason: DenyReason::MfaRequired
                }
            ),
            "a later provider must not authenticate past an authoritative MfaRequired"
        );
    }

    #[test]
    fn debug_redacts_secret_material() {
        // Bearer is fully redacted.
        assert_eq!(
            format!("{:?}", Credential::Bearer("tok".into())),
            "Credential::Bearer(<redacted>)"
        );
        // SshSignature shows the username but never the signature bytes.
        let dbg = format!(
            "{:?}",
            Credential::SshSignature {
                username: "alice".into(),
                nonce: vec![1, 2, 3],
                signature: vec![0xde, 0xad, 0xbe, 0xef],
            }
        );
        assert!(dbg.contains("alice"));
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("222")); // 0xde — raw signature byte must not appear
    }

    // ── A2aPeerProvider Tests ────────────────────────────────────────────

    fn a2a_section_with_bearer_peer(
        name: &str,
        token: &str,
    ) -> (
        zeroclaw_config::multi_agent::A2aServerSection,
        std::collections::HashMap<String, zeroclaw_config::multi_agent::PeerGroupConfig>,
    ) {
        let token_hash = hex::encode(sha2::Sha256::digest(token.as_bytes()));
        let mut section = zeroclaw_config::multi_agent::A2aServerSection::default();
        section.peers.insert(
            name.to_string(),
            zeroclaw_config::multi_agent::A2aPeerConfig {
                name: name.to_string(),
                auth: zeroclaw_config::multi_agent::A2aPeerAuth::Bearer { token_hash },
                peer_group: None,
            },
        );
        (section, std::collections::HashMap::new())
    }

    #[tokio::test]
    async fn a2a_peer_provider_authenticates_matching_bearer() {
        let (section, peer_groups) = a2a_section_with_bearer_peer("partner", "secret-token");
        let provider = A2aPeerProvider::from_config(&section, &peer_groups);
        assert_eq!(provider.name(), "a2a-peer");
        assert_eq!(provider.method(), AuthMethod::A2aPeer);

        let ok = provider
            .verify(&Credential::Bearer("secret-token".into()))
            .await;
        assert!(ok.is_allowed());
    }

    #[tokio::test]
    async fn a2a_peer_provider_rejects_wrong_bearer() {
        let (section, peer_groups) = a2a_section_with_bearer_peer("partner", "correct-token");
        let provider = A2aPeerProvider::from_config(&section, &peer_groups);

        let bad = provider
            .verify(&Credential::Bearer("wrong-token".into()))
            .await;
        assert!(!bad.is_allowed());
    }

    #[tokio::test]
    async fn a2a_peer_provider_accepts_bearer_credential() {
        let (section, peer_groups) = a2a_section_with_bearer_peer("partner", "token");
        let provider = A2aPeerProvider::from_config(&section, &peer_groups);
        assert!(provider.accepts(&Credential::Bearer("x".into())));
        assert!(!provider.accepts(&Credential::None));
    }

    #[tokio::test]
    async fn a2a_peer_provider_with_peer_group_assigns_principal_fields() {
        use zeroclaw_config::multi_agent::{A2aServerSection, PeerGroupConfig, AgentAlias};
        let token_hash = hex::encode(sha2::Sha256::digest("secret".as_bytes()));
        let mut peer_groups = std::collections::HashMap::new();
        peer_groups.insert(
            "research-org".to_string(),
            PeerGroupConfig {
                channel: "telegram".into(),
                agents: vec![AgentAlias::new("researcher"), AgentAlias::new("analyst")],
                external_peers: Vec::new(),
                ignore: Vec::new(),
                output_modality: zeroclaw_config::multi_agent::OutputModality::Mirror,
            },
        );

        let mut section = A2aServerSection::default();
        let peer_name = zeroclaw_config::multi_agent::PeerGroupName::new("research-org");
        section.peers.insert(
            "partner".to_string(),
            zeroclaw_config::multi_agent::A2aPeerConfig {
                name: "partner".to_string(),
                auth: zeroclaw_config::multi_agent::A2aPeerAuth::Bearer { token_hash },
                peer_group: Some(peer_name),
            },
        );
        let provider = A2aPeerProvider::from_config(&section, &peer_groups);
        let outcome = provider
            .verify(&Credential::Bearer("secret".into()))
            .await;
        match outcome {
            AuthOutcome::Authenticated(principal) => {
                assert_eq!(principal.peer_group.as_deref(), Some("research-org"));
                let aliases: Vec<&str> = principal
                    .allowed_aliases
                    .iter()
                    .map(|a| a.as_str())
                    .collect();
                assert!(aliases.contains(&"researcher"));
                assert!(aliases.contains(&"analyst"));
            }
            _ => panic!("expected Authenticated outcome"),
        }
    }
}
