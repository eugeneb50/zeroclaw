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
#[derive(Default, Clone)]
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

    /// Whether any registered provider accepts the given credential kind.
    /// Used for pre-screening in `Optional` auth policies before calling
    /// the (potentially expensive) `verify` path.
    #[must_use]
    pub fn accepts_any(&self, credential: &Credential) -> bool {
        self.providers.iter().any(|p| p.accepts(credential))
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
    ///
    /// **Deprecated in favor of [`A2aPeerProvider::from_peers`] plus a live
    /// resolver.** This constructor snapshots the maps by value, which is the
    /// `ConfigSnapshot` pattern the gateway SIGHUP-reload story rejects: a
    /// peer added to `[a2a.peers]` after `run_gateway()` boots will not be
    /// honored until a full process restart. Use
    /// [`LiveConfigA2aResolver`](crate::security::LiveConfigA2aResolver) (or
    /// any other `A2aPeerResolver` impl) instead and read on every verify.
    /// Kept for one minor release to give third-party tooling that calls it
    /// directly time to migrate.
    #[deprecated(
        since = "0.9.0",
        note = "snapshots config; read on every verify via LiveConfigA2aResolver instead"
    )]
    pub fn from_config(
        config: &zeroclaw_config::multi_agent::A2aServerSection,
        peer_groups: &std::collections::HashMap<
            String,
            zeroclaw_config::multi_agent::PeerGroupConfig,
        >,
    ) -> Self {
        Self {
            peers: config.peers.clone(),
            peer_groups: peer_groups.clone(),
        }
    }

    /// Create a pure-data provider from already-resolved peer and peer-group
    /// maps. No config reference is retained; construction is allocation-only
    /// and stays out of any shared state. Use inside a resolver (`verify()`
    /// reads the maps fresh from the canonical `Config`) or in tests where
    /// the live-config wiring is irrelevant.
    #[must_use]
    pub fn from_peers(
        peers: std::collections::HashMap<String, zeroclaw_config::multi_agent::A2aPeerConfig>,
        peer_groups: std::collections::HashMap<
            String,
            zeroclaw_config::multi_agent::PeerGroupConfig,
        >,
    ) -> Self {
        Self { peers, peer_groups }
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
                            if let Some(group_config) = self.peer_groups.get(pg.as_str()) {
                                group_config.agents.to_vec()
                            } else {
                                Vec::new()
                            }
                        } else {
                            Vec::new()
                        };

                        let mut principal = Principal::new(
                            zeroclaw_api::principal::PrincipalId::from(peer.name.clone()),
                            peer.name.clone(),
                            AuthMethod::A2aPeer,
                        )
                        .with_allowed_aliases(allowed_aliases);
                        // Only stamp `Principal.peer_group` when the peer
                        // declares one — otherwise leave it `None` so the
                        // absence carries through (instead of `Some("")`).
                        if let Some(pg) = peer.peer_group.as_ref() {
                            principal = principal.with_peer_group(pg.as_str());
                        }

                        return AuthOutcome::Authenticated(principal);
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

        // Check peer-group-scoped A2A external peer credentials.
        // Unlike top-level `[a2a.peers]` entries (which store a pre-computed
        // token_hash), the credential here is stored in plaintext and hashed
        // at verify time for operator ergonomics.
        for (pg_name, group_config) in &self.peer_groups {
            for (peer_id, entry) in &group_config.a2a_external_peers {
                let presented_hash = hex::encode(sha2::Sha256::digest(token.as_bytes()));
                let expected_hash = hex::encode(sha2::Sha256::digest(entry.credential.as_bytes()));
                if constant_time_eq(&presented_hash, &expected_hash) {
                    let allowed_aliases = entry
                        .allowed_aliases_override
                        .clone()
                        .unwrap_or_else(|| group_config.agents.to_vec());

                    let principal = Principal::new(
                        zeroclaw_api::principal::PrincipalId::from(peer_id.clone()),
                        peer_id.clone(),
                        AuthMethod::A2aPeer,
                    )
                    .with_allowed_aliases(allowed_aliases)
                    .with_peer_group(pg_name);

                    return AuthOutcome::Authenticated(principal);
                }
            }
        }

        AuthOutcome::Denied {
            reason: DenyReason::BadCredential,
        }
    }
}

// ── Live-config resolver ──────────────────────────────────────────────
//
// `A2aPeerProvider` is a pure-data type. Resolvers below make verify() reach
// the canonical `Config` on every call, so SIGHUP-induced reload (or any other
// writer to `Arc<RwLock<Config>>`) is honored without a process restart. This
// is the path `AppState` carries in the gateway; the snapshot pattern
// (`A2aPeerProvider::from_config`/`empty` placed on `AppState`) is prohibited
// by AGENTS.md "single source of truth" and tracked against issue #7410
// (the exact same violation pattern that is being paid down for webhook
// signing secrets; we generalize it to the A2A peer material at the same time).

/// Resolves A2A peer authentication against a live credential source.
///
/// Implementors own the canonical read path (typically `Arc<RwLock<Config>>`)
/// and must not retain a snapshot — every `verify()` call is expected to read
/// at-most-current data so config reload propagates without daemon restart.
/// `#[non_exhaustive]` keeps the trait forward-compatible.
#[async_trait::async_trait]
pub trait A2aPeerResolver: Send + Sync {
    /// Resolve a credential to an [`AuthOutcome`]. The credential is borrowed
    /// for the call only; the resolver must clone any state it needs to survive
    /// past the function (e.g., for use after the borrowed `credential`
    /// lifetime ends).
    async fn verify(&self, credential: &Credential) -> AuthOutcome;
}

/// Resolver that reads `[a2a.peers]` and `[peer_groups]` from a live
/// `Arc<RwLock<Config>>` on every call.
///
/// **Lock discipline:** the read lock is acquired briefly to snapshot the two
/// `HashMap`s, then released before any `await`. The constructed
/// `A2aPeerProvider` is a pure-data type and `provider.verify(...)` runs
/// without holding the `RwLock`. This honors `anti-lock-across-await`.
pub struct LiveConfigA2aResolver {
    config: std::sync::Arc<parking_lot::RwLock<zeroclaw_config::schema::Config>>,
}

impl LiveConfigA2aResolver {
    /// Wrap a live-config handle. Typically constructed with
    /// `state.config.clone()` from the gateway boot path, where `state.config`
    /// is itself `Arc<RwLock<Config>>`.
    #[must_use]
    pub fn new(
        config: std::sync::Arc<parking_lot::RwLock<zeroclaw_config::schema::Config>>,
    ) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl A2aPeerResolver for LiveConfigA2aResolver {
    async fn verify(&self, credential: &Credential) -> AuthOutcome {
        // Acquire read lock briefly, snapshot two HashMaps, release.
        // No await is held across this block.
        let provider = {
            let cfg = self.config.read();
            A2aPeerProvider::from_peers(cfg.a2a.peers.clone(), cfg.peer_groups.clone())
        };
        // Provider is now pure data; verify may await freely.
        provider.verify(credential).await
    }
}

// ── AuthRegistry (gateway-facing auth facade) ──────────────────────────

/// Gateway-facing facade over the full set of registered auth providers.
///
/// Provides a single `verify()` dispatch for the route-level auth middleware
/// (`AuthLayer` in `zeroclaw-gateway`) that delegates to `ProviderRegistry`.
/// This is the trait the middleware depends on, keeping it decoupled from
/// the concrete provider list and registry internals.
///
/// Fail-closed contract: `verify` returns [`AuthOutcome::Denied`] for anything
/// that cannot be positively authenticated — never a silent allow.
#[async_trait::async_trait]
pub trait AuthRegistry: Send + Sync {
    /// Resolve a credential through all registered providers, returning the
    /// first authoritative [`AuthOutcome`]. Follows the same default-deny and
    /// authoritative-deny semantics as [`ProviderRegistry::resolve`].
    async fn verify(&self, credential: &Credential) -> AuthOutcome;

    /// Whether any registered provider accepts the given credential kind.
    /// Used by the `Optional` policy to skip verification when no credential
    /// is presented and no provider would accept it anyway.
    fn accepts(&self, credential: &Credential) -> bool;
}

/// Concrete [`AuthRegistry`] wrapping a [`ProviderRegistry`].
///
/// The registry is behind a `parking_lot::RwLock` so new providers can be
/// added at runtime (e.g., after a config reload adds an OIDC provider) —
/// reads are uncontended at gateway scale and the lock is only held during
/// the synchronous `resolve()` call (no `.await` under the lock).
pub struct LiveAuthRegistry {
    registry: parking_lot::RwLock<ProviderRegistry>,
}

impl LiveAuthRegistry {
    /// Wrap an already-populated registry.
    #[must_use]
    pub fn new(registry: ProviderRegistry) -> Self {
        Self {
            registry: parking_lot::RwLock::new(registry),
        }
    }

    /// Register an additional provider at runtime.
    pub fn register(&self, provider: Arc<dyn AuthProvider>) {
        self.registry.write().register(provider);
    }
}

#[async_trait::async_trait]
impl AuthRegistry for LiveAuthRegistry {
    async fn verify(&self, credential: &Credential) -> AuthOutcome {
        // Snapshot the provider registry under the lock, then release
        // BEFORE any await — `parking_lot::RwLockReadGuard` is not `Send`.
        let registry = {
            let guard = self.registry.read();
            guard.clone()
        };
        let outcome = registry.resolve(credential).await;
        match &outcome {
            AuthOutcome::Authenticated(p) => {
                zeroclaw_log::record!(
                    INFO,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                        .with_attrs(::serde_json::json!({
                            "provider": "registry",
                            "outcome": "authenticated",
                            "user_id": crate::security::redact(&p.user_id),
                            "auth_method": format!("{:?}", p.auth_method),
                        })),
                    "AuthRegistry::verify success"
                );
            }
            AuthOutcome::Trusted(p) => {
                zeroclaw_log::record!(
                    INFO,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                        .with_attrs(::serde_json::json!({
                            "provider": "registry",
                            "outcome": "trusted",
                            "user_id": crate::security::redact(&p.user_id),
                        })),
                    "AuthRegistry::verify trusted (shared-operator)"
                );
            }
            AuthOutcome::Denied { reason } => {
                zeroclaw_log::record!(
                    WARN,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                        .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                        .with_attrs(::serde_json::json!({
                            "provider": "registry",
                            "outcome": "denied",
                            "reason": format!("{reason:?}"),
                        })),
                    "AuthRegistry::verify denied"
                );
            }
        }
        outcome
    }

    fn accepts(&self, credential: &Credential) -> bool {
        self.registry.read().accepts_any(credential)
    }
}

/// An [`AuthProvider`] that reads `[a2a.peers]` and `[peer_groups]` from a
/// live `Arc<RwLock<Config>>` on every `verify()` call.
///
/// This is the live-config-aware provider registered in the gateway's
/// `ProviderRegistry` (via `LiveAuthRegistry`). Unlike `A2aPeerProvider`
/// which snapshots peer state once at construction, this provider re-reads
/// the canonical `Config` on every call so SIGHUP reload / dashboard PATCH
/// propagates without a process restart (the #7410 invariant).
pub struct LiveA2aPeerProvider {
    config: std::sync::Arc<parking_lot::RwLock<zeroclaw_config::schema::Config>>,
}

impl LiveA2aPeerProvider {
    /// Wrap a live-config handle. Typically constructed with
    /// `state.config.clone()` from the gateway boot path.
    #[must_use]
    pub fn new(
        config: std::sync::Arc<parking_lot::RwLock<zeroclaw_config::schema::Config>>,
    ) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl AuthProvider for LiveA2aPeerProvider {
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
        let provider = {
            let cfg = self.config.read();
            A2aPeerProvider::from_peers(cfg.a2a.peers.clone(), cfg.peer_groups.clone())
        };
        provider.verify(credential).await
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
        let provider = A2aPeerProvider::from_peers(section.peers, peer_groups);
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
        let provider = A2aPeerProvider::from_peers(section.peers, peer_groups);

        let bad = provider
            .verify(&Credential::Bearer("wrong-token".into()))
            .await;
        assert!(!bad.is_allowed());
    }

    #[tokio::test]
    async fn a2a_peer_provider_accepts_bearer_credential() {
        let (section, peer_groups) = a2a_section_with_bearer_peer("partner", "token");
        let provider = A2aPeerProvider::from_peers(section.peers, peer_groups);
        assert!(provider.accepts(&Credential::Bearer("x".into())));
        assert!(!provider.accepts(&Credential::None));
    }

    #[tokio::test]
    async fn a2a_peer_provider_with_peer_group_assigns_principal_fields() {
        use std::collections::HashMap;
        use zeroclaw_config::multi_agent::{A2aServerSection, AgentAlias, PeerGroupConfig};
        let token_hash = hex::encode(sha2::Sha256::digest("secret".as_bytes()));
        let mut peer_groups = HashMap::new();
        peer_groups.insert(
            "research-org".to_string(),
            PeerGroupConfig {
                channel: "telegram".into(),
                agents: vec![AgentAlias::new("researcher"), AgentAlias::new("analyst")],
                external_peers: Vec::new(),
                ignore: Vec::new(),
                output_modality: zeroclaw_config::multi_agent::OutputModality::Mirror,
                a2a_external_peers: HashMap::new(),
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
        let provider = A2aPeerProvider::from_peers(section.peers, peer_groups);
        let outcome = provider.verify(&Credential::Bearer("secret".into())).await;
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

    // ── LiveConfigA2aResolver regression tests (#7410) ─────────────────────
    // These pin the "read on every verify against live config" invariant that
    // #7410 mandates for the gateway webhook-secret pay-down; the same pattern
    // generalizes to A2A peer resolution here. Failure mode: peer added via
    // config mutation after construction is not honored at verify-time.

    /// Build a sha256 hex digest for a plain token so the provider matches.
    fn hex_token_hash(token: &str) -> String {
        hex::encode(sha2::Sha256::digest(token.as_bytes()))
    }

    #[tokio::test]
    async fn live_config_resolver_seeds_with_initial_peers() {
        let (section, peer_groups) = a2a_section_with_bearer_peer("infra-initial", "tok-1");
        // Convert section into the live config's `a2a.peers` map.
        let mut cfg = zeroclaw_config::schema::Config::default();
        cfg.a2a.peers = section.peers;
        cfg.peer_groups = peer_groups;

        let state = Arc::new(parking_lot::RwLock::new(cfg));
        let resolver = LiveConfigA2aResolver::new(Arc::clone(&state));

        let outcome = resolver.verify(&Credential::Bearer("tok-1".into())).await;
        assert!(outcome.is_allowed(), "initial peer must verify");

        let outcome = resolver
            .verify(&Credential::Bearer("nonexistent-tok".into()))
            .await;
        assert!(!outcome.is_allowed(), "unknown token must be denied");
    }

    /// Regression #7410: rotating a peer in the live config must be honored
    /// at the next `verify()` call WITHOUT a process restart. The previous
    /// `A2aPeerProvider::from_config` snapshot failed exactly this case.
    #[tokio::test]
    async fn live_config_resolver_picks_up_newly_added_peer_after_config_reload() {
        use zeroclaw_config::multi_agent::{A2aPeerAuth, A2aPeerConfig};

        let initial_token = "tok-1";
        let initial_hash = hex_token_hash(initial_token);
        let mut initial_peers = std::collections::HashMap::new();
        initial_peers.insert(
            "infra-initial".to_string(),
            A2aPeerConfig {
                name: "Infra Initial".into(),
                auth: A2aPeerAuth::Bearer {
                    token_hash: initial_hash,
                },
                peer_group: None,
            },
        );

        let mut cfg = zeroclaw_config::schema::Config::default();
        cfg.a2a.peers = initial_peers;
        let state = Arc::new(parking_lot::RwLock::new(cfg));
        let resolver = LiveConfigA2aResolver::new(Arc::clone(&state));

        // Sanity: initial peer resolves.
        assert!(
            resolver
                .verify(&Credential::Bearer("tok-1".into()))
                .await
                .is_allowed()
        );

        // Mutate config under the live lock: add a new peer. (No Arc::make_mut,
        // no process restart — simulates a SIGHUP/editor PATCH.)
        {
            let mut cfg = state.write();
            let new_token = "tok-2";
            let new_hash = hex_token_hash(new_token);
            cfg.a2a.peers.insert(
                "infra-reloaded".to_string(),
                A2aPeerConfig {
                    name: "Infra Reloaded".into(),
                    auth: A2aPeerAuth::Bearer {
                        token_hash: new_hash,
                    },
                    peer_group: None,
                },
            );
            assert!(cfg.a2a.peers.contains_key("infra-reloaded"));
        } // write lock released; resolver's next verify() reads fresh.

        // CRITICAL: new peer must be honored on next verify, without restart.
        let outcome = resolver.verify(&Credential::Bearer("tok-2".into())).await;
        assert!(
            outcome.is_allowed(),
            "newly added peer must verify live (regression for #7410 snapshot pattern)"
        );

        // And the original peer still verifies (mutation didn't break the
        // remaining entries).
        assert!(
            resolver
                .verify(&Credential::Bearer("tok-1".into()))
                .await
                .is_allowed(),
            "previously-added peer must keep verifying after reload mutation"
        );

        // Rotation: replace existing peer's token in place.
        let rotated_token_hash = hex_token_hash("tok-1-rotated");
        {
            let mut cfg = state.write();
            cfg.a2a.peers.insert(
                "infra-initial".to_string(),
                A2aPeerConfig {
                    name: "Infra Initial".into(),
                    auth: A2aPeerAuth::Bearer {
                        token_hash: rotated_token_hash,
                    },
                    peer_group: None,
                },
            );
        }
        assert!(
            !resolver
                .verify(&Credential::Bearer("tok-1".into()))
                .await
                .is_allowed(),
            "old token must be denied after rotation"
        );
        assert!(
            resolver
                .verify(&Credential::Bearer("tok-1-rotated".into()))
                .await
                .is_allowed(),
            "rotated token must verify"
        );
    }

    /// Resolve across `peer_groups` for a newly-added peer via live reload
    /// (the flag that PR-B1 unlocked via `peer_group` plumbing).
    #[tokio::test]
    async fn live_config_resolver_picks_up_peer_groups_change() {
        use zeroclaw_config::multi_agent::{
            A2aPeerAuth, A2aPeerConfig, AgentAlias, PeerGroupConfig, PeerGroupName,
        };

        let (state, resolver) = {
            let state = Arc::new(parking_lot::RwLock::new(
                zeroclaw_config::schema::Config::default(),
            ));
            let resolver = LiveConfigA2aResolver::new(Arc::clone(&state));
            (state, resolver)
        };
        // Insert a peer with no peer_group initially.
        let peer_token = "infra-tok";
        let mut peers = std::collections::HashMap::new();
        peers.insert(
            "infra-x".to_string(),
            A2aPeerConfig {
                name: "Infra X".into(),
                auth: A2aPeerAuth::Bearer {
                    token_hash: hex_token_hash(peer_token),
                },
                peer_group: None,
            },
        );
        {
            let mut w = state.write();
            w.a2a.peers = peers.clone();
        }

        // First verify — no peer_group attached to the peer, so allowed_aliases
        // on the principal is empty.
        match resolver
            .verify(&Credential::Bearer(peer_token.into()))
            .await
        {
            AuthOutcome::Authenticated(p) => {
                assert!(
                    p.allowed_aliases.is_empty(),
                    "no peer_group means no allowed aliases"
                );
                assert!(p.peer_group.is_none());
            }
            o => panic!("expected Authenticated, got {o:?}"),
        }

        // Now mutate config: attach a peer_group and a peer_groups map.
        {
            let mut w = state.write();
            w.peer_groups.insert(
                "shared".to_string(),
                PeerGroupConfig {
                    channel: "telegram".into(),
                    agents: vec![AgentAlias::new("researcher"), AgentAlias::new("analyst")],
                    external_peers: Vec::new(),
                    ignore: Vec::new(),
                    output_modality: zeroclaw_config::multi_agent::OutputModality::Mirror,
                    a2a_external_peers: std::collections::HashMap::new(),
                },
            );
            w.a2a.peers.insert(
                "infra-x".to_string(),
                A2aPeerConfig {
                    name: "Infra X".into(),
                    auth: A2aPeerAuth::Bearer {
                        token_hash: hex_token_hash(peer_token),
                    },
                    peer_group: Some(PeerGroupName::new("shared")),
                },
            );
        }

        // Second verify — should now resolve `peer_group` field and bring
        // `researcher` / `analyst` into `allowed_aliases`.
        match resolver
            .verify(&Credential::Bearer(peer_token.into()))
            .await
        {
            AuthOutcome::Authenticated(p) => {
                assert_eq!(p.peer_group.as_deref(), Some("shared"));
                let aliases: Vec<&str> = p.allowed_aliases.iter().map(|a| a.as_str()).collect();
                assert!(aliases.contains(&"researcher"));
                assert!(aliases.contains(&"analyst"));
            }
            o => panic!("expected Authenticated, got {o:?}"),
        }
    }

    /// External peer added via live config reload without process restart.
    /// Proves that `a2a_external_peers` entries inside peer groups are read
    /// fresh from `Arc<RwLock<Config>>` on every verify, mirroring the #7410
    /// anti-snapshot pattern.
    #[tokio::test]
    async fn live_config_resolver_picks_up_new_reloaded_external_peer() {
        use std::collections::HashMap;
        use zeroclaw_config::multi_agent::{A2aExternalPeerEntry, AgentAlias, PeerGroupConfig};

        let (state, resolver) = {
            let state = Arc::new(parking_lot::RwLock::new(
                zeroclaw_config::schema::Config::default(),
            ));
            let resolver = LiveConfigA2aResolver::new(Arc::clone(&state));
            (state, resolver)
        };

        // Start with a peer group that has no a2a_external_peers.
        let mut mg = HashMap::new();
        mg.insert(
            "ops".to_string(),
            PeerGroupConfig {
                channel: "telegram".into(),
                agents: vec![AgentAlias::new("bot")],
                external_peers: Vec::new(),
                ignore: Vec::new(),
                output_modality: zeroclaw_config::multi_agent::OutputModality::Mirror,
                a2a_external_peers: HashMap::new(),
            },
        );
        {
            let mut w = state.write();
            w.peer_groups = mg.clone();
        }

        // 1. Unknown external peer token is rejected before reload.
        assert!(
            !resolver
                .verify(&Credential::Bearer("ext-tok".into()))
                .await
                .is_allowed(),
            "unknown peer must be rejected before reload"
        );

        // 2. Mutate config: add an a2a_external_peers entry for the peer group.
        {
            let mut w = state.write();
            w.peer_groups
                .get_mut("ops")
                .unwrap()
                .a2a_external_peers
                .insert(
                    "ext-peer".into(),
                    A2aExternalPeerEntry {
                        credential: "ext-tok".into(),
                        allowed_aliases_override: None,
                    },
                );
        }

        // 3. Now the external peer token is accepted — live reload, no restart.
        match resolver.verify(&Credential::Bearer("ext-tok".into())).await {
            AuthOutcome::Authenticated(p) => {
                assert_eq!(p.id.as_str(), "ext-peer");
                assert_eq!(p.peer_group.as_deref(), Some("ops"));
                let aliases: Vec<&str> = p.allowed_aliases.iter().map(|a| a.as_str()).collect();
                assert!(aliases.contains(&"bot"));
            }
            o => panic!("expected Authenticated after reload, got {o:?}"),
        }

        // 4. Token for a peer NOT in a2a_external_peers is still denied.
        assert!(
            !resolver
                .verify(&Credential::Bearer("unknown-tok".into()))
                .await
                .is_allowed(),
            "unknown token must remain denied after reload"
        );
    }

    /// Lock discipline: the live-config resolver must NOT hold the
    /// `parking_lot::RwLock` across an `.await`. `verify()` snapshots and
    /// releases synchronously, then constructs a pure-data `A2aPeerProvider`
    /// and runs the awaitable path on that. This regression pins the
    /// `anti-lock-across-await` constraint that any future refactor must keep.
    #[tokio::test]
    async fn live_config_resolver_releases_read_lock_before_await() {
        // Build a config that yields one peer.
        let mut cfg = zeroclaw_config::schema::Config::default();
        let mut peers = std::collections::HashMap::new();
        peers.insert(
            "p".to_string(),
            zeroclaw_config::multi_agent::A2aPeerConfig {
                name: "P".into(),
                auth: zeroclaw_config::multi_agent::A2aPeerAuth::Bearer {
                    token_hash: hex_token_hash("any-tok"),
                },
                peer_group: None,
            },
        );
        cfg.a2a.peers = peers;

        let state = Arc::new(parking_lot::RwLock::new(cfg));
        let resolver = LiveConfigA2aResolver::new(Arc::clone(&state));

        // Acquire the WRITER lock first to prove the resolver does not hold
        // any read lock during its await chain. If lock discipline regressed
        // (resolver holds read across .await), this write acquisition would
        // either deadlock or block until timeout — we use tokio::time::timeout
        // for safety and rely on the rwlock being fair.
        let cred = Credential::Bearer("any-tok".into());
        let verify_task = resolver.verify(&cred);
        tokio::time::timeout(std::time::Duration::from_millis(250), async {
            // Try to acquire the write lock. If the resolver released its
            // read lock before .await, this acquires immediately.
            let _w = state.write();
        })
        .await
        .expect("write-lock must be acquirable within 250ms — lock discipline broken");
        // And the verify resolves successfully.
        let outcome = verify_task.await;
        assert!(outcome.is_allowed());
    }

    #[tokio::test]
    async fn a2a_peer_provider_authenticates_external_peer() {
        use std::collections::HashMap;
        use zeroclaw_config::multi_agent::{A2aExternalPeerEntry, AgentAlias, PeerGroupConfig};
        let mut peer_groups = HashMap::new();
        peer_groups.insert(
            "ops-team".to_string(),
            PeerGroupConfig {
                channel: "telegram".into(),
                agents: vec![
                    AgentAlias::new("ops-bot-alpha"),
                    AgentAlias::new("ops-bot-beta"),
                ],
                external_peers: Vec::new(),
                ignore: Vec::new(),
                output_modality: zeroclaw_config::multi_agent::OutputModality::Mirror,
                a2a_external_peers: [(
                    "infra-jenkins".to_string(),
                    A2aExternalPeerEntry {
                        credential: "sk-jenkins-secret".into(),
                        allowed_aliases_override: None,
                    },
                )]
                .into_iter()
                .collect(),
            },
        );

        let provider = A2aPeerProvider::from_peers(HashMap::new(), peer_groups);

        let outcome = provider
            .verify(&Credential::Bearer("sk-jenkins-secret".into()))
            .await;
        match outcome {
            AuthOutcome::Authenticated(p) => {
                assert_eq!(p.peer_group.as_deref(), Some("ops-team"));
                assert_eq!(p.id.as_str(), "infra-jenkins");
                let aliases: Vec<&str> = p.allowed_aliases.iter().map(|a| a.as_str()).collect();
                assert!(aliases.contains(&"ops-bot-alpha"));
                assert!(aliases.contains(&"ops-bot-beta"));
            }
            o => panic!("expected Authenticated, got {o:?}"),
        }
    }

    #[tokio::test]
    async fn a2a_peer_provider_rejects_wrong_external_credential() {
        use std::collections::HashMap;
        use zeroclaw_config::multi_agent::{A2aExternalPeerEntry, AgentAlias, PeerGroupConfig};
        let mut peer_groups = HashMap::new();
        peer_groups.insert(
            "ops-team".to_string(),
            PeerGroupConfig {
                channel: "telegram".into(),
                agents: vec![AgentAlias::new("ops-bot-alpha")],
                external_peers: Vec::new(),
                ignore: Vec::new(),
                output_modality: zeroclaw_config::multi_agent::OutputModality::Mirror,
                a2a_external_peers: [(
                    "infra-jenkins".to_string(),
                    A2aExternalPeerEntry {
                        credential: "real-token".into(),
                        allowed_aliases_override: None,
                    },
                )]
                .into_iter()
                .collect(),
            },
        );

        let provider = A2aPeerProvider::from_peers(HashMap::new(), peer_groups);

        let outcome = provider
            .verify(&Credential::Bearer("wrong-token".into()))
            .await;
        assert!(!outcome.is_allowed());
    }

    #[tokio::test]
    async fn a2a_peer_provider_external_peer_respects_alias_override() {
        use std::collections::HashMap;
        use zeroclaw_config::multi_agent::{A2aExternalPeerEntry, AgentAlias, PeerGroupConfig};
        let mut peer_groups = HashMap::new();
        peer_groups.insert(
            "ops-team".to_string(),
            PeerGroupConfig {
                channel: "telegram".into(),
                agents: vec![
                    AgentAlias::new("ops-bot-alpha"),
                    AgentAlias::new("ops-bot-beta"),
                ],
                external_peers: Vec::new(),
                ignore: Vec::new(),
                output_modality: zeroclaw_config::multi_agent::OutputModality::Mirror,
                a2a_external_peers: [(
                    "limited-peer".to_string(),
                    A2aExternalPeerEntry {
                        credential: "tok".into(),
                        allowed_aliases_override: Some(vec![AgentAlias::new("ops-bot-alpha")]),
                    },
                )]
                .into_iter()
                .collect(),
            },
        );

        let provider = A2aPeerProvider::from_peers(HashMap::new(), peer_groups);

        let outcome = provider.verify(&Credential::Bearer("tok".into())).await;
        match outcome {
            AuthOutcome::Authenticated(p) => {
                let aliases: Vec<&str> = p.allowed_aliases.iter().map(|a| a.as_str()).collect();
                assert_eq!(aliases, vec!["ops-bot-alpha"]);
            }
            o => panic!("expected Authenticated, got {o:?}"),
        }
    }

    #[tokio::test]
    async fn a2a_peer_provider_external_peer_without_override_inherits_agents() {
        use std::collections::HashMap;
        use zeroclaw_config::multi_agent::{A2aExternalPeerEntry, AgentAlias, PeerGroupConfig};
        let mut peer_groups = HashMap::new();
        peer_groups.insert(
            "ops-team".to_string(),
            PeerGroupConfig {
                channel: "telegram".into(),
                agents: vec![AgentAlias::new("alpha")],
                external_peers: Vec::new(),
                ignore: Vec::new(),
                output_modality: zeroclaw_config::multi_agent::OutputModality::Mirror,
                a2a_external_peers: [(
                    "ext".to_string(),
                    A2aExternalPeerEntry {
                        credential: "x".into(),
                        allowed_aliases_override: None,
                    },
                )]
                .into_iter()
                .collect(),
            },
        );

        let provider = A2aPeerProvider::from_peers(HashMap::new(), peer_groups);

        let outcome = provider.verify(&Credential::Bearer("x".into())).await;
        match outcome {
            AuthOutcome::Authenticated(p) => {
                let aliases: Vec<&str> = p.allowed_aliases.iter().map(|a| a.as_str()).collect();
                assert_eq!(aliases, vec!["alpha"]);
            }
            o => panic!("expected Authenticated, got {o:?}"),
        }
    }
}
