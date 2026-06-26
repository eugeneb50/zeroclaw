//! Native pairing bearer auth provider — bridges [`PairingGuard`] to the
//! [`AuthProvider`] trait so the gateway can use the unified `ProviderRegistry`.

use std::sync::Arc;

use async_trait::async_trait;
use zeroclaw_api::principal::{AuthMethod, AuthOutcome, DenyReason, Principal};

use crate::security::auth_provider::{AuthProvider, Credential};
use crate::security::pairing::PairingGuard;

/// An [`AuthProvider`] that verifies bearer tokens against the
/// [`PairingGuard`] and emits [`Principal::shared_operator`] on success.
///
/// This is the production bridge for the single-operator / trusted-local path.
/// OIDC, SSH-key, and peercred providers are added by their own scoped changes.
pub struct NativeAuthProvider {
    pairing: Arc<PairingGuard>,
}

impl NativeAuthProvider {
    #[must_use]
    pub fn new(pairing: Arc<PairingGuard>) -> Self {
        Self { pairing }
    }
}

#[async_trait]
impl AuthProvider for NativeAuthProvider {
    fn name(&self) -> &str {
        "native"
    }

    fn method(&self) -> AuthMethod {
        AuthMethod::Native
    }

    fn accepts(&self, credential: &Credential) -> bool {
        matches!(credential, Credential::Bearer(_))
    }

    async fn verify(&self, credential: &Credential) -> AuthOutcome {
        match credential {
            Credential::Bearer(token) => {
                if self.pairing.is_authenticated(token) {
                    AuthOutcome::Trusted(Principal::shared_operator())
                } else {
                    AuthOutcome::Denied {
                        reason: DenyReason::BadCredential,
                    }
                }
            }
            _ => AuthOutcome::Denied {
                reason: DenyReason::BadCredential,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroclaw_runtime::security::pairing::PairingGuard;

    #[tokio::test]
    async fn authenticates_valid_token() {
        let mut pairing = PairingGuard::new(false, &[]);
        pairing.try_pair("test-code", "127.0.0.1").await.unwrap();
        let tokens = pairing.paired_tokens();
        let token = tokens.first().unwrap().clone();

        let provider = NativeAuthProvider::new(Arc::new(pairing));
        let outcome = provider.verify(&Credential::Bearer(token)).await;

        assert!(outcome.is_allowed());
        assert_eq!(outcome.principal().unwrap().auth_method, AuthMethod::Native);
    }

    #[tokio::test]
    async fn rejects_invalid_token() {
        let pairing = PairingGuard::new(true, &["valid-token".to_string()]);
        let provider = NativeAuthProvider::new(Arc::new(pairing));
        let outcome = provider.verify(&Credential::Bearer("invalid".into())).await;

        assert!(!outcome.is_allowed());
        assert!(matches!(outcome, AuthOutcome::Denied { reason: DenyReason::BadCredential }));
    }
}