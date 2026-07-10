use crate::error::AppError;
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OAuthIdentity {
    pub provider: String,
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
}

#[async_trait]
pub trait OAuthProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn authorization_url(&self, state: &str, pkce_challenge: &str) -> Result<String, AppError>;
    async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: &str,
    ) -> Result<OAuthIdentity, AppError>;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OAuthState {
    pub state: String,
    pub pkce_verifier: String,
}

impl OAuthState {
    pub fn generate() -> Self {
        Self {
            state: random_urlsafe(32),
            pkce_verifier: random_urlsafe(48),
        }
    }

    pub fn matches(&self, returned_state: &str) -> bool {
        constant_time_eq(self.state.as_bytes(), returned_state.as_bytes())
    }
}

fn random_urlsafe(size: usize) -> String {
    let mut bytes = vec![0_u8; size];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_state_is_random_and_comparable() {
        let state = OAuthState::generate();
        assert!(state.matches(&state.state));
        assert!(!state.matches("different"));
        assert_ne!(state.state, OAuthState::generate().state);
    }
}
