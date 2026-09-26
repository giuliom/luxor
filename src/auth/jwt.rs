use crate::{access::Role, config::Config, error::AppError, state::AppState};
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header, request::Parts},
};
use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone)]
pub struct JwtService {
    secret: SecretString,
    lifetime_seconds: i64,
    issuer: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Claims {
    pub sub: Uuid,
    pub role: Role,
    pub iat: i64,
    pub exp: i64,
    pub iss: String,
}

impl JwtService {
    pub fn from_config(config: &Config) -> Self {
        Self::new(
            config.auth.jwt_secret.clone(),
            config.auth.access_token_ttl_seconds,
            config.auth.jwt_issuer.clone(),
        )
    }

    pub fn new(secret: SecretString, lifetime_seconds: i64, issuer: String) -> Self {
        Self {
            secret,
            lifetime_seconds,
            issuer,
        }
    }

    pub fn issue(&self, user_id: Uuid, role: Role) -> Result<String, AppError> {
        let now = Utc::now().timestamp();
        let claims = Claims {
            sub: user_id,
            role,
            iat: now,
            exp: now + self.lifetime_seconds,
            iss: self.issuer.clone(),
        };
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(self.secret.expose_secret().as_bytes()),
        )
        .map_err(|_| AppError::Authentication)
    }

    pub fn verify(&self, token: &str) -> Result<Claims, AppError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.issuer]);
        validation.leeway = 0;
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.expose_secret().as_bytes()),
            &validation,
        )
        .map(|data| data.claims)
        .map_err(|_| AppError::Unauthorized)
    }
}

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub id: Uuid,
    pub role: Role,
}

/// Authenticates a request by its bearer access token. Works with any router
/// state that exposes the foundation's [`AppState`].
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let value = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(AppError::Unauthorized)?;
        // RFC 7235 makes the authentication scheme case-insensitive.
        let token = value
            .split_once(' ')
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
            .map(|(_, token)| token.trim())
            .filter(|token| !token.is_empty())
            .ok_or(AppError::Unauthorized)?;
        let claims = AppState::from_ref(state).jwt.verify(token)?;
        Ok(Self {
            id: claims.sub,
            role: claims.role,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread, time::Duration};

    const ISSUER: &str = "test-issuer";

    fn service(lifetime_seconds: i64) -> JwtService {
        JwtService::new(
            SecretString::from("a-test-secret-with-at-least-32-characters".to_owned()),
            lifetime_seconds,
            ISSUER.to_owned(),
        )
    }

    #[test]
    fn issues_and_verifies_access_tokens() {
        let user_id = Uuid::new_v4();
        let token = service(60).issue(user_id, Role::Admin).unwrap();
        let claims = service(60).verify(&token).unwrap();
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.role, Role::Admin);
    }

    #[test]
    fn rejects_expired_access_tokens() {
        let token = service(-1).issue(Uuid::new_v4(), Role::User).unwrap();
        thread::sleep(Duration::from_millis(10));
        assert!(matches!(
            service(60).verify(&token),
            Err(AppError::Unauthorized)
        ));
    }

    // Tokens minted before roles existed carry no role claim; they must fail
    // verification so the client falls back to the refresh flow for a
    // role-bearing token.
    #[test]
    fn rejects_tokens_without_a_role_claim() {
        #[derive(Serialize)]
        struct LegacyClaims {
            sub: Uuid,
            iat: i64,
            exp: i64,
            iss: String,
        }
        let now = Utc::now().timestamp();
        let legacy = LegacyClaims {
            sub: Uuid::new_v4(),
            iat: now,
            exp: now + 60,
            iss: ISSUER.into(),
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &legacy,
            &EncodingKey::from_secret(b"a-test-secret-with-at-least-32-characters"),
        )
        .unwrap();
        assert!(matches!(
            service(60).verify(&token),
            Err(AppError::Unauthorized)
        ));
    }

    /// Two applications sharing a signing secret must still not accept each
    /// other's tokens.
    #[test]
    fn rejects_tokens_issued_by_another_application() {
        let other = JwtService::new(
            SecretString::from("a-test-secret-with-at-least-32-characters".to_owned()),
            60,
            "another-application".to_owned(),
        );
        let token = other.issue(Uuid::new_v4(), Role::User).unwrap();
        assert!(matches!(
            service(60).verify(&token),
            Err(AppError::Unauthorized)
        ));
    }
}
