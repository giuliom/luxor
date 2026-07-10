use crate::{
    auth::{hash_refresh_token, rotate_refresh_token, AuthUser},
    db,
    error::{ApiJson, AppError},
    models::PublicUser,
    services,
    state::AppState,
};
use axum::{extract::State, http::StatusCode, Json};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::{Deserialize, Serialize};
use time::Duration;

const REFRESH_COOKIE: &str = "luxor_refresh";
const REFRESH_COOKIE_PATH: &str = "/api/auth";

#[derive(Deserialize)]
pub struct CredentialsRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    user: PublicUser,
}

pub async fn register(
    State(state): State<AppState>,
    jar: CookieJar,
    ApiJson(request): ApiJson<CredentialsRequest>,
) -> Result<(StatusCode, CookieJar, Json<AuthResponse>), AppError> {
    let (user, grant) = services::auth::register(
        &state.db,
        &request.email,
        request.password,
        state.config.refresh_token_ttl_seconds,
    )
    .await?;
    let access_token = state.jwt.issue(user.id)?;
    let jar = jar.add(refresh_cookie(&state, grant.token));
    Ok((
        StatusCode::CREATED,
        jar,
        Json(auth_response(&state, access_token, user.into())),
    ))
}

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    ApiJson(request): ApiJson<CredentialsRequest>,
) -> Result<(CookieJar, Json<AuthResponse>), AppError> {
    let (user, grant) = services::auth::login(
        &state.db,
        &request.email,
        request.password,
        state.config.refresh_token_ttl_seconds,
    )
    .await?;
    let access_token = state.jwt.issue(user.id)?;
    let jar = jar.add(refresh_cookie(&state, grant.token));
    Ok((jar, Json(auth_response(&state, access_token, user.into()))))
}

pub async fn refresh(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, Json<AuthResponse>), AppError> {
    let presented_token = jar
        .get(REFRESH_COOKIE)
        .map(Cookie::value)
        .ok_or(AppError::Unauthorized)?;
    let grant = rotate_refresh_token(
        &state.db,
        presented_token,
        state.config.refresh_token_ttl_seconds,
    )
    .await?;
    let user = db::user_by_id(&state.db, grant.user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let access_token = state.jwt.issue(user.id)?;
    let jar = jar.add(refresh_cookie(&state, grant.token));
    Ok((jar, Json(auth_response(&state, access_token, user.into()))))
}

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(StatusCode, CookieJar), AppError> {
    if let Some(cookie) = jar.get(REFRESH_COOKIE) {
        db::revoke_session(&state.db, &hash_refresh_token(cookie.value())).await?;
    }
    Ok((
        StatusCode::NO_CONTENT,
        jar.remove(expired_refresh_cookie(&state)),
    ))
}

pub async fn me(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<PublicUser>, AppError> {
    db::user_by_id(&state.db, auth.id)
        .await?
        .map(PublicUser::from)
        .map(Json)
        .ok_or(AppError::Unauthorized)
}

fn auth_response(state: &AppState, access_token: String, user: PublicUser) -> AuthResponse {
    AuthResponse {
        access_token,
        token_type: "Bearer",
        expires_in: state.config.access_token_ttl_seconds,
        user,
    }
}

fn refresh_cookie(state: &AppState, token: String) -> Cookie<'static> {
    Cookie::build((REFRESH_COOKIE, token))
        .path(REFRESH_COOKIE_PATH)
        .http_only(true)
        .secure(state.config.refresh_cookie_secure)
        .same_site(SameSite::Strict)
        .max_age(Duration::seconds(state.config.refresh_token_ttl_seconds))
        .build()
}

fn expired_refresh_cookie(state: &AppState) -> Cookie<'static> {
    Cookie::build((REFRESH_COOKIE, ""))
        .path(REFRESH_COOKIE_PATH)
        .http_only(true)
        .secure(state.config.refresh_cookie_secure)
        .same_site(SameSite::Strict)
        .max_age(Duration::ZERO)
        .build()
}
