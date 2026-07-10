use axum::{
    extract::{rejection::JsonRejection, FromRequest, Request},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("authentication is required")]
    Unauthorized,
    #[error("access is forbidden")]
    Forbidden,
    #[error("{0}")]
    BadRequest(String),
    #[error("request body is too large")]
    PayloadTooLarge,
    #[error("method not allowed for this route")]
    MethodNotAllowed,
    #[error("{0} was not found")]
    NotFound(&'static str),
    #[error("{0} already exists")]
    Conflict(&'static str),
    #[error("database operation failed")]
    Database(#[from] sqlx::Error),
    #[error("cache operation failed")]
    Cache(#[from] redis::RedisError),
    #[error("serialization failed")]
    Serialization(#[from] serde_json::Error),
    #[error("authentication operation failed")]
    Authentication,
    #[error("internal server error")]
    Internal,
}

#[derive(Debug, Serialize)]
pub struct ApiErrorResponse {
    pub error: ApiErrorBody,
}

#[derive(Debug, Serialize)]
pub struct ApiErrorBody {
    pub code: &'static str,
    pub message: String,
}

impl AppError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Database(_)
            | Self::Cache(_)
            | Self::Serialization(_)
            | Self::Authentication
            | Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::BadRequest(_) => "bad_request",
            Self::PayloadTooLarge => "payload_too_large",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::NotFound(_) => "not_found",
            Self::Conflict(_) => "conflict",
            Self::Database(_)
            | Self::Cache(_)
            | Self::Serialization(_)
            | Self::Authentication
            | Self::Internal => "internal_error",
        }
    }

    fn public_message(&self) -> String {
        match self {
            Self::Database(_)
            | Self::Cache(_)
            | Self::Serialization(_)
            | Self::Authentication
            | Self::Internal => "an internal error occurred".into(),
            _ => self.to_string(),
        }
    }
}

pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned,
{
    type Rejection = AppError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(map_json_rejection)
    }
}

fn map_json_rejection(rejection: JsonRejection) -> AppError {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        AppError::PayloadTooLarge
    } else {
        AppError::BadRequest("request body must contain valid JSON".into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        if status.is_server_error() {
            tracing::error!(error = ?self, "request failed");
            sentry::capture_error(&self);
        }
        (
            status,
            Json(ApiErrorResponse {
                error: ApiErrorBody {
                    code: self.code(),
                    message: self.public_message(),
                },
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn serializes_the_standard_error_contract() {
        let response = AppError::BadRequest("invalid email".into()).into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            String::from_utf8(bytes.to_vec()).unwrap(),
            r#"{"error":{"code":"bad_request","message":"invalid email"}}"#
        );
    }
}
