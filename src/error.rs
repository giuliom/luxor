use axum::{
    extract::{rejection::JsonRejection, FromRequest, Request},
    http::{header, HeaderValue, StatusCode},
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
    #[error("the {0} permission is required")]
    MissingPermission(&'static str),
    #[error("{0}")]
    BadRequest(String),
    #[error("request body is too large")]
    PayloadTooLarge,
    #[error("request body must be encoded as application/json")]
    UnsupportedMediaType,
    #[error("this endpoint is only available over https")]
    HttpsRequired,
    #[error("too many requests; retry after {retry_after_seconds} seconds")]
    RateLimited { retry_after_seconds: u64 },
    #[error("the request took too long to process")]
    RequestTimeout,
    #[error("{0} is at capacity; try again shortly")]
    AtCapacity(&'static str),
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
    #[error("event stream operation failed")]
    EventStream(#[from] rdkafka::error::KafkaError),
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
            Self::Forbidden | Self::MissingPermission(_) => StatusCode::FORBIDDEN,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            // Not a redirect: a request that already carried credentials over
            // plaintext cannot be made safe by retrying it elsewhere.
            Self::HttpsRequired => StatusCode::FORBIDDEN,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
            // A resource limit this instance is already up against, not a
            // fault in the request: the same call succeeds once one of the
            // held resources is released.
            Self::AtCapacity(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Database(_)
            | Self::Cache(_)
            | Self::EventStream(_)
            | Self::Serialization(_)
            | Self::Authentication
            | Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::Forbidden | Self::MissingPermission(_) => "forbidden",
            Self::BadRequest(_) => "bad_request",
            Self::PayloadTooLarge => "payload_too_large",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::HttpsRequired => "https_required",
            Self::RateLimited { .. } => "rate_limited",
            Self::RequestTimeout => "request_timeout",
            Self::AtCapacity(_) => "at_capacity",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::NotFound(_) => "not_found",
            Self::Conflict(_) => "conflict",
            Self::Database(_)
            | Self::Cache(_)
            | Self::EventStream(_)
            | Self::Serialization(_)
            | Self::Authentication
            | Self::Internal => "internal_error",
        }
    }

    fn public_message(&self) -> String {
        match self {
            Self::Database(_)
            | Self::Cache(_)
            | Self::EventStream(_)
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

/// Turns a body that could not be read into the error contract.
///
/// axum's own description quotes the offending input back — an unknown enum
/// variant, a mistyped value — and names the target type's fields. That is
/// worth having while developing, so it is logged; it is not returned, because
/// a response that echoes a request body reflects caller-controlled text to
/// whoever reads it and describes the internal shape to whoever probes it.
/// What the client gets instead names the class of problem, which is enough to
/// tell a malformed body from one this endpoint simply does not accept.
fn map_json_rejection(rejection: JsonRejection) -> AppError {
    tracing::debug!(detail = %rejection.body_text(), "rejected a JSON request body");
    match rejection {
        JsonRejection::JsonSyntaxError(_) => {
            AppError::BadRequest("request body is not valid JSON".into())
        }
        JsonRejection::JsonDataError(_) => AppError::BadRequest(
            "request body does not match the schema this endpoint accepts".into(),
        ),
        JsonRejection::MissingJsonContentType(_) => AppError::UnsupportedMediaType,
        // Reading the body itself failed, which past the body limit is the
        // shape an oversized request arrives in.
        _ => match rejection.status() {
            StatusCode::PAYLOAD_TOO_LARGE => AppError::PayloadTooLarge,
            _ => AppError::BadRequest("request body could not be read".into()),
        },
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        if status.is_server_error() {
            tracing::error!(error = ?self, "request failed");
            sentry::capture_error(&self);
        }
        let retry_after_seconds = match &self {
            Self::RateLimited {
                retry_after_seconds,
            } => Some(*retry_after_seconds),
            _ => None,
        };
        let mut response = (
            status,
            Json(ApiErrorResponse {
                error: ApiErrorBody {
                    code: self.code(),
                    message: self.public_message(),
                },
            }),
        )
            .into_response();
        if let Some(seconds) = retry_after_seconds {
            response.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from_str(&seconds.to_string())
                    .expect("decimal digits are a valid header value"),
            );
        }
        response
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

    /// Infrastructure failures answer alike and say nothing about the
    /// infrastructure: a broker address or a topic name in an error body tells
    /// a caller about the deployment's internals.
    #[tokio::test]
    async fn event_stream_failures_answer_as_internal_errors() {
        let response = AppError::EventStream(rdkafka::error::KafkaError::MessageProduction(
            rdkafka::error::RDKafkaErrorCode::UnknownTopicOrPartition,
        ))
        .into_response();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            String::from_utf8(bytes.to_vec()).unwrap(),
            r#"{"error":{"code":"internal_error","message":"an internal error occurred"}}"#
        );
    }

    #[tokio::test]
    async fn rate_limited_responses_advertise_the_retry_delay() {
        let response = AppError::RateLimited {
            retry_after_seconds: 9,
        }
        .into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "9");
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains(r#""code":"rate_limited""#));
        assert!(body.contains("retry after 9 seconds"));
    }
}
