//! Application error type. Handlers return `Result<_, AppError>`; the
//! response carries an [`ErrorPage`] marker that the `error_pages`
//! middleware turns into a themed HTML page.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::storage::StorageError;

#[derive(Debug)]
pub enum AppError {
    NotFound,
    /// 404 with a specific explanation.
    NotFoundMsg(String),
    BadRequest(String),
    Forbidden(String),
    PayloadTooLarge(String),
    NotImplemented(String),
    /// 429 with Retry-After: 60.
    TooManyRequests(String),
    ServiceUnavailable(String),
    /// Details are logged; the visitor sees a generic message.
    Internal(String),
}

/// Response extension read by the error-page middleware.
#[derive(Clone, Debug)]
pub struct ErrorPage {
    pub status: StatusCode,
    pub message: String,
}

impl AppError {
    pub fn internal(e: impl std::fmt::Display) -> Self {
        AppError::Internal(e.to_string())
    }

    fn status_and_message(&self) -> (StatusCode, String) {
        match self {
            AppError::NotFound => (
                StatusCode::NOT_FOUND,
                "The page you asked for does not exist.".into(),
            ),
            AppError::NotFoundMsg(m) => (StatusCode::NOT_FOUND, m.clone()),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            AppError::Forbidden(m) => (StatusCode::FORBIDDEN, m.clone()),
            AppError::PayloadTooLarge(m) => (StatusCode::PAYLOAD_TOO_LARGE, m.clone()),
            AppError::NotImplemented(m) => (StatusCode::NOT_IMPLEMENTED, m.clone()),
            AppError::TooManyRequests(m) => (StatusCode::TOO_MANY_REQUESTS, m.clone()),
            AppError::ServiceUnavailable(m) => (StatusCode::SERVICE_UNAVAILABLE, m.clone()),
            AppError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong on our side. Please try again later.".into(),
            ),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if let AppError::Internal(detail) = &self {
            tracing::error!(error = %detail, "internal error");
        }
        let (status, message) = self.status_and_message();
        let mut resp = (status, message.clone()).into_response();
        if status == StatusCode::TOO_MANY_REQUESTS {
            resp.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                axum::http::HeaderValue::from_static("60"),
            );
        }
        resp.extensions_mut().insert(ErrorPage { status, message });
        resp
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::Internal(format!("database: {e}"))
    }
}

impl From<askama::Error> for AppError {
    fn from(e: askama::Error) -> Self {
        AppError::Internal(format!("template: {e}"))
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Internal(format!("io: {e}"))
    }
}

impl From<StorageError> for AppError {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::NotFound => {
                tracing::error!("stored object missing for a file row");
                AppError::NotFound
            }
            StorageError::NotImplemented(m) => AppError::NotImplemented(m.into()),
            other => AppError::Internal(format!("storage: {other}")),
        }
    }
}
