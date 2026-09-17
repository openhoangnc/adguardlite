//! Error responses.
//!
//! Upstream answers failures with a plain-text body and the matching status
//! code, which is what the web UI shows the user verbatim.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// An API failure.
#[derive(Debug)]
pub struct ApiError {
    /// The status to answer with.
    pub status: StatusCode,
    /// The message shown to the user.
    pub message: String,
}

impl ApiError {
    /// A 400 with a message.
    pub fn bad_request(m: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: m.into(),
        }
    }

    /// A 401.
    pub fn unauthorized(m: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: m.into(),
        }
    }

    /// A 403.
    pub fn forbidden(m: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: m.into(),
        }
    }

    /// A 404.
    pub fn not_found(m: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: m.into(),
        }
    }

    /// A 500.
    pub fn internal(m: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: m.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, self.message).into_response()
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.status, self.message)
    }
}

impl std::error::Error for ApiError {}

/// The result type handlers return.
pub type ApiResult<T> = Result<T, ApiError>;
