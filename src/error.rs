use thiserror::Error;

/// Errors that can occur when interacting with the EUVD API
#[derive(Debug, Error)]
pub enum EuvdError {
    /// HTTP transport error
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// Rate limit exceeded (429 response)
    #[error("rate limited")]
    RateLimited,

    /// Resource not found (404 response)
    #[error("not found: {0}")]
    NotFound(String),

    /// Failed to parse API response
    #[error("parse error: {0}")]
    Parse(String),

    /// API returned an error response
    #[error("API error: {status} {body}")]
    Api { status: u16, body: String },
}

/// Result type alias for EUVD operations
pub type Result<T> = std::result::Result<T, EuvdError>;
