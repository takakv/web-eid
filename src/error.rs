/// An error from a Web eID operation.
#[derive(Debug, thiserror::Error)]
pub enum WebEidError {
    /// The origin is not `https://host[:port]` without a trailing slash.
    #[error("invalid origin {0:?}: expected https://host[:port] without a trailing slash")]
    InvalidOrigin(String),

    /// An ID card operation failed.
    #[error(transparent)]
    Card(#[from] esteid_cryptoki::EstEidError),

    /// A PKCS#11 key operation failed.
    #[error(transparent)]
    Token(#[from] tokenkey::TokenkeyError),

    /// Serializing the authentication token failed.
    #[error("failed to serialize the authentication token: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, WebEidError>;
