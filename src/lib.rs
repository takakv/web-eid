//! Web eID client library.

mod auth;
mod error;
mod sign;

pub use auth::{authenticate, AuthToken, TOKEN_FORMAT};
pub use error::{Result, WebEidError};
pub use sign::{recommended_hash, sign};

pub use esteid_cryptoki::{modules, EstEidError, IdCard};
pub use tokenkey::{EcCurve, Hash, KeyAlgorithm, TokenkeyError};
