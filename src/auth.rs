use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use esteid_cryptoki::IdCard;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};
use tokenkey::{EcCurve, Hash, KeyAlgorithm, SignScheme};

use crate::error::{Result, WebEidError};

/// The Web eID authentication token format identifier.
pub const TOKEN_FORMAT: &str = "web-eid:1.0";

/// A Web eID authentication token.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthToken {
    /// Base64-encoded DER of the user's authentication certificate.
    pub unverified_certificate: String,
    /// The signature algorithm.
    pub algorithm: String,
    /// Base64-encoded signature of the token.
    pub signature: String,
    /// The type identifier and version of the token format.
    pub format: String,
    /// URL identifying the application that issued the token.
    pub app_version: String,
}

impl AuthToken {
    /// The token in its JSON wire format.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

/// Authenticate with the ID card: sign the origin and challenge nonce with
/// the authentication key (PIN1) and produce a Web eID authentication token.
///
/// `origin` is the
/// [ASCII serialization of the website origin](https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin)
/// of the relying party.
///
/// The signed data is `hash(origin) || hash(challenge_nonce)`.
pub fn authenticate(
    card: &IdCard,
    origin: &str,
    challenge_nonce: &[u8],
    pin1: &str,
) -> Result<AuthToken> {
    validate_origin(origin)?;

    let KeyAlgorithm::Ec(curve) = card.auth.algorithm()?;
    let (hash, algorithm) = curve_parameters(curve);

    let mut data_to_sign = digest(hash, origin.as_bytes());
    data_to_sign.extend_from_slice(&digest(hash, challenge_nonce));

    let key = card.open_auth(pin1)?;
    let signature = key.sign(SignScheme::Ecdsa(hash), &data_to_sign)?;

    Ok(AuthToken {
        unverified_certificate: BASE64.encode(card.auth_certificate_der()),
        algorithm: algorithm.to_string(),
        signature: BASE64.encode(signature),
        format: TOKEN_FORMAT.to_string(),
        app_version: app_version(),
    })
}

fn curve_parameters(curve: EcCurve) -> (Hash, &'static str) {
    match curve {
        EcCurve::P256 => (Hash::Sha256, "ES256"),
        EcCurve::P384 => (Hash::Sha384, "ES384"),
        EcCurve::P521 => (Hash::Sha512, "ES512"),
    }
}

fn digest(hash: Hash, data: &[u8]) -> Vec<u8> {
    match hash {
        Hash::Sha256 => Sha256::digest(data).to_vec(),
        Hash::Sha384 => Sha384::digest(data).to_vec(),
        Hash::Sha512 => Sha512::digest(data).to_vec(),
    }
}

fn app_version() -> String {
    format!(
        "https://github.com/takakv/web-eid/releases/{}",
        env!("CARGO_PKG_VERSION")
    )
}

fn validate_origin(origin: &str) -> Result<()> {
    let host = origin
        .strip_prefix("https://")
        .ok_or_else(|| WebEidError::InvalidOrigin(origin.to_string()))?;
    if host.is_empty() || host.contains('/') {
        return Err(WebEidError::InvalidOrigin(origin.to_string()));
    }
    Ok(())
}
