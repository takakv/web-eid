use esteid_cryptoki::IdCard;
use tokenkey::{EcCurve, Hash, KeyAlgorithm, SignScheme};

use crate::error::Result;

/// Sign `data` with the card's signing key (PIN2) for a qualified electronic
/// signature.
///
/// `data` is the raw data to be signed and is hashed with `hash` before signing.
/// The returned ECDSA signature is the raw `r || s` concatenation as produced by the card.
pub fn sign(card: &IdCard, hash: Hash, data: &[u8], pin2: &str) -> Result<Vec<u8>> {
    let key = card.open_signing(pin2)?;
    Ok(key.sign(SignScheme::Ecdsa(hash), data)?)
}

/// The hash matching the signing key's curve strength.
pub fn recommended_hash(card: &IdCard) -> Result<Hash> {
    let KeyAlgorithm::Ec(curve) = card.sign.algorithm()?;
    Ok(match curve {
        EcCurve::P256 => Hash::Sha256,
        EcCurve::P384 => Hash::Sha384,
        EcCurve::P521 => Hash::Sha512,
    })
}
