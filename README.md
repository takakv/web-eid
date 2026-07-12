# web-eid

[Web eID] client for authentication and signing with Estonian ID cards.

ID card support is provided by [esteid-cryptoki] which requires the [OpenSC] PKCS#11 module.

[Web eID]: https://github.com/web-eid/web-eid-system-architecture-doc
[esteid-cryptoki]: https://crates.io/crates/esteid-cryptoki
[OpenSC]: https://github.com/OpenSC/OpenSC

## Authentication

Produce a [Web eID authentication token] for a server-issued challenge nonce:

```rust
let card = web_eid::IdCard::find()?;
let token = web_eid::authenticate(
    &card,
    "https://ria.ee",
    challenge_nonce,
    pin1,
)?;
let json = token.to_json()?;
```

[Web eID authentication token]: https://web-eid.github.io/web-eid-system-architecture-doc/web-eid-auth-token-v2-format-spec.pdf

## Signing

Create a digital signature with the signing key:

```rust
let hash = web_eid::recommended_hash(&card)?;
let signature = web_eid::sign(&card, hash, data_to_be_signed, pin2)?;
```

ECDSA signatures are returned as the raw `r || s` concatenation as produced by the card.
To verify a signature e.g. with OpenSSL it must be encoded into an [RFC 3279] `Ecdsa-Sig-Value`.

[RFC 3279]: https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.3

## License

Apache-2.0.
