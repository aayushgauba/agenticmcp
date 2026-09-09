use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// Private key material is intentionally neither serializable nor Debug/Clone.
pub struct KeyPair(SigningKey);

impl KeyPair {
    pub(crate) fn secret_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub(crate) fn from_secret(bytes: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(bytes))
    }

    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: B64.encode(self.0.verifying_key().as_bytes()),
        }
    }

    pub(crate) fn sign(&self, bytes: &[u8]) -> String {
        B64.encode(self.0.sign(bytes).to_bytes())
    }
}

/// The supported public JWK profile; private key fields are rejected on decode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicKey {
    pub kty: String,
    pub crv: String,
    pub x: String,
}

impl PublicKey {
    pub fn validate(&self) -> Result<()> {
        self.key().map(|_| ())
    }

    fn key(&self) -> Result<VerifyingKey> {
        if self.kty != "OKP" || self.crv != "Ed25519" {
            return Err(Error::Signature);
        }
        let bytes = B64.decode(&self.x).map_err(|_| Error::Signature)?;
        let key = VerifyingKey::from_bytes(&bytes.try_into().map_err(|_| Error::Signature)?)
            .map_err(|_| Error::Signature)?;
        if key.is_weak() {
            return Err(Error::Signature);
        }
        Ok(key)
    }

    pub(crate) fn verify(&self, bytes: &[u8], signature: &str) -> Result<()> {
        let signature = B64.decode(signature).map_err(|_| Error::Signature)?;
        let signature = Signature::from_slice(&signature).map_err(|_| Error::Signature)?;
        self.key()?
            .verify_strict(bytes, &signature)
            .map_err(|_| Error::Signature)
    }
}

pub(crate) fn id() -> String {
    let mut bytes = [0; 24];
    OsRng.fill_bytes(&mut bytes);
    B64.encode(bytes)
}

pub(crate) fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn canonical(value: &impl Serialize) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    validate_json(&value, 0)?;
    Ok(serde_json_canonicalizer::to_vec(&value)?)
}

fn validate_json(value: &serde_json::Value, depth: usize) -> Result<()> {
    if depth > 64 {
        return Err(Error::Invalid("JSON nesting too deep"));
    }
    match value {
        serde_json::Value::Number(n) => {
            // Avoid cross-language identity collisions caused by integer rounding.
            const MAX_SAFE: f64 = 9_007_199_254_740_991.0;
            if n.as_f64()
                .is_none_or(|f| !f.is_finite() || f.abs() > MAX_SAFE)
            {
                return Err(Error::Invalid(
                    "JSON number exceeds interoperable range; use a string",
                ));
            }
        }
        serde_json::Value::Array(values) => {
            for v in values {
                validate_json(v, depth + 1)?;
            }
        }
        serde_json::Value::Object(values) => {
            for v in values.values() {
                validate_json(v, depth + 1)?;
            }
        }
        _ => (),
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

pub(crate) fn encode<T: Serialize>(
    claims: &T,
    key: &KeyPair,
    typ: &str,
    kid: &str,
) -> Result<String> {
    let header = Header {
        alg: "EdDSA".into(),
        typ: typ.into(),
        kid: kid.into(),
    };
    let input = format!(
        "{}.{}",
        B64.encode(canonical(&header)?),
        B64.encode(canonical(claims)?)
    );
    Ok(format!("{input}.{}", key.sign(input.as_bytes())))
}

pub(crate) fn decode<T: DeserializeOwned>(
    token: &str,
    key: &PublicKey,
    typ: &str,
    kid: &str,
) -> Result<T> {
    if token.len() > 32_768 {
        return Err(Error::Invalid("JWT too large"));
    }
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::Signature);
    }
    let header: Header =
        serde_json::from_slice(&B64.decode(parts[0]).map_err(|_| Error::Signature)?)?;
    if header.alg != "EdDSA" || header.typ != typ || header.kid != kid {
        return Err(Error::Signature);
    }
    key.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), parts[2])?;
    Ok(serde_json::from_slice(
        &B64.decode(parts[1]).map_err(|_| Error::Signature)?,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn unhex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc8032_empty_message_vector() {
        // RFC 8032 §7.1 test 1, independently published key/signature.
        let key = PublicKey {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: B64.encode(unhex(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            )),
        };
        let signature = B64.encode(unhex(concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )));
        key.verify(b"", &signature).unwrap();
        assert!(key.verify(b"modified", &signature).is_err());
    }

    #[test]
    fn canonical_json_uses_utf16_key_order_and_ecmascript_numbers() {
        let value = json!({"\u{e000}": 1, "\u{1f600}": 2, "n": -0.0, "f": 1.0e-7});
        assert_eq!(
            String::from_utf8(canonical(&value).unwrap()).unwrap(),
            "{\"f\":1e-7,\"n\":0,\"😀\":2,\"\u{e000}\":1}"
        );
    }

    #[test]
    fn ambiguous_large_numbers_are_rejected() {
        assert!(canonical(&json!({"n": 9_007_199_254_740_993_u64})).is_err());
        assert!(canonical(&json!({"n": "9007199254740993"})).is_ok());
    }

    #[test]
    fn signed_but_unsupported_jose_headers_are_rejected() {
        let key = KeyPair::generate();
        for header in [
            r#"{"alg":"none","typ":"test","kid":"key"}"#,
            r#"{"alg":"HS256","typ":"test","kid":"key"}"#,
            r#"{"alg":"EdDSA","typ":"other","kid":"key"}"#,
            r#"{"alg":"EdDSA","typ":"test","kid":"other"}"#,
            r#"{"alg":"EdDSA","typ":"test","kid":"key","crit":["custom"]}"#,
            r#"{"alg":"EdDSA","typ":"test","kid":"key","jku":"https://evil.example.com"}"#,
            r#"{"alg":"EdDSA","alg":"EdDSA","typ":"test","kid":"key"}"#,
        ] {
            let input = format!("{}.{}", B64.encode(header), B64.encode(b"{}"));
            let token = format!("{input}.{}", key.sign(input.as_bytes()));
            assert!(decode::<serde_json::Value>(&token, &key.public_key(), "test", "key").is_err());
        }
    }
}
