use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer as _, Verifier as _},
};
use rand::{RngCore, rngs::OsRng};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{EncodePrivateKey, LineEnding},
    traits::PublicKeyParts,
};
use serde_json::json;
use std::collections::HashMap;

/// Local issuer key; no serialized private material or Debug output.
pub struct IssuerKey {
    encoding: EncodingKey,
    decoding: DecodingKey,
    pub kid: String,
    jwk: Value,
}
impl IssuerKey {
    pub fn generate() -> Result<Self> {
        let private = RsaPrivateKey::new(&mut OsRng, 2048).map_err(|_| Error::Credential)?;
        let public = RsaPublicKey::from(&private);
        let pem = private
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|_| Error::Credential)?;
        let kid = random_id();
        let jwk = json!({"kty":"RSA","use":"sig","alg":"RS256","kid":kid,
            "n":B64.encode(public.n().to_bytes_be()),"e":B64.encode(public.e().to_bytes_be())});
        let encoding = EncodingKey::from_rsa_pem(pem.as_bytes()).map_err(|_| Error::Credential)?;
        let decoding = DecodingKey::from_rsa_components(
            jwk["n"].as_str().unwrap_or(""),
            jwk["e"].as_str().unwrap_or(""),
        )
        .map_err(|_| Error::Credential)?;
        Ok(Self {
            encoding,
            decoding,
            kid,
            jwk,
        })
    }
    pub fn jwks(&self) -> Value {
        json!({"keys":[self.jwk]})
    }
    pub fn sign(&self, claims: &Value) -> Result<String> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(&header, claims, &self.encoding).map_err(|_| Error::Credential)
    }
    pub fn verify(&self, token: &str, issuer: &str, now: u64, skew: u64) -> Result<Value> {
        decode_token(token, &self.decoding, issuer, now, skew)
    }
}

pub fn random_id() -> String {
    let mut b = [0; 24];
    OsRng.fill_bytes(&mut b);
    B64.encode(b)
}

/// Per-process/session P-256 holder key, independent of the registered agent.
pub struct ProofKey(SigningKey);
impl Default for ProofKey {
    fn default() -> Self {
        Self::generate()
    }
}
impl ProofKey {
    pub fn generate() -> Self {
        Self(SigningKey::random(&mut OsRng))
    }
    pub fn public_jwk(&self) -> Value {
        let point = self.0.verifying_key().to_encoded_point(false);
        json!({"kty":"EC","crv":"P-256","x":B64.encode(point.x().expect("P256 x")),"y":B64.encode(point.y().expect("P256 y"))})
    }
    pub fn thumbprint(&self) -> Result<String> {
        jwk_thumbprint(&self.public_jwk())
    }
    pub fn proof(
        &self,
        method: &str,
        uri: &str,
        token: Option<&str>,
        nonce: Option<&str>,
        now: u64,
    ) -> Result<String> {
        let header = json!({"alg":"ES256","typ":"dpop+jwt","jwk":self.public_jwk()});
        let mut claims = json!({"htm":method.to_uppercase(),"htu":uri,"iat":now,"jti":random_id()});
        if let Some(token) = token {
            claims["ath"] = json!(access_token_hash(token));
        }
        if let Some(nonce) = nonce {
            claims["nonce"] = json!(nonce);
        }
        let input = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(&header)?),
            B64.encode(serde_json::to_vec(&claims)?)
        );
        let signature: Signature = self.0.sign(input.as_bytes());
        Ok(format!("{input}.{}", B64.encode(signature.to_bytes())))
    }
}

fn timestamp(v: &Value) -> Option<i64> {
    v.as_i64()
        .or_else(|| v.as_f64().map(|f| f as i64))
        .or_else(|| v.as_str()?.parse().ok())
}
fn check_times(claims: &Value, now: u64, skew: u64) -> Result<()> {
    let now = i128::from(now);
    let skew = i128::from(skew);
    for field in ["iat", "nbf", "exp"] {
        if let Some(v) = claims.get(field) {
            let t = i128::from(timestamp(v).ok_or(Error::Credential)?);
            if (field == "exp" && t <= now - skew) || (field != "exp" && t > now + skew) {
                return Err(Error::Credential);
            }
        }
    }
    Ok(())
}
fn decode_token(
    token: &str,
    key: &DecodingKey,
    issuer: &str,
    now: u64,
    skew: u64,
) -> Result<Value> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    let claims = jsonwebtoken::decode::<Value>(token, key, &validation)
        .map_err(|_| Error::Credential)?
        .claims;
    if claims["iss"] != issuer {
        return Err(Error::Credential);
    }
    check_times(&claims, now, skew)?;
    Ok(claims)
}

/// Signature verification is offline against a trusted local JWKS snapshot.
pub fn verify_rs256(token: &str, jwks: &Value, issuer: &str, now: u64, skew: u64) -> Result<Value> {
    let header = jsonwebtoken::decode_header(token).map_err(|_| Error::Credential)?;
    if header.alg != Algorithm::RS256 {
        return Err(Error::Credential);
    }
    let kid = header.kid.ok_or(Error::Credential)?;
    let keys = jwks["keys"].as_array().ok_or(Error::Credential)?;
    let key = keys
        .iter()
        .find(|j| j["kid"] == kid && j["kty"] == "RSA")
        .ok_or(Error::Credential)?;
    let decoding = DecodingKey::from_rsa_components(
        key["n"].as_str().ok_or(Error::Credential)?,
        key["e"].as_str().ok_or(Error::Credential)?,
    )
    .map_err(|_| Error::Credential)?;
    decode_token(token, &decoding, issuer, now, skew)
}

pub struct ResourceRequest<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub audience: Option<&'a str>,
    pub scopes: &'a [String],
    pub proof: Option<&'a str>,
    pub legacy_pop: Option<&'a str>,
    pub legacy_timestamp: Option<&'a str>,
    /// Actual located bound targets from the resource's request extractor.
    pub values: &'a Value,
}

/// Auth51's defaults: signature skew 60s, proof age 300s, PoP required.
/// Replay rejection is an explicit extra safeguard: Python currently has no
/// proof replay cache. The MCP executor enables it alongside durable receipts.
pub struct ResourceVerifier {
    pub issuer: String,
    pub jwks: Value,
    pub require_pop: bool,
    pub clock_skew: u64,
    pub proof_skew: u64,
    pub reject_replay: bool,
    seen: HashMap<(String, String), u64>,
}
impl ResourceVerifier {
    pub fn new(issuer: &str, jwks: Value) -> Self {
        Self {
            issuer: issuer.into(),
            jwks,
            require_pop: true,
            clock_skew: 60,
            proof_skew: 300,
            reject_replay: false,
            seen: HashMap::new(),
        }
    }
    pub fn verify(
        &mut self,
        token: &str,
        request: &ResourceRequest<'_>,
        now: u64,
        provider: impl FnMut(&Value) -> Result<Value>,
    ) -> Result<Value> {
        let claims = verify_rs256(token, &self.jwks, &self.issuer, now, self.clock_skew)?;
        if let Some(aud) = request.audience {
            if claims["aud"] != aud
                && !claims["aud"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|a| a == aud))
            {
                return Err(Error::Policy(403, "invalid audience".into()));
            }
        }
        let raw = claims
            .get("scope")
            .filter(|s| truthy(s))
            .or_else(|| claims.get("scp"));
        let have: Vec<&str> = match raw {
            Some(Value::String(s)) => s.split_whitespace().collect(),
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
            _ => vec![],
        };
        if request.scopes.iter().any(|s| !have.contains(&s.as_str())) {
            return Err(Error::Policy(403, "missing required scope".into()));
        }
        let cnf = &claims["cnf"];
        let mut replay = None;
        if !truthy(cnf) {
            if self.require_pop {
                return Err(Error::Credential);
            }
        } else if let Some(jkt) = cnf["jkt"].as_str() {
            let proof = request.proof.ok_or(Error::Credential)?;
            let (header, pclaims, input, sig) = split_proof(proof)?;
            if header["typ"] != "dpop+jwt"
                || header["alg"] != "ES256"
                || jwk_thumbprint(&header["jwk"])? != jkt
            {
                return Err(Error::Credential);
            }
            let mut point = vec![4];
            for c in ["x", "y"] {
                point.extend(
                    B64.decode(header["jwk"][c].as_str().ok_or(Error::Credential)?)
                        .map_err(|_| Error::Credential)?,
                );
            }
            VerifyingKey::from_sec1_bytes(&point)
                .map_err(|_| Error::Credential)?
                .verify(
                    input.as_bytes(),
                    &Signature::from_slice(&sig).map_err(|_| Error::Credential)?,
                )
                .map_err(|_| Error::Credential)?;
            check_times(&pclaims, now, 0)?;
            let iat = pclaims["iat"].as_f64().ok_or(Error::Credential)?;
            if (now as f64 - iat).abs() > self.proof_skew as f64
                || pclaims["htm"].as_str().map(str::to_uppercase).as_deref()
                    != Some(&request.method.to_uppercase())
                || pclaims["htu"] != request.uri
                || pclaims["ath"] != access_token_hash(token)
            {
                return Err(Error::Credential);
            }
            if self.reject_replay {
                let jti = pclaims["jti"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or(Error::Credential)?;
                self.seen.retain(|_, exp| *exp >= now);
                let key = (jkt.to_string(), jti.to_string());
                if self.seen.contains_key(&key) {
                    return Err(Error::Credential);
                }
                replay = Some((key, now.saturating_add(self.proof_skew)));
            }
        } else if cnf.get("jwk").is_some() {
            verify_legacy(&claims, request)?;
        } else {
            return Err(Error::Credential);
        }
        if let Some(binding) = claims.get("vb").filter(|v| truthy(v)) {
            let binding: ValueBinding = serde_json::from_value(binding.clone())?;
            verify_binding(&binding, request.values, provider)?;
        }
        if let Some((key, expiry)) = replay {
            self.seen.insert(key, expiry);
        }
        Ok(claims)
    }
}

fn split_proof(proof: &str) -> Result<(Value, Value, String, Vec<u8>)> {
    let p: Vec<_> = proof.split('.').collect();
    if p.len() != 3 {
        return Err(Error::Credential);
    }
    let dec = |p: &str| B64.decode(p).map_err(|_| Error::Credential);
    Ok((
        serde_json::from_slice(&dec(p[0])?)?,
        serde_json::from_slice(&dec(p[1])?)?,
        format!("{}.{}", p[0], p[1]),
        dec(p[2])?,
    ))
}
fn verify_legacy(claims: &Value, r: &ResourceRequest<'_>) -> Result<()> {
    use rsa::{BigUint, pkcs1v15, signature::Verifier as _};
    use sha2::Sha256;
    let jwk = &claims["cnf"]["jwk"];
    let decode = |s: &Value| {
        B64.decode(s.as_str().ok_or(Error::Credential)?)
            .map_err(|_| Error::Credential)
    };
    let key = RsaPublicKey::new(
        BigUint::from_bytes_be(&decode(&jwk["n"])?),
        BigUint::from_bytes_be(&decode(&jwk["e"])?),
    )
    .map_err(|_| Error::Credential)?;
    let stamp = r
        .legacy_timestamp
        .ok_or(Error::Credential)?
        .parse::<i64>()
        .map_err(|_| Error::Credential)?;
    let message = json!({"method":r.method,"url":r.uri,"data":"","checksum":claims["agent_proof"]["agent_checksum"],"timestamp":stamp});
    let sig = base64::engine::general_purpose::STANDARD
        .decode(r.legacy_pop.ok_or(Error::Credential)?)
        .map_err(|_| Error::Credential)?;
    pkcs1v15::VerifyingKey::<Sha256>::new(key)
        .verify(
            super::identity::python_json(&message)?.as_bytes(),
            &pkcs1v15::Signature::try_from(sig.as_slice()).map_err(|_| Error::Credential)?,
        )
        .map_err(|_| Error::Credential)
}

pub(crate) fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(m) => !m.is_empty(),
        Value::Number(n) => n.as_f64() != Some(0.0),
    }
}
