//! Cloudflare Access JWT authentication.
//!
//! When ZeroClaw is behind Cloudflare Access, requests include a validated JWT
//! after the user authenticates. This module extracts and validates that JWT
//! to identify the user instead of using internal pairing codes.

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum CloudflareAudience {
    Single(String),
    Multiple(Vec<String>),
}

/// Claims extracted from Cloudflare Access JWT.
#[derive(Debug, Clone, Deserialize)]
pub struct CloudflareClaims {
    /// User's email address.
    pub email: Option<String>,
    /// User's unique identifier.
    pub sub: Option<String>,
    /// Issuer - should be https://<team>.cloudflareaccess.com
    pub iss: Option<String>,
    /// Audience - should match the Application AUD tag
    pub aud: Option<CloudflareAudience>,
    /// Expiration timestamp
    pub exp: Option<i64>,
    /// Issued at timestamp
    pub iat: Option<i64>,
    /// Groups the user belongs to (if configured).
    #[serde(default)]
    pub groups: Vec<String>,
    /// Custom claims from the token.
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Result of JWT validation.
#[derive(Debug)]
pub enum CloudflareAuthResult {
    /// User is authenticated via Cloudflare Access.
    Authenticated(CloudflareClaims),
    /// Cloudflare Access headers not present (normal for non-CF requests).
    NotPresent,
    /// JWT validation failed.
    Invalid(String),
}

/// Extract and validate Cloudflare Access JWT from request headers/cookies.
///
/// Cloudflare Access sets the JWT in:
///
/// 1. Cookie: `CF_Access_JWT` (browser requests)
/// 2. Header: `CF-Access-Client-Token` (service tokens/API requests)
///
/// The JWT is validated against Cloudflare's public key, which can be fetched
/// from the well-known endpoint or configured directly.
pub fn validate_cloudflare_token(
    jwt: &str,
    public_key: &str,
    aud_tag: Option<&str>,
) -> CloudflareAuthResult {
    if jwt.is_empty() {
        return CloudflareAuthResult::NotPresent;
    }

    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return CloudflareAuthResult::Invalid("Invalid JWT format".to_string());
    }

    let header = match decode_base64_url(parts[0]) {
        Ok(h) => h,
        Err(e) => return CloudflareAuthResult::Invalid(format!("Failed to decode header: {}", e)),
    };

    let header_json: serde_json::Value = match serde_json::from_slice(&header) {
        Ok(v) => v,
        Err(e) => return CloudflareAuthResult::Invalid(format!("Invalid header JSON: {}", e)),
    };

    let alg = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("RS256");
    let kid = header_json
        .get("kid")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    if alg != "RS256" {
        return CloudflareAuthResult::Invalid(format!("Unsupported algorithm: {}", alg));
    }

    let payload = match decode_base64_url(parts[1]) {
        Ok(p) => p,
        Err(e) => return CloudflareAuthResult::Invalid(format!("Failed to decode payload: {}", e)),
    };

    let claims: CloudflareClaims = match serde_json::from_slice(&payload) {
        Ok(c) => c,
        Err(e) => return CloudflareAuthResult::Invalid(format!("Invalid claims JSON: {}", e)),
    };

    // Validate expiration
    if let Some(exp) = claims.exp {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if exp < now {
            tracing::warn!("Token expired: exp={}, now={}", exp, now);
            return CloudflareAuthResult::Invalid("Token expired".to_string());
        }
    }

    // Validate audience if provided
    if let Some(expected_aud) = aud_tag {
        if let Some(aud) = &claims.aud {
            let aud_ok = match aud {
                CloudflareAudience::Single(aud) => aud == expected_aud,
                CloudflareAudience::Multiple(audiences) => {
                    audiences.iter().any(|aud| aud == expected_aud)
                }
            };
            if !aud_ok {
                let got = match aud {
                    CloudflareAudience::Single(aud) => aud.clone(),
                    CloudflareAudience::Multiple(audiences) => audiences.join(","),
                };
                return CloudflareAuthResult::Invalid(format!(
                    "Invalid audience: expected {}, got {}",
                    expected_aud, got
                ));
            }
        } else {
            return CloudflareAuthResult::Invalid("Missing audience claim".to_string());
        }
    }

    // Validate issuer
    if let Some(iss) = &claims.iss {
        tracing::debug!("JWT issuer: {}", iss);
        if !iss.ends_with(".cloudflareaccess.com") && !iss.contains(".cloudflareaccess.com") {
            return CloudflareAuthResult::Invalid(format!("Invalid issuer: {}", iss));
        }
    }

    // Signature verification will be done below
    let signature_input = format!("{}.{}", parts[0], parts[1]);
    let signature = match decode_base64_url(parts[2]) {
        Ok(s) => s,
        Err(e) => {
            return CloudflareAuthResult::Invalid(format!("Failed to decode signature: {}", e))
        }
    };

    tracing::debug!("Verifying signature with configured public key...");
    match verify_rsa_sha256(public_key, signature_input.as_bytes(), &signature) {
        Ok(()) => {
            tracing::debug!("JWT validation successful (configured key)");
            return CloudflareAuthResult::Authenticated(claims);
        }
        Err(primary_err) => {
            tracing::warn!(
                "Signature verification failed with configured key: {}",
                primary_err
            );

            // Fallback: verify against Cloudflare JWKS for key rotation support.
            if let Some(iss) = claims.iss.as_deref() {
                if let Err(jwks_err) = verify_against_cloudflare_jwks(
                    iss,
                    kid.as_deref(),
                    signature_input.as_bytes(),
                    &signature,
                ) {
                    tracing::warn!(
                        "Signature verification failed via JWKS fallback: {}",
                        jwks_err
                    );
                    return CloudflareAuthResult::Invalid(format!(
                        "Signature verification failed: {}; jwks fallback failed: {}",
                        primary_err, jwks_err
                    ));
                }

                tracing::debug!("JWT validation successful (JWKS fallback)");
                return CloudflareAuthResult::Authenticated(claims);
            }

            return CloudflareAuthResult::Invalid(format!(
                "Signature verification failed: {}",
                primary_err
            ));
        }
    }
}

fn decode_base64_url(input: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    engine
        .decode(input)
        .map_err(|e| format!("Base64 decode error: {}", e))
}

fn verify_rsa_sha256(public_key_pem: &str, message: &[u8], signature: &[u8]) -> Result<(), String> {
    use ring::signature::UnparsedPublicKey;
    use ring::signature::RSA_PKCS1_2048_8192_SHA256;

    let public_key = parse_rsa_public_key(public_key_pem)?;
    let public_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_key);

    public_key
        .verify(message, signature)
        .map_err(|e| format!("Signature verify error: {}", e))
}

#[derive(Debug, Deserialize)]
struct CloudflareJwks {
    keys: Vec<CloudflareJwkKey>,
}

#[derive(Debug, Deserialize)]
struct CloudflareJwkKey {
    kid: String,
    kty: String,
    n: String,
    e: String,
}

#[derive(Clone)]
struct JwksCacheEntry {
    fetched_at: Instant,
    keys: HashMap<String, Vec<u8>>, // kid -> SPKI DER
}

static CLOUDFLARE_JWKS_CACHE: OnceLock<Mutex<HashMap<String, JwksCacheEntry>>> = OnceLock::new();
const JWKS_CACHE_TTL: Duration = Duration::from_secs(300);

fn verify_against_cloudflare_jwks(
    iss: &str,
    kid: Option<&str>,
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    use ring::signature::{UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};

    let keys = cloudflare_jwks_keys_for_issuer(iss)?;
    if keys.is_empty() {
        return Err("No RSA keys found in Cloudflare JWKS".to_string());
    }

    if let Some(target_kid) = kid {
        if let Some(key) = keys.get(target_kid) {
            let verifier = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key);
            return verifier
                .verify(message, signature)
                .map_err(|e| format!("kid {} verify error: {}", target_kid, e));
        }
    }

    for (candidate_kid, key) in &keys {
        let verifier = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key);
        if verifier.verify(message, signature).is_ok() {
            tracing::debug!("JWT signature verified with JWKS kid={}", candidate_kid);
            return Ok(());
        }
    }

    Err("No matching JWKS key could verify signature".to_string())
}

fn cloudflare_jwks_keys_for_issuer(iss: &str) -> Result<HashMap<String, Vec<u8>>, String> {
    let cache = CLOUDFLARE_JWKS_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let now = Instant::now();

    if let Some(cached) = cache
        .lock()
        .map_err(|_| "JWKS cache lock poisoned".to_string())?
        .get(iss)
        .cloned()
    {
        if now.duration_since(cached.fetched_at) < JWKS_CACHE_TTL {
            return Ok(cached.keys);
        }
    }

    let keys = fetch_cloudflare_jwks_keys(iss)?;
    cache
        .lock()
        .map_err(|_| "JWKS cache lock poisoned".to_string())?
        .insert(
            iss.to_string(),
            JwksCacheEntry {
                fetched_at: now,
                keys: keys.clone(),
            },
        );

    Ok(keys)
}

fn fetch_cloudflare_jwks_keys(iss: &str) -> Result<HashMap<String, Vec<u8>>, String> {
    let jwks_url = format!("{}/cdn-cgi/access/certs", iss.trim_end_matches('/'));
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| format!("Failed to build JWKS client: {}", e))?;

    let jwks: CloudflareJwks = client
        .get(&jwks_url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|e| format!("Failed to fetch Cloudflare JWKS from {}: {}", jwks_url, e))?
        .json()
        .map_err(|e| format!("Failed to parse Cloudflare JWKS JSON: {}", e))?;

    let mut keys = HashMap::new();
    for k in jwks.keys {
        if k.kty != "RSA" {
            continue;
        }
        let spki = jwk_rsa_to_spki_der(&k.n, &k.e)?;
        keys.insert(k.kid, spki);
    }
    Ok(keys)
}

fn jwk_rsa_to_spki_der(n_b64url: &str, e_b64url: &str) -> Result<Vec<u8>, String> {
    let n = decode_base64_url(n_b64url)?;
    let e = decode_base64_url(e_b64url)?;

    let rsa_pubkey = der_sequence([der_integer(&n), der_integer(&e)].concat());

    // rsaEncryption OID + NULL params
    let alg_id = der_sequence([der_oid(&[1, 2, 840, 113549, 1, 1, 1]), der_null()].concat());

    let subject_public_key = der_bit_string(&rsa_pubkey);

    Ok(der_sequence([alg_id, subject_public_key].concat()))
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 128 {
        return vec![len as u8];
    }

    let mut bytes = Vec::new();
    let mut n = len;
    while n > 0 {
        bytes.push((n & 0xff) as u8);
        n >>= 8;
    }
    bytes.reverse();

    let mut out = vec![0x80 | (bytes.len() as u8)];
    out.extend(bytes);
    out
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(value.len()));
    out.extend(value);
    out
}

fn der_sequence(value: Vec<u8>) -> Vec<u8> {
    der_tlv(0x30, &value)
}

fn der_integer(raw: &[u8]) -> Vec<u8> {
    let mut value = raw.to_vec();
    while value.len() > 1 && value[0] == 0 {
        value.remove(0);
    }
    if value.first().map(|b| b & 0x80 != 0).unwrap_or(false) {
        let mut prefixed = vec![0x00];
        prefixed.extend(value);
        return der_tlv(0x02, &prefixed);
    }
    der_tlv(0x02, &value)
}

fn der_bit_string(raw: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(raw.len() + 1);
    v.push(0x00); // 0 unused bits
    v.extend(raw);
    der_tlv(0x03, &v)
}

fn der_null() -> Vec<u8> {
    der_tlv(0x05, &[])
}

fn der_oid(components: &[u64]) -> Vec<u8> {
    if components.len() < 2 {
        return der_tlv(0x06, &[]);
    }

    let mut bytes = Vec::new();
    bytes.push((components[0] * 40 + components[1]) as u8);
    for &c in &components[2..] {
        let mut stack = Vec::new();
        let mut value = c;
        stack.push((value & 0x7f) as u8);
        value >>= 7;
        while value > 0 {
            stack.push(((value & 0x7f) as u8) | 0x80);
            value >>= 7;
        }
        stack.reverse();
        bytes.extend(stack);
    }
    der_tlv(0x06, &bytes)
}

fn parse_rsa_public_key(pem: &str) -> Result<Vec<u8>, String> {
    let pem = pem.trim();
    let header = "-----BEGIN PUBLIC KEY-----";
    let footer = "-----END PUBLIC KEY-----";

    if pem.contains("-----BEGIN CERTIFICATE-----") {
        return Err(
            "cf_access_public_key contains a CERTIFICATE PEM; expected a PUBLIC KEY PEM"
                .to_string(),
        );
    }

    if !pem.contains(header) {
        use base64::Engine;
        let standard = base64::engine::general_purpose::STANDARD;

        if let Ok(decoded) = standard.decode(pem) {
            return Ok(decoded);
        }

        if let Ok(decoded) = decode_base64_url(pem) {
            return Ok(decoded);
        }

        return Ok(pem.as_bytes().to_vec());
    }

    let start = pem.find(header).map(|i| i + header.len()).unwrap_or(0);
    let end = pem.find(footer).map(|i| i).unwrap_or(pem.len());

    let encoded = pem[start..end].trim();
    let encoded_compact: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();

    // PEM bodies use standard base64 (with '+' and '/' chars, often padded).
    // Keep a URL-safe fallback in case operators paste URL-safe encoded DER.
    {
        use base64::Engine;
        let standard = base64::engine::general_purpose::STANDARD;
        if let Ok(decoded) = standard.decode(&encoded_compact) {
            return Ok(decoded);
        }
    }

    decode_base64_url(&encoded_compact)
}

/// Check if Cloudflare Access headers are present in the request.
pub fn has_cloudflare_access_headers(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get("cf-access-jwt-assertion")
        .or_else(|| headers.get("cf-access-client-token"))
        .is_some()
        || headers
            .get(axum::http::header::COOKIE)
            .map(|c| c.to_str().unwrap_or("").contains("CF_Authorization"))
            .unwrap_or(false)
}

/// Extract Cloudflare Access JWT from request.
///
/// Checks headers in order:
/// 1. `Cf-Access-Jwt-Assertion` header (primary)
/// 2. `CF_Authorization` cookie (browser)
/// 3. `CF-Access-Client-Token` header (service tokens)
pub fn extract_cloudflare_jwt(headers: &axum::http::HeaderMap) -> Option<String> {
    // 1. Check Cf-Access-Jwt-Assertion header (primary) - case insensitive
    for (name, value) in headers.iter() {
        if name
            .as_str()
            .eq_ignore_ascii_case("cf-access-jwt-assertion")
        {
            tracing::debug!("Found Cf-Access-Jwt-Assertion header");
            return value.to_str().ok().map(|s| s.to_string());
        }
    }

    // 2. Check CF_Access_JWT cookie (standard Cloudflare Access cookie)
    if let Some(cookie) = headers.get(axum::http::header::COOKIE) {
        if let Ok(cookie_str) = cookie.to_str() {
            for part in cookie_str.split(';') {
                let part = part.trim();
                if part.starts_with("CF_Access_JWT=") || part.starts_with("CF_Authorization=") {
                    let key = if part.starts_with("CF_Access_JWT=") {
                        "CF_Access_JWT="
                    } else {
                        "CF_Authorization="
                    };
                    tracing::debug!("Found {} cookie", key.trim_end_matches('='));
                    return Some(part.strip_prefix(key)?.to_string());
                }
            }
        }
    }

    // 3. Check CF-Access-Client-Token header (service tokens)
    for (name, value) in headers.iter() {
        if name.as_str().eq_ignore_ascii_case("cf-access-client-token") {
            tracing::debug!("Found CF-Access-Client-Token header");
            return value.to_str().ok().map(|s| s.to_string());
        }
    }

    tracing::debug!("No Cloudflare Access JWT found in headers");
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_jwt_from_cookie() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "CF_Access_JWT=eyJhbGciOiJSUzI1NiJ9.test.signature"
                .parse()
                .unwrap(),
        );

        let jwt = extract_cloudflare_jwt(&headers);
        assert!(jwt.is_some());
        assert!(jwt.unwrap().starts_with("eyJhbGciOiJSUzI1NiJ9"));
    }

    #[test]
    fn test_has_cloudflare_headers() {
        let mut headers = axum::http::HeaderMap::new();
        assert!(!has_cloudflare_access_headers(&headers));

        headers.insert("CF_Access_JWT", "test.jwt".parse().unwrap());
        assert!(has_cloudflare_access_headers(&headers));
    }

    #[test]
    fn test_parse_rsa_public_key_accepts_standard_pem_base64() {
        let pem = "-----BEGIN PUBLIC KEY-----\nAQIDBA==\n-----END PUBLIC KEY-----";
        let parsed = parse_rsa_public_key(pem).expect("pem parse should succeed");
        assert_eq!(parsed, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_validate_audience_with_array_claim() {
        let claims: CloudflareClaims = serde_json::from_str(r#"{"aud":["aud-a","aud-b"]}"#)
            .expect("claims parse should succeed");

        let aud_ok = match claims.aud {
            Some(CloudflareAudience::Multiple(v)) => v.iter().any(|a| a == "aud-b"),
            _ => false,
        };

        assert!(aud_ok);
    }

    #[test]
    fn test_parse_rsa_public_key_rejects_certificate_pem() {
        let cert = "-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----";
        let err = parse_rsa_public_key(cert).expect_err("certificate pem should be rejected");
        assert!(err.contains("expected a PUBLIC KEY PEM"));
    }
}
