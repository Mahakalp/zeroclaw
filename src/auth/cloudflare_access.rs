//! Cloudflare Access JWT authentication.
//!
//! When ZeroClaw is behind Cloudflare Access, requests include a validated JWT
//! after the user authenticates. This module extracts and validates that JWT
//! to identify the user instead of using internal pairing codes.

use serde::Deserialize;

/// Claims extracted from Cloudflare Access JWT.
#[derive(Debug, Clone, Deserialize)]
pub struct CloudflareClaims {
    /// User's email address.
    pub email: Option<String>,
    /// User's unique identifier.
    pub sub: Option<String>,
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
pub fn validate_cloudflare_token(jwt: &str, public_key: &str) -> CloudflareAuthResult {
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

    let signature_input = format!("{}.{}", parts[0], parts[1]);
    let signature = match decode_base64_url(parts[2]) {
        Ok(s) => s,
        Err(e) => {
            return CloudflareAuthResult::Invalid(format!("Failed to decode signature: {}", e))
        }
    };

    if let Err(e) = verify_rsa_sha256(public_key, signature_input.as_bytes(), &signature) {
        return CloudflareAuthResult::Invalid(format!("Signature verification failed: {}", e));
    }

    CloudflareAuthResult::Authenticated(claims)
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

fn parse_rsa_public_key(pem: &str) -> Result<Vec<u8>, String> {
    let pem = pem.trim();
    let header = "-----BEGIN PUBLIC KEY-----";
    let footer = "-----END PUBLIC KEY-----";

    if !pem.contains(header) {
        return Ok(pem.as_bytes().to_vec());
    }

    let start = pem.find(header).map(|i| i + header.len()).unwrap_or(0);
    let end = pem.find(footer).map(|i| i).unwrap_or(pem.len());

    let encoded = pem[start..end].trim();
    decode_base64_url(encoded)
}

/// Check if Cloudflare Access headers are present in the request.
pub fn has_cloudflare_access_headers(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get("cf-access-jwt")
        .or_else(|| headers.get("cf-access-client-token"))
        .is_some()
        || headers
            .get(axum::http::header::COOKIE)
            .map(|c| c.to_str().unwrap_or("").contains("CF_Access_JWT"))
            .unwrap_or(false)
}

/// Extract Cloudflare Access JWT from request.
///
/// Checks headers in order:
/// 1. `CF_Access_JWT` cookie
/// 2. `CF-Access-Client-Token` header (for service tokens)
pub fn extract_cloudflare_jwt(headers: &axum::http::HeaderMap) -> Option<String> {
    if let Some(cookie) = headers.get(axum::http::header::COOKIE) {
        if let Ok(cookie_str) = cookie.to_str() {
            for part in cookie_str.split(';') {
                let part = part.trim();
                if part.starts_with("CF_Access_JWT=") {
                    return Some(part.strip_prefix("CF_Access_JWT=")?.to_string());
                }
            }
        }
    }

    if let Some(token) = headers.get("cf-access-client-token") {
        return token.to_str().ok().map(|s| s.to_string());
    }

    if let Some(token) = headers.get("CF-Access-Client-Token") {
        return token.to_str().ok().map(|s| s.to_string());
    }

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
}
