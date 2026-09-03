use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

type HmacSha256 = Hmac<Sha256>;

/// AWS Signature Version 4 request signer for S3-compatible APIs.
#[derive(Debug, Clone)]
pub struct SigV4Signer {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub region: String,
    pub service: String,
}

impl SigV4Signer {
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        region: impl Into<String>,
    ) -> Self {
        Self {
            access_key_id: access_key_id.into(),
            secret_access_key: secret_access_key.into(),
            region: region.into(),
            service: "s3".to_string(),
        }
    }

    /// Computes the 4-step AWS HMAC-SHA256 signing key for a given date stamp (`YYYYMMDD`).
    pub fn derive_signing_key(&self, date_stamp: &str) -> Vec<u8> {
        let k_secret = format!("AWS4{}", self.secret_access_key);
        let mut mac = HmacSha256::new_from_slice(k_secret.as_bytes()).expect("HMAC can take key of any size");
        mac.update(date_stamp.as_bytes());
        let k_date = mac.finalize().into_bytes();

        let mut mac = HmacSha256::new_from_slice(&k_date).expect("HMAC key");
        mac.update(self.region.as_bytes());
        let k_region = mac.finalize().into_bytes();

        let mut mac = HmacSha256::new_from_slice(&k_region).expect("HMAC key");
        mac.update(self.service.as_bytes());
        let k_service = mac.finalize().into_bytes();

        let mut mac = HmacSha256::new_from_slice(&k_service).expect("HMAC key");
        mac.update(b"aws4_request");
        mac.finalize().into_bytes().to_vec()
    }

    /// Generates headers for an S3 HTTP request:
    /// - `X-Amz-Date`
    /// - `X-Amz-Content-Sha256`
    /// - `Authorization`
    pub fn sign_request(
        &self,
        method: &str,
        path: &str,
        query_params: &[(String, String)],
        headers: &BTreeMap<String, String>,
        payload_sha256: &str,
        datetime: &str,
    ) -> (String, String, String) {
        let date_stamp = &datetime[..8]; // YYYYMMDD
        let credential_scope = format!("{}/{}/{}/aws4_request", date_stamp, self.region, self.service);

        // 1. Prepare canonical headers
        let mut canon_headers = BTreeMap::new();
        for (k, v) in headers {
            let lower = k.to_ascii_lowercase();
            let trimmed = v.trim();
            canon_headers.insert(lower, trimmed.to_string());
        }
        // Ensure x-amz-date and x-amz-content-sha256 are present
        canon_headers.insert("x-amz-date".to_string(), datetime.to_string());
        canon_headers.insert("x-amz-content-sha256".to_string(), payload_sha256.to_string());

        let mut canonical_headers_str = String::new();
        let mut signed_headers_vec = Vec::new();
        for (k, v) in &canon_headers {
            canonical_headers_str.push_str(&format!("{}:{}\n", k, v));
            signed_headers_vec.push(k.as_str());
        }
        let signed_headers_str = signed_headers_vec.join(";");

        // 2. Canonical query string
        let mut sorted_query = query_params.to_vec();
        sorted_query.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let canonical_query_str = sorted_query
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding(k), urlencoding(v)))
            .collect::<Vec<_>>()
            .join("&");

        // 3. Canonical URI
        let canonical_uri = if path.is_empty() { "/" } else { path };

        // 4. Canonical Request
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method, canonical_uri, canonical_query_str, canonical_headers_str, signed_headers_str, payload_sha256
        );

        let hashed_canonical_request = hex::encode(Sha256::digest(canonical_request.as_bytes()));

        // 5. String to Sign
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            datetime, credential_scope, hashed_canonical_request
        );

        // 6. Compute Signature
        let signing_key = self.derive_signing_key(date_stamp);
        let mut mac = HmacSha256::new_from_slice(&signing_key).expect("HMAC key");
        mac.update(string_to_sign.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        // 7. Authorization header
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.access_key_id, credential_scope, signed_headers_str, signature
        );

        (authorization, datetime.to_string(), payload_sha256.to_string())
    }
}

/// S3-compliant URI component percent-encoding (preserves unreserved characters A-Z a-z 0-9 - _ . ~)
fn urlencoding(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sigv4_signing_derivation_deterministic() {
        let signer = SigV4Signer::new(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
        );
        let key1 = signer.derive_signing_key("20130524");
        let key2 = signer.derive_signing_key("20130524");
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);

        let mut headers = BTreeMap::new();
        headers.insert("host".to_string(), "examplebucket.s3.amazonaws.com".to_string());

        let (auth, date, sha) = signer.sign_request(
            "GET",
            "/test.txt",
            &[],
            &headers,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "20130524T000000Z",
        );

        assert_eq!(date, "20130524T000000Z");
        assert_eq!(sha, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert!(auth.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders="
        ));
        assert!(auth.contains("host;x-amz-content-sha256;x-amz-date"));
        assert!(auth.contains("Signature="));
    }
}
