//! Canonical hashing for manifests and preprocessed values.

use sha2::{Digest, Sha256};

use crate::manifest::AuditManifest;

/// Content-addressed hash (hex).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentHash(pub String);

/// Canonical JSON (serde_json default map order is insertion-preserving via IndexMap where used).
pub fn canonical_json<T: serde::Serialize>(value: &T) -> Result<String, serde_json::Error> {
    serde_json::to_string(value)
}

/// SHA-256 hex of canonical JSON.
pub fn content_hash<T: serde::Serialize>(value: &T) -> Result<ContentHash, serde_json::Error> {
    let json = canonical_json(value)?;
    let digest = Sha256::digest(json.as_bytes());
    Ok(ContentHash(hex_encode(&digest)))
}

/// Hash little-endian u32 words (preprocessed column values).
pub fn hash_u32_values(values: &[u32]) -> String {
    let mut hasher = blake3::Hasher::new();
    for value in values {
        hasher.update(&value.to_le_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

/// Hash an audit manifest document.
pub fn hash_manifest(manifest: &AuditManifest) -> Result<ContentHash, serde_json::Error> {
    content_hash(manifest)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_u32_is_stable() {
        let a = hash_u32_values(&[1, 2, 3]);
        let b = hash_u32_values(&[1, 2, 3]);
        let c = hash_u32_values(&[1, 2, 4]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
