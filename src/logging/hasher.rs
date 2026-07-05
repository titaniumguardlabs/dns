use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct RotatingHasher {
    pub secret: Vec<u8>,
    pub rotation_minutes: u64,
}

impl RotatingHasher {
    pub fn hash(&self, purpose: &str, value: &[u8], now: SystemTime) -> (u64, String) {
        let epoch_secs = now
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();
        let window = epoch_secs / (self.rotation_minutes * 60);

        let mut first_input = Vec::with_capacity(purpose.len() + 8);
        first_input.extend_from_slice(purpose.as_bytes());
        first_input.extend_from_slice(&window.to_be_bytes());
        let key = hmac_sha256(&self.secret, &first_input);
        let digest = hmac_sha256(key.as_slice(), value);
        (window, hex::encode(digest))
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub fn unix_millis(ts: SystemTime) -> u128 {
    ts.duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis()
}

pub fn day_bucket(unix_ms: u128) -> u128 {
    unix_ms / 1000 / 60 / 60 / 24
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotating_hash_matches_hmac_sha256_vector() {
        let hasher = RotatingHasher {
            secret: b"test-secret".to_vec(),
            rotation_minutes: 1,
        };
        let now = UNIX_EPOCH + Duration::from_secs(42 * 60);

        let (window, digest) = hasher.hash("qname", b"example.com.", now);

        assert_eq!(window, 42);
        assert_eq!(
            digest,
            "bd437d2aa60b3b779f7b220115afab8d3ccbd8a94a5621c3379e586e00fec5e3"
        );
    }
}
