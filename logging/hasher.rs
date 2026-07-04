use aws_lc_rs::hmac;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&key, data).as_ref().to_vec()
}

pub fn unix_millis(ts: SystemTime) -> u128 {
    ts.duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis()
}

pub fn day_bucket(unix_ms: u128) -> u128 {
    unix_ms / 1000 / 60 / 60 / 24
}
