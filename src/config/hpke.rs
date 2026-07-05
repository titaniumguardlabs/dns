use serde::{Deserialize, de::Error as DeError};
use serde_json::Value;

pub fn deserialize_hpke_kem_id<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = parse_hpke_id_with_names(deserializer, map_kem_name_to_id)?;
    match value {
        0x0010 | 0x0011 | 0x0012 | 0x0020 | 0x0021 => Ok(value),
        other => Err(D::Error::custom(format!(
            "unsupported HPKE KEM ID {other:#06x}; allowed: DHKEM(P-256, HKDF-SHA256), DHKEM(P-384, HKDF-SHA384), DHKEM(P-521, HKDF-SHA512), DHKEM(X25519, HKDF-SHA256), DHKEM(X448, HKDF-SHA512)"
        ))),
    }
}

pub fn deserialize_hpke_kdf_id<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = parse_hpke_id_with_names(deserializer, map_kdf_name_to_id)?;
    match value {
        0x0001 | 0x0002 | 0x0003 => Ok(value),
        other => Err(D::Error::custom(format!(
            "unsupported HPKE KDF ID {other:#06x}; allowed: HKDF-SHA256, HKDF-SHA384, HKDF-SHA512"
        ))),
    }
}

pub fn deserialize_hpke_aead_id<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = parse_hpke_id_with_names(deserializer, map_aead_name_to_id)?;
    match value {
        0x0001 | 0x0002 | 0x0003 | 0xFFFF => Ok(value),
        other => Err(D::Error::custom(format!(
            "unsupported HPKE AEAD ID {other:#06x}; allowed: AES-128-GCM, AES-256-GCM, CHACHA20POLY1305, EXPORT-ONLY"
        ))),
    }
}

fn parse_hpke_id_with_names<'de, D, F>(deserializer: D, map_name: F) -> Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
    F: Fn(&str) -> Option<u16>,
{
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::Number(number) => {
            let raw = number
                .as_u64()
                .ok_or_else(|| D::Error::custom("HPKE ID must be a non-negative integer"))?;
            u16::try_from(raw).map_err(|_| D::Error::custom("HPKE ID must fit in u16"))
        }
        Value::String(text) => {
            if let Some(id) = map_name(&text) {
                Ok(id)
            } else {
                parse_hpke_id_str::<D::Error>(&text)
            }
        }
        _ => Err(D::Error::custom(
            "HPKE ID must be a number or a hex string like 0x0020",
        )),
    }
}

fn parse_hpke_id_str<E: DeError>(text: &str) -> Result<u16, E> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(E::custom("HPKE ID string must not be empty"));
    }
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u16::from_str_radix(hex, 16)
            .map_err(|_| E::custom(format!("invalid hexadecimal HPKE ID: {trimmed}")));
    }
    trimmed
        .parse::<u16>()
        .map_err(|_| E::custom(format!("invalid HPKE ID: {trimmed}")))
}

fn map_kem_name_to_id(name: &str) -> Option<u16> {
    let normalized = normalize_hpke_name(name);
    match normalized.as_str() {
        "DHKEM(P-256,HKDF-SHA256)" => Some(0x0010),
        "DHKEM(P-384,HKDF-SHA384)" => Some(0x0011),
        "DHKEM(P-521,HKDF-SHA512)" => Some(0x0012),
        "DHKEM(X25519,HKDF-SHA256)" => Some(0x0020),
        "DHKEM(X448,HKDF-SHA512)" => Some(0x0021),
        _ => None,
    }
}

fn map_kdf_name_to_id(name: &str) -> Option<u16> {
    let normalized = normalize_hpke_name(name);
    match normalized.as_str() {
        "HKDF-SHA256" => Some(0x0001),
        "HKDF-SHA384" => Some(0x0002),
        "HKDF-SHA512" => Some(0x0003),
        _ => None,
    }
}

fn map_aead_name_to_id(name: &str) -> Option<u16> {
    let normalized = normalize_hpke_name(name);
    match normalized.as_str() {
        "AES-128-GCM" => Some(0x0001),
        "AES-256-GCM" => Some(0x0002),
        "CHACHA20POLY1305" => Some(0x0003),
        "EXPORT-ONLY" => Some(0xFFFF),
        _ => None,
    }
}

fn normalize_hpke_name(name: &str) -> String {
    name.trim()
        .to_ascii_uppercase()
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect()
}
