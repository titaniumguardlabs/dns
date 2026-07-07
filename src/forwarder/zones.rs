use super::DynResult;
use crate::config::{ZoneConfig, decode_dnssec_ed25519_key_file};
use crate::dns::{DnsClass, DnsName, DnsQuestion, DnsRecord, RData, RecordType, ResponseCode};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub(super) struct AuthoritativeZones {
    zones: Vec<AuthoritativeZone>,
}

pub(super) struct AuthoritativeZone {
    pub(super) apex_ascii: String,
    soa_record: DnsRecord,
    rrsets: HashMap<(DnsName, RecordType), Vec<DnsRecord>>,
    names: HashSet<DnsName>,
    dnssec_enabled: bool,
}

pub(super) struct AuthoritativeLookup {
    pub(super) response_code: ResponseCode,
    pub(super) answers: Vec<DnsRecord>,
    pub(super) authorities: Vec<DnsRecord>,
}

impl AuthoritativeZones {
    pub(super) fn from_configs(zone_configs: &[ZoneConfig]) -> DynResult<Self> {
        let mut zones = Vec::with_capacity(zone_configs.len());
        for zone_config in zone_configs {
            zones.push(AuthoritativeZone::from_config(zone_config)?);
        }
        Ok(Self { zones })
    }

    pub(super) fn resolve_question(&self, query: &DnsQuestion) -> Option<AuthoritativeLookup> {
        let zone = self.find_zone(&query.name)?;
        let qname = &query.name;
        let qtype = query.record_type;

        if qtype == RecordType::ANY {
            let answers = zone.records_for_name(qname);
            if !answers.is_empty() {
                return Some(AuthoritativeLookup {
                    response_code: ResponseCode::NoError,
                    answers,
                    authorities: vec![],
                });
            }
        } else if let Some(records) = zone.rrsets.get(&(qname.clone(), qtype)) {
            let mut answers = records.clone();
            answers.extend(zone.rrsig_for(qname, qtype));
            return Some(AuthoritativeLookup {
                response_code: ResponseCode::NoError,
                answers,
                authorities: vec![],
            });
        } else if qtype != RecordType::CNAME {
            if let Some(cnames) = zone.rrsets.get(&(qname.clone(), RecordType::CNAME)) {
                let mut answers = cnames.clone();
                answers.extend(zone.rrsig_for(qname, RecordType::CNAME));
                if let Some(RData::CNAME(target)) = cnames.first().map(|record| &record.data) {
                    if let Some(target_records) = zone.rrsets.get(&(target.clone(), qtype)) {
                        answers.extend(target_records.clone());
                        answers.extend(zone.rrsig_for(target, qtype));
                    }
                }
                return Some(AuthoritativeLookup {
                    response_code: ResponseCode::NoError,
                    answers,
                    authorities: vec![],
                });
            }
        }

        if zone.names.contains(qname) {
            let mut authorities = vec![zone.soa_record.clone()];
            authorities.extend(zone.denial_records_for_name(qname));
            Some(AuthoritativeLookup {
                response_code: ResponseCode::NoError,
                answers: vec![],
                authorities,
            })
        } else {
            let mut authorities = vec![zone.soa_record.clone()];
            authorities.extend(zone.denial_records_for_name(qname));
            Some(AuthoritativeLookup {
                response_code: ResponseCode::NXDomain,
                answers: vec![],
                authorities,
            })
        }
    }

    pub(super) fn find_zone<'a>(&'a self, name: &DnsName) -> Option<&'a AuthoritativeZone> {
        self.zones
            .iter()
            .filter(|zone| Self::name_in_zone(name, zone))
            .max_by_key(|zone| zone.apex_ascii.len())
    }

    fn name_in_zone(name: &DnsName, zone: &AuthoritativeZone) -> bool {
        let qname = name.to_ascii().to_lowercase();
        if qname == zone.apex_ascii {
            return true;
        }
        qname
            .strip_suffix(&zone.apex_ascii)
            .is_some_and(|left| left.ends_with('.'))
    }
}

impl AuthoritativeZone {
    fn from_config(config: &ZoneConfig) -> DynResult<Self> {
        let apex = DnsName::parse_ascii(&config.name)?;
        let apex_ascii = apex.to_ascii().to_lowercase();
        let soa_record = DnsRecord {
            name: apex.clone(),
            ttl: config.soa.ttl,
            class: DnsClass::IN,
            data: RData::SOA {
                mname: DnsName::parse_ascii(&config.soa.mname)?,
                rname: DnsName::parse_ascii(&config.soa.rname)?,
                serial: config.soa.serial,
                refresh: config.soa.refresh,
                retry: config.soa.retry,
                expire: config.soa.expire,
                minimum: config.soa.minimum,
            },
        };
        let mut rrsets: HashMap<(DnsName, RecordType), Vec<DnsRecord>> = HashMap::new();
        let mut names: HashSet<DnsName> = HashSet::new();
        names.insert(apex.clone());
        rrsets.insert((apex.clone(), RecordType::SOA), vec![soa_record.clone()]);

        for (owner, typed_sets) in &config.records {
            let owner_name = Self::owner_name(owner, &apex)?;
            names.insert(owner_name.clone());

            for (record_type, rrset) in typed_sets {
                let parsed_type = Self::parse_record_type(record_type)?;
                let records =
                    Self::parse_rrset(&owner_name, parsed_type, rrset.ttl, &rrset.values)?;
                rrsets
                    .entry((owner_name.clone(), parsed_type))
                    .or_default()
                    .extend(records);
            }
        }
        let dnssec_enabled = config.dnssec.as_ref().is_some_and(|dnssec| dnssec.enabled);
        if dnssec_enabled {
            Self::sign_zone(config, &apex, &mut rrsets, &mut names)?;
        }

        Ok(Self {
            apex_ascii,
            soa_record,
            rrsets,
            names,
            dnssec_enabled,
        })
    }

    fn owner_name(owner: &str, zone_name: &DnsName) -> DynResult<DnsName> {
        if owner == "@" || owner.is_empty() {
            return Ok(zone_name.clone());
        }
        if owner.ends_with('.') {
            return Ok(DnsName::parse_ascii(owner)?);
        }
        Ok(DnsName::parse_ascii(&format!(
            "{owner}.{}",
            zone_name.to_ascii()
        ))?)
    }

    fn parse_record_type(record_type: &str) -> DynResult<RecordType> {
        match record_type.to_ascii_uppercase().as_str() {
            "A" => Ok(RecordType::A),
            "AAAA" => Ok(RecordType::AAAA),
            "TXT" => Ok(RecordType::TXT),
            "SRV" => Ok(RecordType::SRV),
            "NS" => Ok(RecordType::NS),
            "SOA" => Ok(RecordType::SOA),
            "CNAME" => Ok(RecordType::CNAME),
            "MX" => Ok(RecordType::MX),
            "PTR" => Ok(RecordType::PTR),
            "CAA" => Ok(RecordType::CAA),
            "SVCB" => Ok(RecordType::SVCB),
            "HTTPS" => Ok(RecordType::HTTPS),
            "DS" => Ok(RecordType::DS),
            other => Err(format!("unsupported authoritative record type: {other}").into()),
        }
    }

    fn parse_rrset(
        owner: &DnsName,
        record_type: RecordType,
        ttl: u32,
        values: &[String],
    ) -> DynResult<Vec<DnsRecord>> {
        if values.is_empty() {
            return Err(format!(
                "authoritative rrset {} {} must include at least one value",
                owner.to_ascii(),
                record_type
            )
            .into());
        }

        values
            .iter()
            .map(|value| {
                let data = super::zone_records::parse(record_type, value)?;
                Ok(DnsRecord {
                    name: owner.clone(),
                    ttl,
                    class: DnsClass::IN,
                    data,
                })
            })
            .collect()
    }

    fn records_for_name(&self, owner: &DnsName) -> Vec<DnsRecord> {
        self.rrsets
            .iter()
            .filter(|((record_owner, _), _)| record_owner == owner)
            .flat_map(|(_, records)| records.iter().cloned())
            .collect()
    }

    fn rrsig_for(&self, owner: &DnsName, record_type: RecordType) -> Vec<DnsRecord> {
        self.rrsets
            .get(&(owner.clone(), RecordType::RRSIG))
            .into_iter()
            .flat_map(|records| records.iter())
            .filter(|record| {
                matches!(
                    &record.data,
                    RData::RRSIG { type_covered, .. } if *type_covered == record_type
                )
            })
            .cloned()
            .collect()
    }

    fn denial_records_for_name(&self, qname: &DnsName) -> Vec<DnsRecord> {
        if !self.dnssec_enabled {
            return Vec::new();
        }
        let owner = if self.names.contains(qname) {
            qname
        } else {
            self.names.iter().next().unwrap_or(qname)
        };
        let mut records = self
            .rrsets
            .get(&(owner.clone(), RecordType::NSEC))
            .cloned()
            .unwrap_or_default();
        records.extend(self.rrsig_for(owner, RecordType::NSEC));
        records
    }

    fn sign_zone(
        config: &ZoneConfig,
        apex: &DnsName,
        rrsets: &mut HashMap<(DnsName, RecordType), Vec<DnsRecord>>,
        names: &mut HashSet<DnsName>,
    ) -> DynResult<()> {
        let dnssec = config.dnssec.as_ref().ok_or("dnssec config missing")?;
        let ksk_key = SigningKey::from_bytes(&decode_dnssec_ed25519_key_file(
            &dnssec.ksk_secret_key_path,
            "zones[].dnssec.ksk_secret_key_path",
        )?);
        let zsk_key = SigningKey::from_bytes(&decode_dnssec_ed25519_key_file(
            &dnssec.zsk_secret_key_path,
            "zones[].dnssec.zsk_secret_key_path",
        )?);
        let signature_ttl = dnssec.signature_ttl.unwrap_or(config.soa.ttl);
        let dnskey_ttl = config.soa.ttl;
        let ksk_dnskey = dnskey_record(apex, dnskey_ttl, 257, &ksk_key);
        let zsk_dnskey = dnskey_record(apex, dnskey_ttl, 256, &zsk_key);
        rrsets.insert(
            (apex.clone(), RecordType::DNSKEY),
            vec![ksk_dnskey.clone(), zsk_dnskey.clone()],
        );
        names.insert(apex.clone());
        add_nsec_records(rrsets, names, config.soa.ttl)?;
        let signing_plan: Vec<((DnsName, RecordType), Vec<DnsRecord>)> = rrsets
            .iter()
            .filter(|((_, record_type), _)| *record_type != RecordType::RRSIG)
            .map(|(key, records)| (key.clone(), records.clone()))
            .collect();
        for ((owner, record_type), records) in signing_plan {
            let signers: Vec<(&SigningKey, u16)> = if record_type == RecordType::DNSKEY {
                vec![
                    (&ksk_key, key_tag(&ksk_dnskey)?),
                    (&zsk_key, key_tag(&zsk_dnskey)?),
                ]
            } else {
                vec![(&zsk_key, key_tag(&zsk_dnskey)?)]
            };
            for (signer, tag) in signers {
                let signature = sign_rrset(
                    &owner,
                    record_type,
                    &records,
                    apex,
                    signer,
                    tag,
                    signature_ttl,
                    dnssec.valid_from,
                    dnssec.valid_until,
                )?;
                rrsets
                    .entry((owner.clone(), RecordType::RRSIG))
                    .or_default()
                    .push(signature);
            }
        }
        Ok(())
    }
}

const DNSSEC_ALGORITHM_ED25519: u8 = 15;

fn dnskey_record(owner: &DnsName, ttl: u32, flags: u16, key: &SigningKey) -> DnsRecord {
    DnsRecord {
        name: owner.clone(),
        ttl,
        class: DnsClass::IN,
        data: RData::DNSKEY {
            flags,
            protocol: 3,
            algorithm: DNSSEC_ALGORITHM_ED25519,
            public_key: VerifyingKey::from(key).to_bytes().to_vec(),
        },
    }
}

fn key_tag(record: &DnsRecord) -> DynResult<u16> {
    let rdata = record_rdata_wire(record)?;
    let mut ac = 0u32;
    for (i, byte) in rdata.iter().enumerate() {
        ac += if i & 1 == 0 {
            u32::from(*byte) << 8
        } else {
            u32::from(*byte)
        };
    }
    ac += (ac >> 16) & 0xffff;
    Ok((ac & 0xffff) as u16)
}

fn add_nsec_records(
    rrsets: &mut HashMap<(DnsName, RecordType), Vec<DnsRecord>>,
    names: &HashSet<DnsName>,
    ttl: u32,
) -> DynResult<()> {
    let mut ordered: Vec<DnsName> = names.iter().cloned().collect();
    ordered.sort_by_key(|name| canonical_name_key(name));
    for (idx, owner) in ordered.iter().enumerate() {
        let next = ordered[(idx + 1) % ordered.len()].clone();
        let mut types: Vec<RecordType> = rrsets
            .keys()
            .filter_map(|(name, record_type)| (name == owner).then_some(*record_type))
            .collect();
        types.push(RecordType::NSEC);
        types.push(RecordType::RRSIG);
        types.sort_by_key(|record_type| record_type.code());
        types.dedup();
        rrsets.insert(
            (owner.clone(), RecordType::NSEC),
            vec![DnsRecord {
                name: owner.clone(),
                ttl,
                class: DnsClass::IN,
                data: RData::NSEC {
                    next_domain: next,
                    type_bit_maps: type_bit_maps(&types)?,
                },
            }],
        );
    }
    Ok(())
}

fn sign_rrset(
    owner: &DnsName,
    record_type: RecordType,
    records: &[DnsRecord],
    signer_name: &DnsName,
    signing_key: &SigningKey,
    key_tag: u16,
    signature_ttl: u32,
    inception: u32,
    expiration: u32,
) -> DynResult<DnsRecord> {
    let original_ttl = records.first().map_or(signature_ttl, |record| record.ttl);
    let labels = label_count(owner);
    let mut signed = rrsig_signed_prefix(
        record_type,
        DNSSEC_ALGORITHM_ED25519,
        labels,
        original_ttl,
        expiration,
        inception,
        key_tag,
        signer_name,
    )?;
    let mut canonical_records: Vec<Vec<u8>> = records
        .iter()
        .map(|record| canonical_record_wire(record, original_ttl))
        .collect::<DynResult<Vec<_>>>()?;
    canonical_records.sort();
    for record in canonical_records {
        signed.extend_from_slice(&record);
    }
    let signature = signing_key.sign(&signed).to_bytes().to_vec();
    Ok(DnsRecord {
        name: owner.clone(),
        ttl: signature_ttl,
        class: DnsClass::IN,
        data: RData::RRSIG {
            type_covered: record_type,
            algorithm: DNSSEC_ALGORITHM_ED25519,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name: signer_name.clone(),
            signature,
        },
    })
}

fn rrsig_signed_prefix(
    type_covered: RecordType,
    algorithm: u8,
    labels: u8,
    original_ttl: u32,
    expiration: u32,
    inception: u32,
    key_tag: u16,
    signer_name: &DnsName,
) -> DynResult<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&type_covered.code().to_be_bytes());
    out.push(algorithm);
    out.push(labels);
    out.extend_from_slice(&original_ttl.to_be_bytes());
    out.extend_from_slice(&expiration.to_be_bytes());
    out.extend_from_slice(&inception.to_be_bytes());
    out.extend_from_slice(&key_tag.to_be_bytes());
    signer_name.emit(&mut out)?;
    Ok(out)
}

fn canonical_record_wire(record: &DnsRecord, original_ttl: u32) -> DynResult<Vec<u8>> {
    let mut clone = record.clone();
    clone.ttl = original_ttl;
    Ok(clone.to_wire()?)
}

fn record_rdata_wire(record: &DnsRecord) -> DynResult<Vec<u8>> {
    let wire = record.to_wire()?;
    let mut decoder = crate::dns::wire::DnsDecoder::new(&wire);
    let _ = DnsName::read(&mut decoder)?;
    let _ = decoder.read_u16()?;
    let _ = decoder.read_u16()?;
    let _ = decoder.read_u32()?;
    let len = usize::from(decoder.read_u16()?);
    Ok(decoder.read_exact(len)?.to_vec())
}

fn type_bit_maps(types: &[RecordType]) -> DynResult<Vec<u8>> {
    let mut by_window: HashMap<u8, Vec<u8>> = HashMap::new();
    for record_type in types {
        let code = record_type.code();
        let window = (code / 256) as u8;
        let offset = (code % 256) as u8;
        let octet = usize::from(offset / 8);
        let bit = offset % 8;
        let bitmap = by_window.entry(window).or_default();
        if bitmap.len() <= octet {
            bitmap.resize(octet + 1, 0);
        }
        bitmap[octet] |= 1 << (7 - bit);
    }
    let mut windows: Vec<(u8, Vec<u8>)> = by_window.into_iter().collect();
    windows.sort_by_key(|(window, _)| *window);
    let mut out = Vec::new();
    for (window, mut bitmap) in windows {
        while bitmap.last() == Some(&0) {
            bitmap.pop();
        }
        let len = u8::try_from(bitmap.len()).map_err(|_| "NSEC bitmap window too large")?;
        out.push(window);
        out.push(len);
        out.extend_from_slice(&bitmap);
    }
    Ok(out)
}

fn canonical_name_key(name: &DnsName) -> Vec<u8> {
    name.to_ascii().to_ascii_lowercase().into_bytes()
}

fn label_count(name: &DnsName) -> u8 {
    let ascii = name.to_ascii();
    let trimmed = ascii.trim_end_matches('.');
    if trimmed.is_empty() {
        0
    } else {
        trimmed.split('.').count().try_into().unwrap_or(u8::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ZoneDnsSecConfig, ZoneRecordSetConfig, ZoneSoaConfig};
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use std::collections::BTreeMap;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn zone_config() -> ZoneConfig {
        let mut apex_records = BTreeMap::new();
        apex_records.insert(
            "NS".to_string(),
            ZoneRecordSetConfig {
                ttl: 3600,
                values: vec!["ns1.example.test.".to_string()],
            },
        );

        let mut api_records = BTreeMap::new();
        api_records.insert(
            "A".to_string(),
            ZoneRecordSetConfig {
                ttl: 300,
                values: vec!["192.0.2.10".to_string()],
            },
        );

        let mut records = BTreeMap::new();
        records.insert("@".to_string(), apex_records);
        records.insert("api".to_string(), api_records);

        ZoneConfig {
            name: "example.test.".to_string(),
            soa: ZoneSoaConfig {
                mname: "ns1.example.test.".to_string(),
                rname: "admin.example.test.".to_string(),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 1209600,
                minimum: 300,
                ttl: 3600,
            },
            records,
            dnssec: None,
        }
    }

    fn unique_temp_path(prefix: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
    }

    fn write_key(prefix: &str, key: [u8; 32]) -> std::path::PathBuf {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;

        let path = unique_temp_path(prefix);
        fs::write(&path, STANDARD.encode(key)).expect("write key");
        path
    }

    #[test]
    fn resolve_question_returns_authoritative_answer() {
        let zones = AuthoritativeZones::from_configs(&[zone_config()]).expect("valid zone");
        let query = DnsQuestion {
            name: DnsName::parse_ascii("api.example.test.").expect("valid qname"),
            record_type: RecordType::A,
            class: DnsClass::IN,
        };

        let lookup = zones
            .resolve_question(&query)
            .expect("zone should answer query");

        assert_eq!(lookup.response_code, ResponseCode::NoError);
        assert_eq!(lookup.answers.len(), 1);
        assert_eq!(lookup.answers[0].name.to_ascii(), "api.example.test.");
        assert_eq!(lookup.answers[0].record_type(), RecordType::A);
        assert!(lookup.authorities.is_empty());
    }

    #[test]
    fn resolve_question_returns_soa_for_name_error() {
        let zones = AuthoritativeZones::from_configs(&[zone_config()]).expect("valid zone");
        let query = DnsQuestion {
            name: DnsName::parse_ascii("missing.example.test.").expect("valid qname"),
            record_type: RecordType::A,
            class: DnsClass::IN,
        };

        let lookup = zones
            .resolve_question(&query)
            .expect("zone should answer query");

        assert_eq!(lookup.response_code, ResponseCode::NXDomain);
        assert!(lookup.answers.is_empty());
        assert_eq!(lookup.authorities.len(), 1);
        assert_eq!(lookup.authorities[0].record_type(), RecordType::SOA);
    }

    #[test]
    fn parses_new_authoritative_record_types() {
        let mut records = BTreeMap::new();
        records.insert(
            "alias".to_string(),
            BTreeMap::from([(
                "CNAME".to_string(),
                ZoneRecordSetConfig {
                    ttl: 300,
                    values: vec!["api.example.test.".to_string()],
                },
            )]),
        );
        records.insert(
            "mail".to_string(),
            BTreeMap::from([(
                "MX".to_string(),
                ZoneRecordSetConfig {
                    ttl: 300,
                    values: vec!["10 mail.example.test.".to_string()],
                },
            )]),
        );
        records.insert(
            "ptr".to_string(),
            BTreeMap::from([(
                "PTR".to_string(),
                ZoneRecordSetConfig {
                    ttl: 300,
                    values: vec!["api.example.test.".to_string()],
                },
            )]),
        );
        records.insert(
            "@".to_string(),
            BTreeMap::from([
                (
                    "CAA".to_string(),
                    ZoneRecordSetConfig {
                        ttl: 300,
                        values: vec!["0 issue ca.example".to_string()],
                    },
                ),
                (
                    "SVCB".to_string(),
                    ZoneRecordSetConfig {
                        ttl: 300,
                        values: vec![
                            "1 svc.example.test. alpn=h2,h3 port=8443 ipv4hint=192.0.2.10"
                                .to_string(),
                        ],
                    },
                ),
                (
                    "HTTPS".to_string(),
                    ZoneRecordSetConfig {
                        ttl: 300,
                        values: vec!["1 . alpn=h3 no-default-alpn".to_string()],
                    },
                ),
                (
                    "DS".to_string(),
                    ZoneRecordSetConfig {
                        ttl: 300,
                        values: vec!["12345 15 2 aabbccdd".to_string()],
                    },
                ),
            ]),
        );
        let mut config = zone_config();
        config.records.extend(records);

        let zones = AuthoritativeZones::from_configs(&[config]).expect("valid zone");
        for (name, record_type) in [
            ("alias.example.test.", RecordType::CNAME),
            ("mail.example.test.", RecordType::MX),
            ("ptr.example.test.", RecordType::PTR),
            ("example.test.", RecordType::CAA),
            ("example.test.", RecordType::SVCB),
            ("example.test.", RecordType::HTTPS),
            ("example.test.", RecordType::DS),
        ] {
            let lookup = zones
                .resolve_question(&DnsQuestion {
                    name: DnsName::parse_ascii(name).expect("name"),
                    record_type,
                    class: DnsClass::IN,
                })
                .expect("answer");
            assert_eq!(lookup.answers[0].record_type(), record_type);
        }
    }

    #[test]
    fn rejects_duplicate_svcb_parameters() {
        let mut config = zone_config();
        config.records.insert(
            "@".to_string(),
            BTreeMap::from([(
                "HTTPS".to_string(),
                ZoneRecordSetConfig {
                    ttl: 300,
                    values: vec!["1 . port=443 port=8443".to_string()],
                },
            )]),
        );

        let err = match AuthoritativeZones::from_configs(&[config]) {
            Ok(_) => panic!("should fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("duplicate SVCB parameter"));
    }

    #[test]
    fn cname_query_returns_cname_and_in_zone_target_answer() {
        let mut config = zone_config();
        config.records.insert(
            "alias".to_string(),
            BTreeMap::from([(
                "CNAME".to_string(),
                ZoneRecordSetConfig {
                    ttl: 300,
                    values: vec!["api.example.test.".to_string()],
                },
            )]),
        );
        let zones = AuthoritativeZones::from_configs(&[config]).expect("valid zone");

        let lookup = zones
            .resolve_question(&DnsQuestion {
                name: DnsName::parse_ascii("alias.example.test.").expect("name"),
                record_type: RecordType::A,
                class: DnsClass::IN,
            })
            .expect("answer");

        assert_eq!(lookup.answers.len(), 2);
        assert_eq!(lookup.answers[0].record_type(), RecordType::CNAME);
        assert_eq!(lookup.answers[1].record_type(), RecordType::A);
    }

    #[test]
    fn dnssec_generates_dnskey_rrsig_and_nsec_records() {
        let ksk = write_key("dnssec-ksk", [1u8; 32]);
        let zsk = write_key("dnssec-zsk", [2u8; 32]);
        let mut config = zone_config();
        config.dnssec = Some(ZoneDnsSecConfig {
            enabled: true,
            algorithm: "ED25519".to_string(),
            ksk_secret_key_path: ksk.display().to_string(),
            zsk_secret_key_path: zsk.display().to_string(),
            valid_from: 1_800_000_000,
            valid_until: 1_800_086_400,
            signature_ttl: Some(600),
        });
        let zones = AuthoritativeZones::from_configs(&[config]).expect("signed zone");
        let _ = fs::remove_file(ksk);
        let _ = fs::remove_file(zsk);
        let zone = zones
            .find_zone(&DnsName::parse_ascii("example.test.").expect("name"))
            .unwrap();

        let dnskeys = zone
            .rrsets
            .get(&(
                DnsName::parse_ascii("example.test.").unwrap(),
                RecordType::DNSKEY,
            ))
            .expect("dnskey rrset");
        assert_eq!(dnskeys.len(), 2);
        let rrsigs = zone
            .rrsets
            .get(&(
                DnsName::parse_ascii("example.test.").unwrap(),
                RecordType::RRSIG,
            ))
            .expect("rrsig rrset");
        assert!(rrsigs.iter().any(|record| matches!(
            record.data,
            RData::RRSIG {
                type_covered: RecordType::DNSKEY,
                ..
            }
        )));
        let nsec = zone
            .rrsets
            .get(&(
                DnsName::parse_ascii("example.test.").unwrap(),
                RecordType::NSEC,
            ))
            .expect("nsec rrset");
        assert_eq!(nsec.len(), 1);
    }

    #[test]
    fn dnssec_rrsig_verifies_with_dnskey_public_key() {
        let ksk = write_key("dnssec-verify-ksk", [3u8; 32]);
        let zsk = write_key("dnssec-verify-zsk", [4u8; 32]);
        let mut config = zone_config();
        config.dnssec = Some(ZoneDnsSecConfig {
            enabled: true,
            algorithm: "ED25519".to_string(),
            ksk_secret_key_path: ksk.display().to_string(),
            zsk_secret_key_path: zsk.display().to_string(),
            valid_from: 1_800_000_000,
            valid_until: 1_800_086_400,
            signature_ttl: Some(600),
        });
        let zones = AuthoritativeZones::from_configs(&[config]).expect("signed zone");
        let _ = fs::remove_file(ksk);
        let _ = fs::remove_file(zsk);
        let owner = DnsName::parse_ascii("api.example.test.").unwrap();
        let zone = zones.find_zone(&owner).unwrap();
        let records = zone
            .rrsets
            .get(&(owner.clone(), RecordType::A))
            .expect("a rrset");
        let rrsig = zone
            .rrsig_for(&owner, RecordType::A)
            .into_iter()
            .next()
            .expect("a rrsig");
        let RData::RRSIG {
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag: signature_key_tag,
            signer_name,
            signature,
            ..
        } = &rrsig.data
        else {
            panic!("expected rrsig");
        };
        let dnskeys = zone
            .rrsets
            .get(&(
                DnsName::parse_ascii("example.test.").unwrap(),
                RecordType::DNSKEY,
            ))
            .expect("dnskey rrset");
        let zsk_dnskey = dnskeys
            .iter()
            .find(|record| matches!(record.data, RData::DNSKEY { flags: 256, .. }))
            .expect("zsk dnskey");
        assert_eq!(*signature_key_tag, key_tag(zsk_dnskey).expect("key tag"));
        let RData::DNSKEY { public_key, .. } = &zsk_dnskey.data else {
            panic!("expected dnskey");
        };
        let verifying_key = VerifyingKey::from_bytes(
            public_key
                .as_slice()
                .try_into()
                .expect("32 byte public key"),
        )
        .expect("verifying key");
        let mut signed = rrsig_signed_prefix(
            RecordType::A,
            *algorithm,
            *labels,
            *original_ttl,
            *expiration,
            *inception,
            *signature_key_tag,
            signer_name,
        )
        .expect("prefix");
        for record in records {
            signed.extend_from_slice(&canonical_record_wire(record, *original_ttl).expect("wire"));
        }
        verifying_key
            .verify(
                &signed,
                &Signature::from_slice(signature).expect("signature"),
            )
            .expect("signature verifies");
    }

    #[test]
    fn dnssec_denial_includes_nsec_and_rrsig() {
        let ksk = write_key("dnssec-denial-ksk", [5u8; 32]);
        let zsk = write_key("dnssec-denial-zsk", [6u8; 32]);
        let mut config = zone_config();
        config.dnssec = Some(ZoneDnsSecConfig {
            enabled: true,
            algorithm: "ED25519".to_string(),
            ksk_secret_key_path: ksk.display().to_string(),
            zsk_secret_key_path: zsk.display().to_string(),
            valid_from: 1_800_000_000,
            valid_until: 1_800_086_400,
            signature_ttl: Some(600),
        });
        let zones = AuthoritativeZones::from_configs(&[config]).expect("signed zone");
        let _ = fs::remove_file(ksk);
        let _ = fs::remove_file(zsk);

        let lookup = zones
            .resolve_question(&DnsQuestion {
                name: DnsName::parse_ascii("missing.example.test.").expect("name"),
                record_type: RecordType::A,
                class: DnsClass::IN,
            })
            .expect("answer");

        assert_eq!(lookup.response_code, ResponseCode::NXDomain);
        assert!(
            lookup
                .authorities
                .iter()
                .any(|record| record.record_type() == RecordType::NSEC)
        );
        assert!(
            lookup
                .authorities
                .iter()
                .any(|record| record.record_type() == RecordType::RRSIG)
        );
    }
}
