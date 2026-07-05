use super::DynResult;
use crate::config::ZoneConfig;
use crate::dns::{DnsClass, DnsName, DnsQuestion, DnsRecord, RData, RecordType, ResponseCode};
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
            return Some(AuthoritativeLookup {
                response_code: ResponseCode::NoError,
                answers: records.clone(),
                authorities: vec![],
            });
        }

        if zone.names.contains(qname) {
            Some(AuthoritativeLookup {
                response_code: ResponseCode::NoError,
                answers: vec![],
                authorities: vec![zone.soa_record.clone()],
            })
        } else {
            Some(AuthoritativeLookup {
                response_code: ResponseCode::NXDomain,
                answers: vec![],
                authorities: vec![zone.soa_record.clone()],
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

        Ok(Self {
            apex_ascii,
            soa_record,
            rrsets,
            names,
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
                let data = Self::parse_rdata(record_type, value)?;
                Ok(DnsRecord {
                    name: owner.clone(),
                    ttl,
                    class: DnsClass::IN,
                    data,
                })
            })
            .collect()
    }

    fn parse_rdata(record_type: RecordType, value: &str) -> DynResult<RData> {
        match record_type {
            RecordType::A => Ok(RData::A(value.parse()?)),
            RecordType::AAAA => Ok(RData::AAAA(value.parse()?)),
            RecordType::TXT => Ok(RData::TXT(vec![value.as_bytes().to_vec()])),
            RecordType::NS => Ok(RData::NS(DnsName::parse_ascii(value)?)),
            RecordType::SRV => {
                let parts: Vec<&str> = value.split_whitespace().collect();
                if parts.len() != 4 {
                    return Err(format!(
                        "invalid SRV value '{value}', expected: '<priority> <weight> <port> <target>'"
                    )
                    .into());
                }
                Ok(RData::SRV {
                    priority: parts[0].parse()?,
                    weight: parts[1].parse()?,
                    port: parts[2].parse()?,
                    target: DnsName::parse_ascii(parts[3])?,
                })
            }
            RecordType::SOA => Err("SOA records must be configured in zone.soa".into()),
            other => {
                Err(format!("unsupported record type in authoritative parser: {other}").into())
            }
        }
    }

    fn records_for_name(&self, owner: &DnsName) -> Vec<DnsRecord> {
        self.rrsets
            .iter()
            .filter(|((record_owner, _), _)| record_owner == owner)
            .flat_map(|(_, records)| records.iter().cloned())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ZoneRecordSetConfig, ZoneSoaConfig};
    use std::collections::BTreeMap;

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
        }
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
}
