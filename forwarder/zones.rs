use super::DynResult;
use crate::config::ZoneConfig;
use hickory_server::proto::op::{Query, ResponseCode};
use hickory_server::proto::rr::{
    Name, RData, Record, RecordType,
    rdata::{A, AAAA, NS, SOA, SRV, TXT},
};
use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub(super) struct AuthoritativeZones {
    zones: Vec<AuthoritativeZone>,
}

pub(super) struct AuthoritativeZone {
    pub(super) apex_ascii: String,
    soa_record: Record,
    rrsets: HashMap<(Name, RecordType), Vec<Record>>,
    names: HashSet<Name>,
}

pub(super) struct AuthoritativeLookup {
    pub(super) response_code: ResponseCode,
    pub(super) answers: Vec<Record>,
    pub(super) authorities: Vec<Record>,
}

impl AuthoritativeZones {
    pub(super) fn from_configs(zone_configs: &[ZoneConfig]) -> DynResult<Self> {
        let mut zones = Vec::with_capacity(zone_configs.len());
        for zone_config in zone_configs {
            zones.push(AuthoritativeZone::from_config(zone_config)?);
        }
        Ok(Self { zones })
    }

    pub(super) fn resolve(&self, query: &Query) -> Option<AuthoritativeLookup> {
        let zone = self.find_zone(query.name())?;
        let qname = query.name();
        let qtype = query.query_type();

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

    pub(super) fn find_zone<'a>(&'a self, name: &Name) -> Option<&'a AuthoritativeZone> {
        self.zones
            .iter()
            .filter(|zone| Self::name_in_zone(name, zone))
            .max_by_key(|zone| zone.apex_ascii.len())
    }

    fn name_in_zone(name: &Name, zone: &AuthoritativeZone) -> bool {
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
        let apex = Name::from_ascii(&config.name)?;
        let apex_ascii = apex.to_ascii().to_lowercase();
        let mname = Name::from_ascii(&config.soa.mname)?;
        let rname = Name::from_ascii(&config.soa.rname)?;
        let soa_data = SOA::new(
            mname,
            rname,
            config.soa.serial,
            config.soa.refresh as i32,
            config.soa.retry as i32,
            config.soa.expire as i32,
            config.soa.minimum,
        );
        let soa_record = Record::from_rdata(apex.clone(), config.soa.ttl, RData::SOA(soa_data));
        let mut rrsets: HashMap<(Name, RecordType), Vec<Record>> = HashMap::new();
        let mut names: HashSet<Name> = HashSet::new();
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

    fn owner_name(owner: &str, zone_name: &Name) -> DynResult<Name> {
        if owner == "@" || owner.is_empty() {
            return Ok(zone_name.clone());
        }
        if owner.ends_with('.') {
            return Ok(Name::from_ascii(owner)?);
        }
        Ok(Name::from_ascii(format!(
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
        owner: &Name,
        record_type: RecordType,
        ttl: u32,
        values: &[String],
    ) -> DynResult<Vec<Record>> {
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
                Ok(Record::from_rdata(owner.clone(), ttl, data))
            })
            .collect()
    }

    fn parse_rdata(record_type: RecordType, value: &str) -> DynResult<RData> {
        match record_type {
            RecordType::A => Ok(RData::A(A(value.parse()?))),
            RecordType::AAAA => Ok(RData::AAAA(AAAA(value.parse()?))),
            RecordType::TXT => Ok(RData::TXT(TXT::new(vec![value.to_string()]))),
            RecordType::NS => Ok(RData::NS(NS(Name::from_ascii(value)?))),
            RecordType::SRV => {
                let parts: Vec<&str> = value.split_whitespace().collect();
                if parts.len() != 4 {
                    return Err(format!(
                        "invalid SRV value '{value}', expected: '<priority> <weight> <port> <target>'"
                    )
                    .into());
                }
                Ok(RData::SRV(SRV::new(
                    parts[0].parse()?,
                    parts[1].parse()?,
                    parts[2].parse()?,
                    Name::from_ascii(parts[3])?,
                )))
            }
            RecordType::SOA => Err("SOA records must be configured in zone.soa".into()),
            other => {
                Err(format!("unsupported record type in authoritative parser: {other}").into())
            }
        }
    }

    fn records_for_name(&self, owner: &Name) -> Vec<Record> {
        self.rrsets
            .iter()
            .filter(|((record_owner, _), _)| record_owner == owner)
            .flat_map(|(_, records)| records.iter().cloned())
            .collect()
    }
}
