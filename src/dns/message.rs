use crate::dns::DnsResult;
use crate::dns::header::{DnsHeader, SectionCounts};
use crate::dns::question::DnsQuestion;
use crate::dns::record::DnsRecord;
use crate::dns::types::{RecordType, ResponseCode};
use crate::dns::wire::{DnsDecoder, read_many, section_len};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

impl DnsMessage {
    pub fn query(id: u16, question: DnsQuestion) -> Self {
        Self {
            header: DnsHeader::query(id),
            questions: vec![question],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    pub fn response_for_request(request: &Self, response_code: ResponseCode) -> Self {
        Self {
            header: DnsHeader::response_from_query(&request.header, response_code),
            questions: request.questions.clone(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    pub fn from_wire(bytes: &[u8]) -> DnsResult<Self> {
        let mut decoder = DnsDecoder::new(bytes);
        let (header, counts) = DnsHeader::read(&mut decoder)?;
        let questions = read_many(counts.questions, &mut decoder, DnsQuestion::read)?;
        let answers = read_many(counts.answers, &mut decoder, DnsRecord::read)?;
        let authorities = read_many(counts.authorities, &mut decoder, DnsRecord::read)?;
        let additionals = read_many(counts.additionals, &mut decoder, DnsRecord::read)?;
        Ok(Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    pub fn to_wire(&self) -> DnsResult<Vec<u8>> {
        let counts = SectionCounts {
            questions: section_len(self.questions.len())?,
            answers: section_len(self.answers.len())?,
            authorities: section_len(self.authorities.len())?,
            additionals: section_len(self.additionals.len())?,
        };
        let mut out = Vec::with_capacity(512);
        self.header.emit(&mut out, counts);
        for question in &self.questions {
            question.emit(&mut out)?;
        }
        for record in &self.answers {
            record.emit(&mut out)?;
        }
        for record in &self.authorities {
            record.emit(&mut out)?;
        }
        for record in &self.additionals {
            record.emit(&mut out)?;
        }
        Ok(out)
    }

    pub fn first_question(&self) -> Option<&DnsQuestion> {
        self.questions.first()
    }

    pub fn edns_dnssec_ok(&self) -> bool {
        self.additionals
            .iter()
            .any(|record| record.record_type() == RecordType::OPT && record.ttl & 0x0000_8000 != 0)
    }
}
