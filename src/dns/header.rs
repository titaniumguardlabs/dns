use crate::dns::DnsResult;
use crate::dns::types::ResponseCode;
use crate::dns::wire::{DnsDecoder, emit_u16};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub response: bool,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub authentic_data: bool,
    pub checking_disabled: bool,
    pub opcode: u8,
    pub response_code: ResponseCode,
}

impl DnsHeader {
    pub fn query(id: u16) -> Self {
        Self {
            id,
            response: false,
            authoritative: false,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
            authentic_data: false,
            checking_disabled: false,
            opcode: 0,
            response_code: ResponseCode::NoError,
        }
    }

    pub fn response_from_query(query: &Self, response_code: ResponseCode) -> Self {
        Self {
            id: query.id,
            response: true,
            authoritative: false,
            truncated: false,
            recursion_desired: query.recursion_desired,
            recursion_available: false,
            authentic_data: false,
            checking_disabled: query.checking_disabled,
            opcode: query.opcode,
            response_code,
        }
    }

    pub(crate) fn read(decoder: &mut DnsDecoder<'_>) -> DnsResult<(Self, SectionCounts)> {
        let id = decoder.read_u16()?;
        let flags = decoder.read_u16()?;
        let counts = SectionCounts {
            questions: decoder.read_u16()?,
            answers: decoder.read_u16()?,
            authorities: decoder.read_u16()?,
            additionals: decoder.read_u16()?,
        };

        Ok((
            Self {
                id,
                response: flags & 0x8000 != 0,
                opcode: ((flags >> 11) & 0x0f) as u8,
                authoritative: flags & 0x0400 != 0,
                truncated: flags & 0x0200 != 0,
                recursion_desired: flags & 0x0100 != 0,
                recursion_available: flags & 0x0080 != 0,
                authentic_data: flags & 0x0020 != 0,
                checking_disabled: flags & 0x0010 != 0,
                response_code: ResponseCode::from_low_bits(flags),
            },
            counts,
        ))
    }

    pub(crate) fn emit(&self, out: &mut Vec<u8>, counts: SectionCounts) {
        emit_u16(out, self.id);
        let mut flags = self.response_code.low_bits();
        if self.response {
            flags |= 0x8000;
        }
        flags |= (u16::from(self.opcode & 0x0f)) << 11;
        if self.authoritative {
            flags |= 0x0400;
        }
        if self.truncated {
            flags |= 0x0200;
        }
        if self.recursion_desired {
            flags |= 0x0100;
        }
        if self.recursion_available {
            flags |= 0x0080;
        }
        if self.authentic_data {
            flags |= 0x0020;
        }
        if self.checking_disabled {
            flags |= 0x0010;
        }
        emit_u16(out, flags);
        emit_u16(out, counts.questions);
        emit_u16(out, counts.answers);
        emit_u16(out, counts.authorities);
        emit_u16(out, counts.additionals);
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SectionCounts {
    pub(crate) questions: u16,
    pub(crate) answers: u16,
    pub(crate) authorities: u16,
    pub(crate) additionals: u16,
}
