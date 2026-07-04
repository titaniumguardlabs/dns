use crate::dns::name::{validate_label, wire_len};
use crate::dns::{DnsError, DnsResult};

pub(crate) fn read_many<T>(
    count: u16,
    decoder: &mut DnsDecoder<'_>,
    mut read: impl FnMut(&mut DnsDecoder<'_>) -> DnsResult<T>,
) -> DnsResult<Vec<T>> {
    let mut items = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        items.push(read(decoder)?);
    }
    Ok(items)
}

pub(crate) fn section_len(len: usize) -> DnsResult<u16> {
    u16::try_from(len).map_err(|_| DnsError::new("dns section contains too many records"))
}

pub(crate) struct DnsDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DnsDecoder<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn position(&self) -> usize {
        self.offset
    }

    pub(crate) fn set_position(&mut self, offset: usize) -> DnsResult<()> {
        if offset > self.bytes.len() {
            return Err(DnsError::new("decoder offset out of range"));
        }
        self.offset = offset;
        Ok(())
    }

    pub(crate) fn read_u8(&mut self) -> DnsResult<u8> {
        Ok(self.read_exact(1)?[0])
    }

    pub(crate) fn read_u16(&mut self) -> DnsResult<u16> {
        let bytes = self.read_exact(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn read_u32(&mut self) -> DnsResult<u32> {
        let bytes = self.read_exact(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(crate) fn read_exact(&mut self, len: usize) -> DnsResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| DnsError::new("decoder offset overflow"))?;
        if end > self.bytes.len() {
            return Err(DnsError::new("truncated dns message"));
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    pub(crate) fn read_name_labels(
        &mut self,
        mut offset: usize,
        advance: bool,
    ) -> DnsResult<Vec<String>> {
        let mut labels = Vec::new();
        let mut jumped = false;
        let mut jumps = 0usize;
        let start_offset = offset;

        loop {
            if offset >= self.bytes.len() {
                return Err(DnsError::new("truncated dns name"));
            }
            let len = self.bytes[offset];
            match len & 0xc0 {
                0x00 => {
                    offset += 1;
                    if len == 0 {
                        if advance {
                            self.offset = if jumped { start_offset + 2 } else { offset };
                        }
                        return Ok(labels);
                    }
                    let label_len = usize::from(len);
                    if label_len > 63 {
                        return Err(DnsError::new("dns label exceeds 63 octets"));
                    }
                    let end = offset
                        .checked_add(label_len)
                        .ok_or_else(|| DnsError::new("dns name offset overflow"))?;
                    if end > self.bytes.len() {
                        return Err(DnsError::new("truncated dns label"));
                    }
                    let label = std::str::from_utf8(&self.bytes[offset..end])
                        .map_err(|_| DnsError::new("dns label is not utf-8"))?;
                    validate_label(label)?;
                    labels.push(label.to_ascii_lowercase());
                    if wire_len(&labels) > 255 {
                        return Err(DnsError::new("dns name exceeds 255 octets"));
                    }
                    offset = end;
                }
                0xc0 => {
                    if offset + 1 >= self.bytes.len() {
                        return Err(DnsError::new("truncated dns compression pointer"));
                    }
                    let pointer =
                        (usize::from(len & 0x3f) << 8) | usize::from(self.bytes[offset + 1]);
                    if pointer >= self.bytes.len() {
                        return Err(DnsError::new("dns compression pointer out of range"));
                    }
                    jumps += 1;
                    if jumps > self.bytes.len() {
                        return Err(DnsError::new("dns compression pointer loop"));
                    }
                    if !jumped && advance {
                        self.offset = offset + 2;
                    }
                    jumped = true;
                    offset = pointer;
                }
                _ => return Err(DnsError::new("unsupported dns label pointer form")),
            }
        }
    }
}

pub(crate) fn emit_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn emit_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}
