pub fn extract_device_hint(
    request_edns: Option<&hickory_server::proto::op::Edns>,
) -> Option<Vec<u8>> {
    let edns = request_edns?;
    for (code, option) in edns.options().as_ref() {
        if u16::from(*code) == 10 {
            if let hickory_server::proto::rr::rdata::opt::EdnsOption::Unknown(_, data) = option {
                return Some(data.clone());
            }
        }
    }
    None
}
