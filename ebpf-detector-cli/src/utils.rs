pub fn format_ip(ip: u32) -> String {
    let bytes = ip.to_be_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

pub fn parse_ip(ip_str: &str) -> anyhow::Result<u32> {
    let parts: Vec<&str> = ip_str.split('.').collect();
    if parts.len() != 4 {
        anyhow::bail!("Invalid IP address format");
    }

    let mut bytes = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] = part.parse()?;
    }

    Ok(u32::from_be_bytes(bytes))
}

