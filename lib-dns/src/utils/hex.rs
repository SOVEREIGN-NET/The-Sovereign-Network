use std::io;

pub fn encode(input: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::new();
    for &byte in input {
        output.push(HEX_CHARS[(byte >> 4) as usize] as char);
        output.push(HEX_CHARS[(byte & 0x0F) as usize] as char);
    }

    output
}

pub fn decode(input: &str) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let buf = input.as_bytes();
    let mut i = 0;

    while i + 1 < buf.len() {
        let v1 = val(buf[i]).ok_or(io::Error::new(io::ErrorKind::InvalidInput, "Invalid hex"))?;
        let v2 = val(buf[i + 1]).ok_or(io::Error::new(io::ErrorKind::InvalidInput, "Invalid hex"))?;

        output.push((v1 << 4) | v2);

        i += 2;
    }

    Ok(output)
}

fn val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
