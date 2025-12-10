use std::io;

pub fn encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut output = String::new();
    let mut i = 0;

    while i + 3 <= input.len() {
        let b1 = input[i];
        let b2 = input[i + 1];
        let b3 = input[i + 2];

        output.push(TABLE[(b1 >> 2) as usize] as char);
        output.push(TABLE[((b1 & 0x03) << 4 | (b2 >> 4)) as usize] as char);
        output.push(TABLE[((b2 & 0x0F) << 2 | (b3 >> 6)) as usize] as char);
        output.push(TABLE[(b3 & 0x3F) as usize] as char);

        i += 3;
    }

    let rem = input.len() - i;
    if rem == 1 {
        let b1 = input[i];
        output.push(TABLE[(b1 >> 2) as usize] as char);
        output.push(TABLE[((b1 & 0x03) << 4) as usize] as char);
        output.push('=');
        output.push('=');

    } else if rem == 2 {
        let b1 = input[i];
        let b2 = input[i + 1];
        output.push(TABLE[(b1 >> 2) as usize] as char);
        output.push(TABLE[((b1 & 0x03) << 4 | (b2 >> 4)) as usize] as char);
        output.push(TABLE[((b2 & 0x0F) << 2) as usize] as char);
        output.push('=');
    }

    output
}

pub fn decode(input: &str) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let buf = input.as_bytes();
    let mut i = 0;

    while i + 3 < buf.len() {
        let v1 = val(buf[i]).ok_or(io::Error::new(io::ErrorKind::InvalidInput, "invalid base64"))?;
        let v2 = val(buf[i + 1]).ok_or(io::Error::new(io::ErrorKind::InvalidInput, "invalid base64"))?;
        let v3 = val(buf[i + 2]).ok_or(io::Error::new(io::ErrorKind::InvalidInput, "invalid base64"))?;
        let v4 = val(buf[i + 3]).ok_or(io::Error::new(io::ErrorKind::InvalidInput, "invalid base64"))?;

        output.push((v1 << 2) | (v2 >> 4));
        if buf[i + 2] != b'=' {
            output.push((v2 << 4) | (v3 >> 2));
        }
        if buf[i + 3] != b'=' {
            output.push((v3 << 6) | v4);
        }

        i += 4;
    }

    Ok(output)
}

fn val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        b'=' => Some(0),
        _ => None,
    }
}
