use std::io;

const B32_STD: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const B32_HEX: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

pub fn encode(input: &[u8]) -> String {
    encode_inner(input, B32_STD, true)
}

pub fn decode(input: &str) -> io::Result<Vec<u8>> {
    decode_inner(input, B32_STD, true)
}

pub fn hex_encode_nopad(input: &[u8]) -> String {
    encode_inner(input, B32_HEX, false)
}

pub fn hex_decode(input: &str) -> io::Result<Vec<u8>> {
    decode_inner(input, B32_HEX, true)
}

fn encode_inner(input: &[u8], table: &[u8; 32], pad: bool) -> String {
    let mut out = String::new();
    let mut i = 0;

    while i + 5 <= input.len() {
        let b1 = input[i];
        let b2 = input[i + 1];
        let b3 = input[i + 2];
        let b4 = input[i + 3];
        let b5 = input[i + 4];

        out.push(table[(b1 >> 3) as usize] as char);
        out.push(table[((b1 & 0x07) << 2 | (b2 >> 6)) as usize] as char);
        out.push(table[((b2 >> 1) & 0x1F) as usize] as char);
        out.push(table[((b2 & 0x01) << 4 | (b3 >> 4)) as usize] as char);
        out.push(table[((b3 & 0x0F) << 1 | (b4 >> 7)) as usize] as char);
        out.push(table[((b4 >> 2) & 0x1F) as usize] as char);
        out.push(table[((b4 & 0x03) << 3 | (b5 >> 5)) as usize] as char);
        out.push(table[(b5 & 0x1F) as usize] as char);

        i += 5;
    }

    let rem = input.len() - i;
    if rem > 0 {
        let b1 = input[i];
        let b2 = if rem >= 2 { input[i + 1] } else { 0 };
        let b3 = if rem >= 3 { input[i + 2] } else { 0 };
        let b4 = if rem >= 4 { input[i + 3] } else { 0 };

        match rem {
            1 => {
                out.push(table[(b1 >> 3) as usize] as char);
                out.push(table[((b1 & 0x07) << 2) as usize] as char);
                if pad { out.push_str("======"); }
            }
            2 => {
                out.push(table[(b1 >> 3) as usize] as char);
                out.push(table[((b1 & 0x07) << 2 | (b2 >> 6)) as usize] as char);
                out.push(table[((b2 >> 1) & 0x1F) as usize] as char);
                out.push(table[((b2 & 0x01) << 4) as usize] as char);
                if pad { out.push_str("===="); }
            }
            3 => {
                out.push(table[(b1 >> 3) as usize] as char);
                out.push(table[((b1 & 0x07) << 2 | (b2 >> 6)) as usize] as char);
                out.push(table[((b2 >> 1) & 0x1F) as usize] as char);
                out.push(table[((b2 & 0x01) << 4 | (b3 >> 4)) as usize] as char);
                out.push(table[((b3 & 0x0F) << 1) as usize] as char);
                if pad { out.push_str("==="); }
            }
            4 => {
                out.push(table[(b1 >> 3) as usize] as char);
                out.push(table[((b1 & 0x07) << 2 | (b2 >> 6)) as usize] as char);
                out.push(table[((b2 >> 1) & 0x1F) as usize] as char);
                out.push(table[((b2 & 0x01) << 4 | (b3 >> 4)) as usize] as char);
                out.push(table[((b3 & 0x0F) << 1 | (b4 >> 7)) as usize] as char);
                out.push(table[((b4 >> 2) & 0x1F) as usize] as char);
                out.push(table[((b4 & 0x03) << 3) as usize] as char);
                if pad { out.push('='); }
            }
            _ => unreachable!(),
        }
    }

    out
}

fn decode_inner(input: &str, table: &[u8; 32], accept_pad: bool) -> io::Result<Vec<u8>> {
    // Build decode map for chosen alphabet; accept lowercase
    let mut map = [255u8; 256];
    for (i, &c) in table.iter().enumerate() {
        map[c as usize] = i as u8;
        if c.is_ascii_uppercase() {
            map[(c as char).to_ascii_lowercase() as usize] = i as u8;
        }
    }
    if accept_pad {
        map[b'=' as usize] = 0;
    }

    let mut acc: u32 = 0;
    let mut bits: u8 = 0;
    let mut out = Vec::new();

    for &ch in input.as_bytes().iter().filter(|&&b| !b" \t\r\n".contains(&b)) {
        if accept_pad && ch == b'=' {
            break; // padding ends stream
        }
        let v = map.get(ch as usize).copied().unwrap_or(255);
        if v == 255 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid base32 symbol"));
        }
        acc = (acc << 5) | (v as u32);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}
