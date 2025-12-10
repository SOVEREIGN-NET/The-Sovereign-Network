use std::io;

pub fn to_octal(n: u16) -> String {
    if n == 0 {
        return "00".to_string();
    }

    let mut tmp = n;
    let mut rev = Vec::with_capacity(6);

    while tmp > 0 {
        let d = (tmp & 0b111) as u8;
        rev.push(b'0' + d);
        tmp >>= 3;
    }

    let mut out = String::with_capacity(rev.len() + 1);
    out.push('0');
    for &b in rev.iter().rev() {
        out.push(b as char);
    }
    out
}

pub fn from_octal(input: &str) -> io::Result<u16> {
    let mut s = input.trim();

    if let Some(rest) = s.strip_prefix("0o").or_else(|| s.strip_prefix("0O")) {
        s = rest;
    } else if s.len() > 1 && s.starts_with('0') {
        s = &s[1..];
    }

    if s.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty octal string"));
    }

    let mut val: u16 = 0;
    for &c in s.as_bytes() {
        let d = oct_val(c).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid octal digit"))?;
        val = val
            .checked_mul(8)
            .and_then(|v| v.checked_add(d as u16))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "octal value out of u16 range"))?;
    }

    Ok(val)
}

fn oct_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'7' => Some(c - b'0'),
        _ => None,
    }
}
