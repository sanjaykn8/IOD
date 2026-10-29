//! Minimal standard-alphabet base64 (RFC 4648, padded). Hand-written so the
//! transport adds no dependency; strict decoding (no whitespace, canonical
//! padding) because the input comes from another process.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[n as usize & 63] as char } else { '=' });
    }
    out
}

fn val(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a') as u32 + 26),
        b'0'..=b'9' => Some((c - b'0') as u32 + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode with an output cap (`max_len` bytes) checked BEFORE allocating.
pub fn decode(s: &str, max_len: usize) -> Result<Vec<u8>, &'static str> {
    let b = s.as_bytes();
    if b.len() % 4 != 0 {
        return Err("base64 length not a multiple of 4");
    }
    let pad = b.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return Err("base64 padding too long");
    }
    let out_len = b.len() / 4 * 3 - pad;
    if out_len > max_len {
        return Err("base64 payload exceeds limit");
    }
    let mut out = Vec::with_capacity(out_len);
    let chunks = b.len() / 4;
    for (i, ch) in b.chunks(4).enumerate() {
        let last = i + 1 == chunks;
        let mut n = 0u32;
        for (j, &c) in ch.iter().enumerate() {
            let v = if c == b'=' {
                if !last || j < 4 - pad {
                    return Err("misplaced base64 padding");
                }
                0
            } else {
                val(c).ok_or("invalid base64 character")?
            };
            n = (n << 6) | v;
        }
        out.push((n >> 16) as u8);
        if !(last && pad == 2) {
            out.push((n >> 8) as u8);
        }
        if !(last && pad >= 1) {
            out.push(n as u8);
        }
    }
    // canonical: unused low bits must be zero
    if pad > 0 {
        let tail = b[b.len() - pad - 1];
        let v = val(tail).ok_or("invalid base64 character")?;
        let mask = if pad == 2 { 0x0f } else { 0x03 };
        if v & mask != 0 {
            return Err("non-canonical base64 padding bits");
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc4648_vectors() {
        for (p, e) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")] {
            assert_eq!(encode(p.as_bytes()), e);
            assert_eq!(decode(e, 100).unwrap(), p.as_bytes());
        }
    }
    #[test]
    fn all_bytes_round_trip_and_strictness() {
        let data: Vec<u8> = (0..=255u8).collect();
        assert_eq!(decode(&encode(&data), 1000).unwrap(), data);
        assert!(decode("Zm9", 10).is_err());
        assert!(decode("Zm9v\n", 10).is_err());
        assert!(decode("Zg==", 0).is_err(), "cap enforced");
        assert!(decode("Zh==", 10).is_err(), "non-canonical bits");
        assert!(decode("=Zg=", 10).is_err());
    }
}
