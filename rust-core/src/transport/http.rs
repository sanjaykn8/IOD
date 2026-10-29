//! Tiny blocking HTTP/1.1 client for the loopback Python service.
//!
//! Deliberately hand-written over `std::net`: no new dependency and, above
//! all, no TLS stack (rustls/ring would introduce elliptic-curve code, which
//! the project forbids). Plain HTTP is acceptable ONLY for loopback (or an
//! explicitly allowed private container network). Bounded in every
//! dimension: connect/read/write timeouts, total deadline, header size,
//! response size, chunked decoding with caps.

use crate::transport::error::{stage, StegoError};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct BaseUrl {
    pub host: String,
    pub port: u16,
}

pub fn parse_base_url(url: &str, allow_nonloopback: bool) -> Result<BaseUrl, String> {
    let rest = url.strip_prefix("http://").ok_or("IOD_PYTHON_URL must start with http:// (TLS is intentionally unsupported)")?;
    let hostport = rest.trim_end_matches('/');
    if hostport.contains('/') || hostport.contains('@') || hostport.is_empty() {
        return Err("IOD_PYTHON_URL must be http://host:port with no path or credentials".into());
    }
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => (h.trim_matches(|c| c == '[' || c == ']'), p.parse::<u16>().map_err(|_| "invalid port")?),
        _ => (hostport, 80),
    };
    let loopback = matches!(host, "127.0.0.1" | "localhost" | "::1");
    if !loopback && !allow_nonloopback {
        return Err("IOD_PYTHON_URL must be loopback unless IOD_STEGO_ALLOW_NONLOOPBACK=1".into());
    }
    if host.chars().any(|c| !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':')) {
        return Err("invalid host".into());
    }
    Ok(BaseUrl { host: host.to_string(), port })
}

pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

fn unavailable(msg: String) -> StegoError {
    StegoError::new("STEGO_BACKEND_UNAVAILABLE", stage::PREPARE, 503, msg)
}

pub fn request(base: &BaseUrl, method: &str, path: &str, body: Option<&[u8]>, timeout: Duration, max_resp: usize) -> Result<HttpResponse, StegoError> {
    let deadline = Instant::now() + timeout;
    let addr = (base.host.as_str(), base.port)
        .to_socket_addrs()
        .map_err(|e| unavailable(format!("cannot resolve backend: {e}")))?
        .next()
        .ok_or_else(|| unavailable("backend address did not resolve".into()))?;
    let mut s = TcpStream::connect_timeout(&addr, timeout.min(Duration::from_secs(5)))
        .map_err(|e| unavailable(format!("cannot connect to the Python stego service: {e}")))?;
    let tmo = |_: std::io::Error| StegoError::new("STEGO_BACKEND_TIMEOUT", stage::PREPARE, 504, "Python stego service timed out");
    s.set_read_timeout(Some(timeout)).map_err(tmo)?;
    s.set_write_timeout(Some(timeout)).map_err(tmo)?;
    let body = body.unwrap_or(&[]);
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}:{}\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        base.host, base.port, body.len()
    );
    let io_err = |e: std::io::Error| {
        if matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) {
            StegoError::new("STEGO_BACKEND_TIMEOUT", stage::PREPARE, 504, "Python stego service timed out")
        } else {
            unavailable(format!("backend I/O error: {e}"))
        }
    };
    s.write_all(head.as_bytes()).map_err(io_err)?;
    s.write_all(body).map_err(io_err)?;

    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 16 * 1024];
    let limit = max_resp + 16 * 1024;
    loop {
        if Instant::now() > deadline {
            return Err(StegoError::new("STEGO_BACKEND_TIMEOUT", stage::PREPARE, 504, "Python stego service exceeded the total deadline"));
        }
        match s.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > limit {
                    return Err(StegoError::new("BACKEND_RESPONSE_TOO_LARGE", stage::PREPARE, 502, "backend response exceeds the size limit"));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io_err(e)),
        }
    }
    parse_response(&buf, max_resp)
}

fn malformed(m: &str) -> StegoError {
    StegoError::new("BACKEND_MALFORMED_RESPONSE", stage::PREPARE, 502, m.to_string())
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

pub fn parse_response(buf: &[u8], max_resp: usize) -> Result<HttpResponse, StegoError> {
    let split = find(buf, b"\r\n\r\n").ok_or_else(|| malformed("no header terminator"))?;
    if split > 16 * 1024 {
        return Err(malformed("headers too large"));
    }
    let head = std::str::from_utf8(&buf[..split]).map_err(|_| malformed("non-UTF-8 headers"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or_else(|| malformed("empty response"))?;
    let mut parts = status_line.split_whitespace();
    let proto = parts.next().unwrap_or("");
    if !proto.starts_with("HTTP/1.") {
        return Err(malformed("not an HTTP/1.x response"));
    }
    let status: u16 = parts.next().and_then(|c| c.parse().ok()).ok_or_else(|| malformed("bad status code"))?;
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            if k == "content-length" {
                content_length = Some(v.parse().map_err(|_| malformed("bad content-length"))?);
            } else if k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
        }
    }
    let raw = &buf[split + 4..];
    let body = if chunked {
        let mut out = Vec::new();
        let mut i = 0usize;
        loop {
            let e = find(&raw[i..], b"\r\n").ok_or_else(|| malformed("truncated chunk header"))? + i;
            let size_s = std::str::from_utf8(&raw[i..e]).map_err(|_| malformed("bad chunk size"))?;
            let size = usize::from_str_radix(size_s.split(';').next().unwrap().trim(), 16).map_err(|_| malformed("bad chunk size"))?;
            i = e + 2;
            if size == 0 {
                break;
            }
            if out.len() + size > max_resp {
                return Err(StegoError::new("BACKEND_RESPONSE_TOO_LARGE", stage::PREPARE, 502, "backend response exceeds the size limit"));
            }
            if raw.len() < i + size + 2 {
                return Err(malformed("truncated chunk"));
            }
            out.extend_from_slice(&raw[i..i + size]);
            i += size + 2;
        }
        out
    } else if let Some(cl) = content_length {
        if cl > max_resp {
            return Err(StegoError::new("BACKEND_RESPONSE_TOO_LARGE", stage::PREPARE, 502, "backend response exceeds the size limit"));
        }
        if raw.len() < cl {
            return Err(malformed("body shorter than content-length"));
        }
        raw[..cl].to_vec()
    } else {
        if raw.len() > max_resp {
            return Err(StegoError::new("BACKEND_RESPONSE_TOO_LARGE", stage::PREPARE, 502, "backend response exceeds the size limit"));
        }
        raw.to_vec()
    };
    Ok(HttpResponse { status, body })
}

/// JSON call: maps non-2xx bodies carrying `{"error":{code,message}}` onto `StegoError`.
pub fn call_json(base: &BaseUrl, method: &str, path: &str, body: Option<&Value>, timeout: Duration, max_resp: usize) -> Result<Value, StegoError> {
    let payload = body.map(|b| serde_json::to_vec(b).unwrap_or_default());
    let r = request(base, method, path, payload.as_deref(), timeout, max_resp)?;
    let v: Value = serde_json::from_slice(&r.body).map_err(|_| malformed("response is not valid JSON"))?;
    if (200..300).contains(&r.status) && v.get("ok").and_then(|x| x.as_bool()) != Some(false) {
        return Ok(v);
    }
    let e = v.get("error");
    let code = e.and_then(|e| e.get("code")).and_then(|c| c.as_str()).unwrap_or("BACKEND_ERROR");
    let msg = e.and_then(|e| e.get("message")).and_then(|c| c.as_str()).unwrap_or("backend reported an error");
    let status = crate::transport::error::status_for_backend_code(code);
    let mut se = StegoError::new(code, stage::PREPARE, status, msg.to_string());
    if let Some(d) = e.and_then(|e| e.get("details")) {
        se = se.with_details(d.clone());
    }
    Err(se)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn url_validation() {
        assert!(parse_base_url("http://127.0.0.1:5001", false).is_ok());
        assert!(parse_base_url("http://localhost:5001/", false).is_ok());
        assert!(parse_base_url("https://127.0.0.1:5001", false).is_err());
        assert!(parse_base_url("http://10.0.0.5:5001", false).is_err());
        assert!(parse_base_url("http://10.0.0.5:5001", true).is_ok());
        assert!(parse_base_url("http://user@127.0.0.1:5001", false).is_err());
        assert!(parse_base_url("http://127.0.0.1:5001/x", false).is_err());
    }
    #[test]
    fn response_parsing_cases() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(parse_response(ok, 10).unwrap().body, b"{}");
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        assert_eq!(parse_response(chunked, 10).unwrap().body, b"{}");
        assert!(parse_response(b"garbage", 10).is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 99999\r\n\r\n{}", 10).is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n{}", 100).is_err(), "short body");
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffff\r\nab", 1000).is_err());
    }
    #[test]
    fn unreachable_port_is_service_unavailable() {
        let base = BaseUrl { host: "127.0.0.1".into(), port: 1 };
        let e = request(&base, "GET", "/x", None, Duration::from_millis(500), 1000).err().unwrap();
        assert_eq!(e.code, "STEGO_BACKEND_UNAVAILABLE");
    }
}
