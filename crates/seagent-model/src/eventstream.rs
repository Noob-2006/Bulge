//! AWS event stream framing (`application/vnd.amazon.eventstream`), as used by Bedrock
//! ConverseStream: `[total len][headers len][prelude crc][headers][payload][message crc]`,
//! big-endian, CRC-32 (IEEE) checked on both prelude and message.

#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub headers: Vec<(String, String)>,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

pub fn crc32(data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let t = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *e = c;
        }
        t
    });
    !data.iter().fold(!0u32, |c, b| {
        t[((c ^ *b as u32) & 0xff) as usize] ^ (c >> 8)
    })
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

#[derive(Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Feed bytes; returns complete messages, or an error on corrupt framing.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Message>, String> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            if self.buf.len() < 12 {
                return Ok(out);
            }
            let total = be32(&self.buf[0..4]) as usize;
            let hlen = be32(&self.buf[4..8]) as usize;
            if total < 16 || hlen + 16 > total || total > 16 << 20 {
                return Err(format!("event stream: bad frame lengths ({total}, {hlen})"));
            }
            if crc32(&self.buf[0..8]) != be32(&self.buf[8..12]) {
                return Err("event stream: prelude CRC mismatch".into());
            }
            if self.buf.len() < total {
                return Ok(out);
            }
            let frame: Vec<u8> = self.buf.drain(..total).collect();
            if crc32(&frame[..total - 4]) != be32(&frame[total - 4..]) {
                return Err("event stream: message CRC mismatch".into());
            }
            let headers = parse_headers(&frame[12..12 + hlen])?;
            out.push(Message {
                headers,
                payload: frame[12 + hlen..total - 4].to_vec(),
            });
        }
    }
}

fn parse_headers(mut b: &[u8]) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let short = || "event stream: truncated header".to_string();
    while !b.is_empty() {
        let n = *b.first().ok_or_else(short)? as usize;
        let name = String::from_utf8_lossy(b.get(1..1 + n).ok_or_else(short)?).to_string();
        let ty = *b.get(1 + n).ok_or_else(short)?;
        b = &b[2 + n..];
        let (val, used) = match ty {
            0 => ("true".to_string(), 0),
            1 => ("false".to_string(), 0),
            2 => (b.first().ok_or_else(short)?.to_string(), 1),
            3 => (
                i16::from_be_bytes(b.get(..2).ok_or_else(short)?.try_into().unwrap()).to_string(),
                2,
            ),
            4 => (
                i32::from_be_bytes(b.get(..4).ok_or_else(short)?.try_into().unwrap()).to_string(),
                4,
            ),
            5 | 8 => (
                i64::from_be_bytes(b.get(..8).ok_or_else(short)?.try_into().unwrap()).to_string(),
                8,
            ),
            6 | 7 => {
                let l =
                    u16::from_be_bytes(b.get(..2).ok_or_else(short)?.try_into().unwrap()) as usize;
                (
                    String::from_utf8_lossy(b.get(2..2 + l).ok_or_else(short)?).to_string(),
                    2 + l,
                )
            }
            9 => (seagent_net::crypto::hex(b.get(..16).ok_or_else(short)?), 16),
            t => return Err(format!("event stream: unknown header type {t}")),
        };
        b = &b[used..];
        out.push((name, val));
    }
    Ok(out)
}

/// Encode a message with string headers (fake servers in tests).
pub fn encode(headers: &[(&str, &str)], payload: &[u8]) -> Vec<u8> {
    let mut h = Vec::new();
    for (k, v) in headers {
        h.push(k.len() as u8);
        h.extend_from_slice(k.as_bytes());
        h.push(7);
        h.extend_from_slice(&(v.len() as u16).to_be_bytes());
        h.extend_from_slice(v.as_bytes());
    }
    let total = 16 + h.len() + payload.len();
    let mut m = Vec::with_capacity(total);
    m.extend_from_slice(&(total as u32).to_be_bytes());
    m.extend_from_slice(&(h.len() as u32).to_be_bytes());
    let pc = crc32(&m);
    m.extend_from_slice(&pc.to_be_bytes());
    m.extend_from_slice(&h);
    m.extend_from_slice(payload);
    let mc = crc32(&m);
    m.extend_from_slice(&mc.to_be_bytes());
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_known_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn roundtrip_split_feeds_and_corruption() {
        let a = encode(
            &[
                (":event-type", "contentBlockDelta"),
                (":message-type", "event"),
            ],
            br#"{"delta":{"text":"hi"}}"#,
        );
        let b = encode(&[(":event-type", "messageStop")], b"{}");
        let mut all = a.clone();
        all.extend_from_slice(&b);
        let mut d = Decoder::new();
        let mut got = Vec::new();
        for chunk in all.chunks(7) {
            got.extend(d.feed(chunk).unwrap());
        }
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].header(":event-type"), Some("contentBlockDelta"));
        assert_eq!(got[0].payload, br#"{"delta":{"text":"hi"}}"#);
        let mut bad = a.clone();
        let n = bad.len();
        bad[n - 6] ^= 1;
        assert!(Decoder::new().feed(&bad).unwrap_err().contains("CRC"));
    }
}
