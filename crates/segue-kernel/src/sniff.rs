//! Domain sniffing on the first bytes of a TCP flow (KERNEL_SPEC §5.2a.1).
//!
//! Pure parsers over a byte prefix. They never consume anything from the
//! socket: the caller keeps the bytes and replays them to the upstream.
//! Detection is by content, not by port, so TLS on 8443 or HTTP on 8080 is
//! still recognised.
//!
//! Every slice access is checked; arbitrary bytes must never panic.

/// Outcome of looking at a prefix of the client's first bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sniff {
    /// A host name was found (lowercase, no trailing dot).
    Domain(String),
    /// The prefix is a valid start of TLS or HTTP but is not complete yet.
    NeedMore,
    /// Not TLS/HTTP, or TLS/HTTP without a usable host name. Final.
    None,
}

/// Look at `buf` as TLS first, then HTTP.
pub fn sniff(buf: &[u8]) -> Sniff {
    if buf.is_empty() {
        return Sniff::NeedMore;
    }
    if buf[0] == 0x16 {
        return tls_sni(buf);
    }
    http_host(buf)
}

/// Extract the server_name from a TLS ClientHello, possibly spread over
/// several handshake records.
pub fn tls_sni(buf: &[u8]) -> Sniff {
    // Reassemble the handshake message from consecutive records.
    let mut hs = Vec::new();
    let mut pos = 0;
    loop {
        let Some(head) = buf.get(pos..pos + 5) else {
            return if hs_complete(&hs) {
                parse_client_hello(&hs)
            } else {
                Sniff::NeedMore
            };
        };
        if head[0] != 0x16 || head[1] != 0x03 {
            return Sniff::None;
        }
        let len = u16::from_be_bytes([head[3], head[4]]) as usize;
        if len == 0 || len > 16384 + 2048 {
            return Sniff::None;
        }
        let start = pos + 5;
        match buf.get(start..start + len) {
            Some(body) => hs.extend_from_slice(body),
            None => {
                // Partial record: use what is there; maybe the SNI is early.
                hs.extend_from_slice(&buf[start.min(buf.len())..]);
                return match parse_client_hello(&hs) {
                    Sniff::NeedMore => Sniff::NeedMore,
                    other => other,
                };
            }
        }
        pos = start + len;
        if hs_complete(&hs) {
            return parse_client_hello(&hs);
        }
    }
}

fn hs_complete(hs: &[u8]) -> bool {
    match hs.get(1..4) {
        Some(l) => {
            hs.len() >= 4 + (usize::from(l[0]) << 16 | usize::from(l[1]) << 8 | usize::from(l[2]))
        }
        None => false,
    }
}

/// Small cursor: every read returns None when out of bounds.
struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.p..self.p.checked_add(n)?)?;
        self.p += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<usize> {
        self.take(1).map(|b| usize::from(b[0]))
    }
    fn u16(&mut self) -> Option<usize> {
        self.take(2)
            .map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
    }
}

/// `hs` is the (possibly truncated) handshake message bytes.
fn parse_client_hello(hs: &[u8]) -> Sniff {
    let complete = hs_complete(hs);
    // On truncation a None from the cursor means "need more", otherwise the
    // message is malformed.
    let short = if complete {
        Sniff::None
    } else {
        Sniff::NeedMore
    };
    if let Some(&t) = hs.first() {
        if t != 0x01 {
            return Sniff::None;
        }
    }
    let end = match hs.get(1..4) {
        Some(l) => (4 + (usize::from(l[0]) << 16 | usize::from(l[1]) << 8 | usize::from(l[2])))
            .min(hs.len()),
        None => return Sniff::NeedMore,
    };
    let mut c = Cur {
        b: &hs[..end],
        p: 4,
    };
    let r = (|| {
        c.take(2 + 32)?; // version, random
        let sid = c.u8()?;
        c.take(sid)?;
        let cs = c.u16()?;
        c.take(cs)?;
        let cm = c.u8()?;
        c.take(cm)?;
        let ext_len = c.u16()?;
        let ext_end = c.p + ext_len;
        while c.p + 4 <= ext_end {
            let ty = c.u16()?;
            let len = c.u16()?;
            let body = c.take(len)?;
            if ty == 0 {
                return Some(server_name(body));
            }
        }
        // Extensions parsed fully with no SNI, or ran out of bytes.
        if c.p >= ext_end && ext_end <= c.b.len() {
            Some(Sniff::None)
        } else {
            None
        }
    })();
    r.unwrap_or(short)
}

fn server_name(body: &[u8]) -> Sniff {
    let mut c = Cur { b: body, p: 0 };
    let Some(list_len) = c.u16() else {
        return Sniff::None;
    };
    let list_end = (2 + list_len).min(body.len());
    while c.p + 3 <= list_end {
        let (Some(kind), Some(len)) = (c.u8(), c.u16()) else {
            return Sniff::None;
        };
        let Some(name) = c.take(len) else {
            return Sniff::None;
        };
        if kind == 0 {
            return clean_host(name);
        }
    }
    Sniff::None
}

/// Longest request line + headers we look through for `Host`.
const HTTP_MAX: usize = 8192;

const METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
];

/// Extract the `Host` header of an HTTP/1.x request.
pub fn http_host(buf: &[u8]) -> Sniff {
    let starts = METHODS.iter().any(|m| {
        let n = m.len().min(buf.len());
        buf[..n] == m[..n]
    });
    if !starts {
        return Sniff::None;
    }
    if !METHODS.iter().any(|m| buf.starts_with(m)) {
        return Sniff::NeedMore;
    }
    let window = &buf[..buf.len().min(HTTP_MAX)];
    // Only lines terminated by '\n' are trusted; the tail may be cut short.
    let mut rest = window;
    let mut first = true;
    while let Some(nl) = rest.iter().position(|&b| b == b'\n') {
        let line = &rest[..nl];
        rest = &rest[nl + 1..];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if std::mem::take(&mut first) {
            continue; // request line
        }
        if line.is_empty() {
            return Sniff::None; // end of headers, no Host
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        if line[..colon].eq_ignore_ascii_case(b"host") {
            return clean_host(strip_port(trim(&line[colon + 1..])));
        }
    }
    if buf.len() >= HTTP_MAX {
        Sniff::None
    } else {
        Sniff::NeedMore
    }
}

fn trim(b: &[u8]) -> &[u8] {
    let s = b
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(b.len());
    let e = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map_or(s, |e| e + 1);
    &b[s..e]
}

fn strip_port(v: &[u8]) -> &[u8] {
    if v.first() == Some(&b'[') {
        // IPv6 literal; rejected by clean_host anyway.
        return v;
    }
    match v.iter().rposition(|&b| b == b':') {
        Some(i) if v[i + 1..].iter().all(u8::is_ascii_digit) => &v[..i],
        _ => v,
    }
}

/// Accept only a plausible DNS name; IP literals give no domain.
fn clean_host(raw: &[u8]) -> Sniff {
    let Ok(s) = std::str::from_utf8(raw) else {
        return Sniff::None;
    };
    let s = s.trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() || s.len() > 253 || s.parse::<std::net::IpAddr>().is_ok() || s.starts_with('[')
    {
        return Sniff::None;
    }
    let ok = s.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    if ok {
        Sniff::Domain(s)
    } else {
        Sniff::None
    }
}

/// Build a minimal TLS 1.2/1.3-style ClientHello carrying `sni` (tests and
/// fuzz seeds). `pad` extra bytes go into a padding extension so callers can
/// make the hello span several TCP segments or records.
#[doc(hidden)]
pub fn client_hello_for_test(sni: Option<&str>, pad: usize) -> Vec<u8> {
    let mut exts = Vec::new();
    if let Some(name) = sni {
        let n = name.as_bytes();
        let mut sn = Vec::new();
        sn.extend_from_slice(&((n.len() + 3) as u16).to_be_bytes());
        sn.push(0);
        sn.extend_from_slice(&(n.len() as u16).to_be_bytes());
        sn.extend_from_slice(n);
        // Put padding first so the SNI is late in the message.
        if pad > 0 {
            exts.extend_from_slice(&21u16.to_be_bytes());
            exts.extend_from_slice(&(pad as u16).to_be_bytes());
            exts.extend(std::iter::repeat_n(0u8, pad));
        }
        exts.extend_from_slice(&0u16.to_be_bytes());
        exts.extend_from_slice(&(sn.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sn);
    } else if pad > 0 {
        exts.extend_from_slice(&21u16.to_be_bytes());
        exts.extend_from_slice(&(pad as u16).to_be_bytes());
        exts.extend(std::iter::repeat_n(0u8, pad));
    }
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[7u8; 32]);
    body.push(0); // session id
    body.extend_from_slice(&[0, 2, 0x13, 0x01]); // cipher suites
    body.extend_from_slice(&[1, 0]); // compression
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    let mut hs = vec![0x01];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_sni_basic_and_every_prefix() {
        let hello = client_hello_for_test(Some("Chat.OpenAI.com."), 0);
        assert_eq!(sniff(&hello), Sniff::Domain("chat.openai.com".into()));
        // Any strict prefix is NeedMore (or the domain once SNI is in), never None.
        for n in 0..hello.len() {
            let r = sniff(&hello[..n]);
            assert!(
                matches!(r, Sniff::NeedMore | Sniff::Domain(_)),
                "prefix {n}: {r:?}"
            );
        }
    }

    #[test]
    fn tls_sni_late_in_big_hello() {
        let hello = client_hello_for_test(Some("api.anthropic.com"), 1800);
        assert!(hello.len() > 1800);
        assert_eq!(sniff(&hello[..1000]), Sniff::NeedMore);
        assert_eq!(sniff(&hello), Sniff::Domain("api.anthropic.com".into()));
    }

    #[test]
    fn tls_hello_split_across_records() {
        let one = client_hello_for_test(Some("example.org"), 300);
        let hs = &one[5..];
        let (a, b) = hs.split_at(100);
        let mut two = Vec::new();
        for part in [a, b] {
            two.extend_from_slice(&[0x16, 0x03, 0x01]);
            two.extend_from_slice(&(part.len() as u16).to_be_bytes());
            two.extend_from_slice(part);
        }
        assert_eq!(sniff(&two[..60]), Sniff::NeedMore);
        assert_eq!(sniff(&two), Sniff::Domain("example.org".into()));
    }

    #[test]
    fn tls_without_sni_or_ip_sni() {
        assert_eq!(sniff(&client_hello_for_test(None, 10)), Sniff::None);
        assert_eq!(
            sniff(&client_hello_for_test(Some("1.2.3.4"), 0)),
            Sniff::None
        );
    }

    #[test]
    fn not_tls() {
        assert_eq!(sniff(&[0x16, 0x01, 0, 0, 0]), Sniff::None);
        assert_eq!(sniff(b"SSH-2.0-OpenSSH"), Sniff::None);
        assert_eq!(
            sniff(&[0x16, 0x03, 0x01, 0x00, 0x05, 0x02, 0, 0, 1, 0]),
            Sniff::None
        );
    }

    #[test]
    fn http_host() {
        let req = b"GET / HTTP/1.1\r\nUser-Agent: x\r\nhost: Example.COM:8080\r\n\r\n";
        assert_eq!(sniff(req), Sniff::Domain("example.com".into()));
        for n in 0..req.len() {
            let r = sniff(&req[..n]);
            assert!(
                matches!(r, Sniff::NeedMore | Sniff::Domain(_)),
                "prefix {n}: {r:?}"
            );
        }
        // A host line cut short is not trusted.
        assert_eq!(sniff(b"GET / HTTP/1.1\r\nHost: examp"), Sniff::NeedMore);
        assert_eq!(
            sniff(b"GET / HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n"),
            Sniff::None
        );
        assert_eq!(sniff(b"GET / HTTP/1.1\r\nX: y\r\n\r\n"), Sniff::None);
        assert_eq!(sniff(b"GE"), Sniff::NeedMore);
        assert_eq!(sniff(b"GX"), Sniff::None);
    }

    #[test]
    fn garbage_never_panics() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let hello = client_hello_for_test(Some("a.b.c"), 64);
        for _ in 0..20000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let mut b = hello.clone();
            let i = (x as usize) % b.len();
            b[i] = (x >> 32) as u8;
            let cut = ((x >> 16) as usize) % (b.len() + 1);
            let _ = sniff(&b[..cut]);
            let raw: Vec<u8> = (0..(x % 64) as usize)
                .map(|k| (x >> (k % 56)) as u8)
                .collect();
            let _ = sniff(&raw);
        }
    }
}
