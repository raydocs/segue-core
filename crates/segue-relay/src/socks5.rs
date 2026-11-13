//! SOCKS5 client (RFC 1928 CONNECT, RFC 1929 username/password) for Decodo
//! Home lines. Only IP targets are sent (ATYP 1 / 4): the relay resolves and
//! checks addresses itself and never hands a domain to the provider for
//! remote resolution (KERNEL_SPEC §5.5 item 4).

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    user: Vec<u8>,
    pass: Vec<u8>,
}

impl Credentials {
    /// `username:password`, each 1..=255 bytes.
    pub fn parse(s: &str) -> Option<Self> {
        let (u, p) = s.split_once(':')?;
        Self::new(u.as_bytes(), p.as_bytes())
    }

    pub fn new(user: &[u8], pass: &[u8]) -> Option<Self> {
        let ok = |b: &[u8]| (1..=255).contains(&b.len());
        (ok(user) && ok(pass)).then(|| Self {
            user: user.to_vec(),
            pass: pass.to_vec(),
        })
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credentials(<redacted>)")
    }
}

/// Why a SOCKS exchange failed. Gateway-side failures (`Auth`, `Protocol`,
/// `Io`) count against the line; `Reply` is the target's fault.
#[derive(Debug)]
pub enum SocksError {
    Io(io::Error),
    Protocol,
    Auth,
    /// CONNECT reply code (RFC 1928 §6), non-zero.
    Reply(u8),
}

impl fmt::Display for SocksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "socks io: {}", e.kind()),
            Self::Protocol => f.write_str("socks protocol error"),
            Self::Auth => f.write_str("socks auth rejected"),
            Self::Reply(c) => write!(f, "socks connect reply {c}"),
        }
    }
}

impl std::error::Error for SocksError {}

impl From<io::Error> for SocksError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl SocksError {
    pub fn is_line_fault(&self) -> bool {
        !matches!(self, Self::Reply(_))
    }
}

/// Greeting + optional auth. After this the stream is ready for CONNECT.
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    creds: Option<&Credentials>,
) -> Result<(), SocksError> {
    let method = if creds.is_some() { 0x02 } else { 0x00 };
    s.write_all(&[0x05, 0x01, method]).await?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await?;
    if r[0] != 0x05 {
        return Err(SocksError::Protocol);
    }
    if r[1] == 0xff {
        return Err(SocksError::Auth);
    }
    if r[1] != method {
        return Err(SocksError::Protocol);
    }
    if let Some(c) = creds {
        let mut m = Vec::with_capacity(3 + c.user.len() + c.pass.len());
        m.push(0x01);
        m.push(c.user.len() as u8);
        m.extend_from_slice(&c.user);
        m.push(c.pass.len() as u8);
        m.extend_from_slice(&c.pass);
        s.write_all(&m).await?;
        // Overwrite our copy of the secret.
        m.iter_mut().for_each(|b| *b = 0);
        s.read_exact(&mut r).await?;
        if r[0] != 0x01 {
            return Err(SocksError::Protocol);
        }
        if r[1] != 0x00 {
            return Err(SocksError::Auth);
        }
    }
    Ok(())
}

/// CONNECT to an IP target; consumes the full reply.
pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    target: SocketAddr,
) -> Result<(), SocksError> {
    let mut m = vec![0x05, 0x01, 0x00];
    match target.ip() {
        IpAddr::V4(a) => {
            m.push(0x01);
            m.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            m.push(0x04);
            m.extend_from_slice(&a.octets());
        }
    }
    m.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&m).await?;
    let mut h = [0u8; 4];
    s.read_exact(&mut h).await?;
    if h[0] != 0x05 || h[2] != 0x00 {
        return Err(SocksError::Protocol);
    }
    if h[1] != 0x00 {
        return Err(SocksError::Reply(h[1]));
    }
    let skip = match h[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize
        }
        _ => return Err(SocksError::Protocol),
    };
    let mut rest = vec![0u8; skip + 2];
    s.read_exact(&mut rest).await?;
    Ok(())
}
