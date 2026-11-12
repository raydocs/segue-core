//! Local SOCKS5 entry point (CONNECT only, no authentication, loopback only).
//!
//! The success reply is sent only after the outbound dial succeeds, so a
//! failed proxy route reaches the application as a SOCKS error instead of a
//! half-open connection.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use segue_routing::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::dial::Dialer;
use crate::rules::{Action, RuleSet};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);

pub const REP_OK: u8 = 0x00;
pub const REP_GENERAL: u8 = 0x01;
pub const REP_NOT_ALLOWED: u8 = 0x02;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CMD_UNSUPPORTED: u8 = 0x07;
pub const REP_ATYP_UNSUPPORTED: u8 = 0x08;

pub struct Kernel {
    pub rules: RuleSet,
    pub dialer: Arc<dyn Dialer>,
}

pub async fn serve(listener: TcpListener, kernel: Arc<Kernel>) -> std::io::Result<()> {
    loop {
        let (conn, _) = listener.accept().await?;
        let kernel = kernel.clone();
        tokio::spawn(async move {
            let _ = handle(conn, &kernel).await;
        });
    }
}

#[derive(Debug)]
enum Fail {
    Io(#[allow(dead_code)] std::io::Error),
    Reply(u8),
}

impl From<std::io::Error> for Fail {
    fn from(e: std::io::Error) -> Self {
        Fail::Io(e)
    }
}

async fn handle(mut conn: TcpStream, kernel: &Kernel) -> Result<(), Fail> {
    let _ = conn.set_nodelay(true);
    let request = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_request(&mut conn))
        .await
        .map_err(|_| Fail::Io(std::io::ErrorKind::TimedOut.into()))?;
    let (addr, port) = match request {
        Ok(target) => target,
        Err(Fail::Reply(code)) => {
            reply(&mut conn, code).await?;
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let tag = match kernel.rules.decide(&addr) {
        Action::Reject => {
            reply(&mut conn, REP_NOT_ALLOWED).await?;
            return Ok(());
        }
        Action::Direct => None,
        Action::Proxy(tag) => Some(tag.as_str()),
    };
    let dialed = tokio::time::timeout(DIAL_TIMEOUT, kernel.dialer.dial(tag, &addr, port)).await;
    let mut upstream = match dialed {
        Ok(Ok(stream)) => stream,
        // A proxy route that fails is refused, never retried as direct.
        Ok(Err(_)) | Err(_) => {
            reply(&mut conn, REP_HOST_UNREACHABLE).await?;
            return Ok(());
        }
    };
    reply(&mut conn, REP_OK).await?;
    tokio::io::copy_bidirectional(&mut conn, &mut upstream).await?;
    Ok(())
}

async fn read_request(conn: &mut TcpStream) -> Result<(TargetAddr, u16), Fail> {
    let mut head = [0u8; 2];
    conn.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(Fail::Io(std::io::ErrorKind::InvalidData.into()));
    }
    let mut methods = vec![0u8; head[1] as usize];
    conn.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        conn.write_all(&[5, 0xff]).await?;
        return Err(Fail::Io(std::io::ErrorKind::PermissionDenied.into()));
    }
    conn.write_all(&[5, 0]).await?;

    let mut req = [0u8; 4];
    conn.read_exact(&mut req).await?;
    if req[0] != 5 {
        return Err(Fail::Io(std::io::ErrorKind::InvalidData.into()));
    }
    let addr = match req[3] {
        1 => {
            let mut b = [0u8; 4];
            conn.read_exact(&mut b).await?;
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::from(b)))
        }
        4 => {
            let mut b = [0u8; 16];
            conn.read_exact(&mut b).await?;
            TargetAddr::Ip(IpAddr::V6(Ipv6Addr::from(b)))
        }
        3 => {
            let len = conn.read_u8().await? as usize;
            let mut b = vec![0u8; len];
            conn.read_exact(&mut b).await?;
            let name = String::from_utf8(b).map_err(|_| Fail::Reply(REP_GENERAL))?;
            // A literal IP sent as a hostname is routed as an IP.
            match name.parse::<IpAddr>() {
                Ok(ip) => TargetAddr::Ip(ip),
                Err(_) if !name.is_empty() => TargetAddr::Domain(name),
                Err(_) => return Err(Fail::Reply(REP_GENERAL)),
            }
        }
        _ => return Err(Fail::Reply(REP_ATYP_UNSUPPORTED)),
    };
    let port = conn.read_u16().await?;
    if req[1] != 1 {
        return Err(Fail::Reply(REP_CMD_UNSUPPORTED));
    }
    Ok((addr, port))
}

async fn reply(conn: &mut TcpStream, code: u8) -> std::io::Result<()> {
    conn.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}
