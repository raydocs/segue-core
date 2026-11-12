//! SOCKS entry + rule table with a fake dialer: checks which route each flow
//! takes and that a failed proxy route is refused rather than sent direct.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use segue_kernel::dial::{DialError, Dialer, Stream};
use segue_kernel::rules::{Action, Cidr, Matcher, Rule, RuleSet};
use segue_kernel::socks::{serve, Kernel, REP_HOST_UNREACHABLE, REP_NOT_ALLOWED, REP_OK};
use segue_routing::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Default)]
struct Fake {
    calls: Mutex<Vec<(Option<String>, String)>>,
    echo: Mutex<Option<std::net::SocketAddr>>,
}

#[async_trait]
impl Dialer for Fake {
    async fn dial(
        &self,
        tag: Option<&str>,
        addr: &TargetAddr,
        port: u16,
    ) -> Result<Stream, DialError> {
        let shown = match addr {
            TargetAddr::Ip(ip) => format!("{ip}:{port}"),
            TargetAddr::Domain(d) => format!("{d}:{port}"),
        };
        self.calls
            .lock()
            .unwrap()
            .push((tag.map(str::to_owned), shown));
        if tag == Some("broken") {
            return Err(DialError("outer link down".into()));
        }
        let echo = self.echo.lock().unwrap().expect("echo server");
        Ok(Box::new(TcpStream::connect(echo).await.unwrap()))
    }
}

async fn echo_server() -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut c, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = c.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

async fn kernel(fake: Arc<Fake>) -> std::net::SocketAddr {
    let rules = RuleSet::new(
        vec![
            Rule {
                matcher: Matcher::DomainSuffix("openai.com".into()),
                action: Action::Proxy("broken".into()),
            },
            Rule {
                matcher: Matcher::DomainSuffix("ads.test".into()),
                action: Action::Reject,
            },
            Rule {
                matcher: Matcher::Cidr(Cidr::parse("192.168.0.0/16").unwrap()),
                action: Action::Direct,
            },
        ],
        Action::Proxy("proxy".into()),
    );
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(serve(l, Arc::new(Kernel::new(rules, fake))));
    addr
}

/// SOCKS5 CONNECT to a hostname; returns the reply code and the stream.
async fn connect(kernel: std::net::SocketAddr, host: &str, port: u16) -> (u8, TcpStream) {
    let mut c = TcpStream::connect(kernel).await.unwrap();
    c.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    c.read_exact(&mut m).await.unwrap();
    assert_eq!(m, [5, 0]);
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    c.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    c.read_exact(&mut rep).await.unwrap();
    (rep[1], c)
}

#[tokio::test]
async fn routes_and_refusals() {
    let fake = Arc::new(Fake::default());
    *fake.echo.lock().unwrap() = Some(echo_server().await);
    let k = kernel(fake.clone()).await;

    // Default route → proxy, data flows end to end.
    let (rep, mut c) = connect(k, "example.com", 443).await;
    assert_eq!(rep, REP_OK);
    c.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    c.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    // Literal IP inside a hostname field is routed as an IP → direct rule.
    let (rep, _) = connect(k, "192.168.1.10", 80).await;
    assert_eq!(rep, REP_OK);

    // Reject rule: no dial at all.
    let (rep, _) = connect(k, "x.ads.test", 443).await;
    assert_eq!(rep, REP_NOT_ALLOWED);

    // Matched proxy route whose outbound fails → refused, no direct retry.
    let (rep, _) = connect(k, "chat.openai.com", 443).await;
    assert_eq!(rep, REP_HOST_UNREACHABLE);

    let calls = fake.calls.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![
            (Some("proxy".into()), "example.com:443".into()),
            (None, "192.168.1.10:80".into()),
            (Some("broken".into()), "chat.openai.com:443".into()),
        ],
        "exactly one dial per allowed flow; the failed openai flow never went direct"
    );
}
