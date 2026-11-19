//! Local control API for the app UI.
//!
//! HTTP/1.1 + JSON on a loopback TCP address only (config validation
//! refuses anything else). Every start draws a fresh random 256-bit token
//! and writes `{"addr": "...", "token": "..."}` to the token file (mode
//! 0600) so only this user's UI can drive the kernel. One request per
//! connection.
//!
//! | Request | Body | Answer |
//! |---|---|---|
//! | `GET /v1/status` | | `{"state", "posture", "exit_choice", "current_exit", "exits", "revoked", "control_refused", "policy", "tun"}` |
//!
//! `exits` is `[{"name": "la", "quality": {"srtt_ms", "loss", "stalls"}}]`:
//! the measured path quality behind the `auto` exit choice (see
//! [`crate::session::ExitQuality`]). `srtt_ms` is `null` until the first
//! control PING/PONG; `loss` is the fraction of sent bytes replayed onto a
//! new carrier; `stalls` counts carriers given up with something expected
//! on them.
//! | `POST /v1/connect` | | status |
//! | `POST /v1/disconnect` | | status |
//! | `POST /v1/exit` | `{"exit": "auto" \| "la" \| "ny" ...}` | status |
//!
//! `state` is what the UI shows: `connected`, `reconnecting` (connecting,
//! re-attaching or no carrier available, i.e. the kill switch is holding
//! traffic) or `disconnected` (user turned it off).
//!
//! `control_refused` lists the exits whose relay refused the control
//! stream for good, `[{"exit": "la", "code": 1}]` with the `REJECT` code
//! (SESSION_PROTOCOL §8; `1` = version, e.g. after a mixed-version deploy,
//! `2` = auth, ...). Data sessions may still work, so `state` can be
//! `connected` meanwhile; the UI tells the user to reconnect or update.
//! Kept while disconnected, cleared by the next `POST /v1/connect` (r12
//! #2).
//!
//! Requests need `Authorization: Bearer <token>`. Requests carrying an
//! `Origin` header (a web page) or a `Host` that is not a loopback name are
//! refused, which closes the DNS-rebinding route into a loopback server.
//!
//! `tun.interface` is the utun name while one is open, otherwise `null`.
//! `tun.routes` is `installed` after the split defaults are in, and `absent`
//! otherwise (no tun mode, or not up yet).

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::killswitch::Posture;
use crate::policy::PolicyStore;
use crate::session::{ExitChoice, KernelDialer};

const MAX_HEAD: usize = 8 << 10;
const MAX_BODY: usize = 4 << 10;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Control {
    dialer: Arc<KernelDialer>,
    policy: Arc<PolicyStore>,
    token: String,
    tun: Mutex<TunSnapshot>,
}

/// What `GET /v1/status` reports about the utun.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunSnapshot {
    pub interface: Option<String>,
    /// `absent` or `installed`.
    pub routes: &'static str,
}

impl TunSnapshot {
    pub const ABSENT: &'static str = "absent";
    pub const INSTALLED: &'static str = "installed";

    pub fn absent() -> Self {
        Self {
            interface: None,
            routes: Self::ABSENT,
        }
    }
}

/// A fresh random token: 32 bytes, hex.
pub fn new_token() -> String {
    let b: [u8; 32] = rand::random();
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Control {
    pub fn new(dialer: Arc<KernelDialer>, policy: Arc<PolicyStore>, token: String) -> Self {
        Self {
            dialer,
            policy,
            token,
            tun: Mutex::new(TunSnapshot::absent()),
        }
    }

    /// Publish the utun the process is holding. `routes` is
    /// [`TunSnapshot::ABSENT`] or [`TunSnapshot::INSTALLED`].
    pub fn set_tun(&self, interface: Option<String>, routes: &'static str) {
        let mut tun = self.tun.lock().unwrap_or_else(|e| e.into_inner());
        tun.interface = interface;
        tun.routes = routes;
    }

    pub fn status(&self) -> Value {
        let s = self.dialer.status();
        let state = match s.posture {
            Posture::Connected => "connected",
            Posture::Disconnected => "disconnected",
            Posture::Connecting | Posture::Reconnecting | Posture::Error => "reconnecting",
        };
        let posture = match s.posture {
            Posture::Connecting => "connecting",
            Posture::Connected => "connected",
            Posture::Reconnecting => "reconnecting",
            Posture::Error => "error",
            Posture::Disconnected => "disconnected",
        };
        let tun = self.tun.lock().unwrap_or_else(|e| e.into_inner()).clone();
        json!({
            "state": state,
            "posture": posture,
            "exit_choice": s.choice.name(),
            "current_exit": s.current_exit,
            "exits": s
                .quality
                .iter()
                .map(|e| {
                    json!({
                        "name": e.name,
                        "quality": {
                            "srtt_ms": e.quality.srtt.map(|d| d.as_millis() as u64),
                            "loss": e.quality.loss,
                            "stalls": e.quality.stalls,
                        },
                    })
                })
                .collect::<Vec<_>>(),
            "revoked": s.revoked.is_some(),
            "control_refused": s
                .control_refused
                .iter()
                .map(|(exit, code)| json!({"exit": exit, "code": code}))
                .collect::<Vec<_>>(),
            "policy": self.policy.status(),
            "tun": {
                "interface": tun.interface,
                "routes": tun.routes,
            },
        })
    }

    /// Dispatch one request. Returns (HTTP status, JSON body).
    pub async fn handle(&self, method: &str, path: &str, body: &[u8]) -> (u16, Value) {
        match (method, path) {
            ("GET", "/v1/status") => (200, self.status()),
            ("POST", "/v1/connect") => {
                self.dialer.connect();
                // Establish a carrier now so `state` turns connected
                // without waiting for the first flow. Failure is reported
                // by the posture, not as an API error.
                let _ = self.dialer.probe().await;
                (200, self.status())
            }
            ("POST", "/v1/disconnect") => {
                self.dialer.disconnect();
                (200, self.status())
            }
            ("POST", "/v1/exit") => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Req {
                    exit: String,
                }
                let req: Req = match serde_json::from_slice(body) {
                    Ok(r) => r,
                    Err(e) => return (400, json!({"error": format!("bad body: {e}")})),
                };
                if let Err(e) = self.dialer.set_exit(&req.exit) {
                    return (400, json!({"error": e.0}));
                }
                if self.dialer.status().choice != ExitChoice::Auto {
                    let _ = self.dialer.probe().await;
                }
                (200, self.status())
            }
            (_, "/v1/status" | "/v1/connect" | "/v1/disconnect" | "/v1/exit") => {
                (405, json!({"error": "method not allowed"}))
            }
            _ => (404, json!({"error": "not found"})),
        }
    }
}

/// Write the token file (fresh, mode 0600, replacing an old one).
pub fn write_token_file(path: &Path, addr: SocketAddr, token: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    let text = json!({"addr": addr.to_string(), "token": token}).to_string();
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    o.open(&tmp)?.write_all(text.as_bytes())?;
    std::fs::rename(&tmp, path)
}

pub async fn serve(listener: TcpListener, control: Arc<Control>) -> std::io::Result<()> {
    loop {
        let (conn, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        let c = control.clone();
        tokio::spawn(async move {
            let _ = conn_once(conn, &c).await;
        });
    }
}

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

async fn read_request(conn: &mut TcpStream) -> Result<Request, u16> {
    let mut buf = Vec::with_capacity(1024);
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        if buf.len() > MAX_HEAD {
            return Err(431);
        }
        let mut chunk = [0u8; 1024];
        match conn.read(&mut chunk).await {
            Ok(0) | Err(_) => return Err(400),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| 400u16)?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let (method, path, version) = (first.next(), first.next(), first.next());
    let (Some(method), Some(path), Some(v)) = (method, path, version) else {
        return Err(400);
    };
    if !v.starts_with("HTTP/1.") {
        return Err(400);
    }
    let mut headers = Vec::new();
    for l in lines {
        let (k, v) = l.split_once(':').ok_or(400u16)?;
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }
    let mut req = Request {
        method: method.to_string(),
        path: path.to_string(),
        headers,
        body: Vec::new(),
    };
    if req.header("transfer-encoding").is_some() {
        return Err(400);
    }
    let len: usize = match req.header("content-length") {
        None => 0,
        Some(v) => v.parse().map_err(|_| 400u16)?,
    };
    if len > MAX_BODY {
        return Err(413);
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        let mut chunk = [0u8; 1024];
        match conn.read(&mut chunk).await {
            Ok(0) | Err(_) => return Err(400),
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    body.truncate(len);
    req.body = body;
    Ok(req)
}

/// Constant-time comparison (no early exit on the first differing byte).
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn loopback_host(host: &str) -> bool {
    let name = match host.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(""),
        None => host.rsplit_once(':').map_or(host, |(h, _)| h),
    };
    name.eq_ignore_ascii_case("localhost")
        || name
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

async fn conn_once(mut conn: TcpStream, c: &Control) -> std::io::Result<()> {
    // The I/O is bounded; the handler is not (connect probes carriers,
    // bounded by the carrier timeout), and must not be cancelled midway.
    let req = tokio::time::timeout(IO_TIMEOUT, read_request(&mut conn))
        .await
        .unwrap_or(Err(408));
    let (code, body) = match req {
        Err(code) => (code, json!({"error": "bad request"})),
        Ok(req) => {
            let auth = req
                .header("authorization")
                .and_then(|v| v.strip_prefix("Bearer "))
                .unwrap_or("");
            if req.header("origin").is_some() {
                (403, json!({"error": "browser requests are not accepted"}))
            } else if !req.header("host").is_some_and(loopback_host) {
                (403, json!({"error": "host must be loopback"}))
            } else if !same(auth.as_bytes(), c.token.as_bytes()) {
                (401, json!({"error": "bad token"}))
            } else {
                c.handle(&req.method, &req.path, &req.body).await
            }
        }
    };
    let text = body.to_string();
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    };
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
    tokio::time::timeout(IO_TIMEOUT, async {
        conn.write_all(resp.as_bytes()).await?;
        conn.shutdown().await
    })
    .await
    .unwrap_or_else(|_| Err(std::io::ErrorKind::TimedOut.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dial::{DialError, Dialer, Stream};
    use crate::policy::Policy;
    use crate::rules::{Action, CidrTable, RuleSet};
    use crate::session::{Exit, SegueRoute, EXIT_AI};
    use async_trait::async_trait;
    use segue_routing::TargetAddr;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Carriers to `reality-la` / `hy2-ny` connect to a TCP sink when up.
    struct Engine {
        up: AtomicBool,
        sink: SocketAddr,
    }

    #[async_trait]
    impl Dialer for Engine {
        async fn dial(&self, _: Option<&str>, _: &TargetAddr, _: u16) -> Result<Stream, DialError> {
            if !self.up.load(Ordering::SeqCst) {
                return Err(DialError("down".into()));
            }
            Ok(Box::new(TcpStream::connect(self.sink).await.unwrap()))
        }
    }

    struct Api {
        addr: SocketAddr,
        token: String,
        engine: Arc<Engine>,
    }

    async fn start() -> Api {
        let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sink_addr = sink.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((c, _)) = sink.accept().await {
                held.push(c);
            }
        });
        let engine = Arc::new(Engine {
            up: AtomicBool::new(true),
            sink: sink_addr,
        });
        let exits = ["la", "ny"]
            .iter()
            .enumerate()
            .map(|(i, n)| Exit {
                name: n.to_string(),
                carrier: format!("c-{n}"),
                redundant_carrier: None,
                relay: "127.0.0.1:7443".parse().unwrap(),
                node_id: i as u64 + 1,
                egress_group: String::new(),
            })
            .collect();
        let routes = [(
            "ai".to_string(),
            SegueRoute {
                ticket: vec![1],
                exit_class: EXIT_AI,
            },
        )]
        .into();
        let dialer = Arc::new(KernelDialer::new(
            engine.clone(),
            exits,
            routes,
            ["ai".to_string()].into(),
        ));
        let policy = PolicyStore::inline(Policy::inline(
            RuleSet::new(Vec::new(), Action::Reject),
            CidrTable::default(),
        ));
        let token = new_token();
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(serve(
            l,
            Arc::new(Control::new(dialer, policy, token.clone())),
        ));
        Api {
            addr,
            token,
            engine,
        }
    }

    async fn call(api: &Api, method: &str, path: &str, headers: &str, body: &str) -> (u16, Value) {
        let mut c = TcpStream::connect(api.addr).await.unwrap();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{headers}Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        c.write_all(req.as_bytes()).await.unwrap();
        let mut out = String::new();
        c.read_to_string(&mut out).await.unwrap();
        let code = out[9..12].parse().unwrap();
        let json = out.split_once("\r\n\r\n").unwrap().1;
        (code, serde_json::from_str(json).unwrap())
    }

    async fn authed(api: &Api, method: &str, path: &str, body: &str) -> (u16, Value) {
        let h = format!("Authorization: Bearer {}\r\n", api.token);
        call(api, method, path, &h, body).await
    }

    #[tokio::test]
    async fn status_connect_disconnect_exit() {
        let api = start().await;
        let (code, s) = authed(&api, "GET", "/v1/status", "").await;
        assert_eq!(code, 200);
        assert_eq!(s["state"], "reconnecting", "{s}");
        assert_eq!(s["posture"], "connecting");
        assert_eq!(s["exit_choice"], "auto");
        assert_eq!(s["current_exit"], "la");
        assert_eq!(s["exits"][0]["name"], "la");
        assert_eq!(s["exits"][1]["name"], "ny");
        assert!(
            s["exits"][0]["quality"]["srtt_ms"].is_null(),
            "no sample yet"
        );
        assert_eq!(s["exits"][0]["quality"]["loss"], 0.0);
        assert_eq!(s["exits"][0]["quality"]["stalls"], 0);
        assert_eq!(s["policy"]["source"], "inline");
        assert!(s["tun"]["interface"].is_null());
        assert_eq!(s["tun"]["routes"], "absent");

        let (_, s) = authed(&api, "POST", "/v1/connect", "").await;
        assert_eq!(s["state"], "connected", "{s}");

        let (code, s) = authed(&api, "POST", "/v1/exit", r#"{"exit":"ny"}"#).await;
        assert_eq!(code, 200);
        assert_eq!(
            (&s["exit_choice"], &s["current_exit"]),
            (&json!("ny"), &json!("ny"))
        );
        let (code, s) = authed(&api, "POST", "/v1/exit", r#"{"exit":"tokyo"}"#).await;
        assert_eq!(code, 400, "{s}");
        let (code, _) = authed(&api, "POST", "/v1/exit", r#"{"exit":1}"#).await;
        assert_eq!(code, 400);
        let (_, s) = authed(&api, "POST", "/v1/exit", r#"{"exit":"auto"}"#).await;
        assert_eq!(s["exit_choice"], "auto");

        let (_, s) = authed(&api, "POST", "/v1/disconnect", "").await;
        assert_eq!(s["state"], "disconnected");
        // Connect while every carrier fails: reconnecting (kill switch
        // holding), not an API error.
        api.engine.up.store(false, Ordering::SeqCst);
        let (code, s) = authed(&api, "POST", "/v1/connect", "").await;
        assert_eq!(code, 200);
        assert_eq!(s["state"], "reconnecting", "{s}");
        assert_eq!(s["posture"], "error");
    }

    #[tokio::test]
    async fn token_origin_host_method_checks() {
        let api = start().await;
        let (code, _) = call(&api, "GET", "/v1/status", "", "").await;
        assert_eq!(code, 401, "no token");
        let (code, _) = call(
            &api,
            "GET",
            "/v1/status",
            "Authorization: Bearer nope\r\n",
            "",
        )
        .await;
        assert_eq!(code, 401, "wrong token");
        let other = new_token();
        let (code, _) = call(
            &api,
            "POST",
            "/v1/disconnect",
            &format!("Authorization: Bearer {other}\r\n"),
            "",
        )
        .await;
        assert_eq!(code, 401, "token of another start");
        let h = format!(
            "Authorization: Bearer {}\r\nOrigin: http://evil.example\r\n",
            api.token
        );
        let (code, _) = call(&api, "POST", "/v1/disconnect", &h, "").await;
        assert_eq!(code, 403, "browser origin");
        // DNS rebinding: Host is the attacker's name.
        let mut c = TcpStream::connect(api.addr).await.unwrap();
        let req = format!(
            "GET /v1/status HTTP/1.1\r\nHost: evil.example\r\nAuthorization: Bearer {}\r\n\r\n",
            api.token
        );
        c.write_all(req.as_bytes()).await.unwrap();
        let mut out = String::new();
        c.read_to_string(&mut out).await.unwrap();
        assert!(out.starts_with("HTTP/1.1 403"), "{out}");
        let (code, _) = authed(&api, "GET", "/v1/disconnect", "").await;
        assert_eq!(code, 405);
        let (code, _) = authed(&api, "GET", "/v1/nope", "").await;
        assert_eq!(code, 404);
        let (_, s) = authed(&api, "GET", "/v1/status", "").await;
        assert_ne!(
            s["state"], "disconnected",
            "refused requests changed nothing"
        );
    }

    #[tokio::test]
    async fn tun_status_reports_the_interface() {
        let api = start().await;
        let (code, s) = authed(&api, "GET", "/v1/status", "").await;
        assert_eq!(code, 200);
        assert_eq!(s["tun"]["routes"], TunSnapshot::ABSENT);
        // The HTTP test does not hold the Control. The setter is covered by
        // building one the same way `start` does and reading `status` directly.
        let dialer = Arc::new(crate::session::KernelDialer::new(
            api.engine.clone(),
            vec![crate::session::Exit {
                name: "la".into(),
                carrier: "c".into(),
                redundant_carrier: None,
                relay: "127.0.0.1:1".parse().unwrap(),
                node_id: 1,
                egress_group: String::new(),
            }],
            std::collections::BTreeMap::new(),
            std::collections::BTreeSet::new(),
        ));
        let policy = PolicyStore::inline(Policy::inline(
            RuleSet::new(Vec::new(), Action::Reject),
            CidrTable::default(),
        ));
        let ctl = Control::new(dialer, policy, "t".into());
        assert_eq!(ctl.status()["tun"]["routes"], "absent");
        ctl.set_tun(Some("utun3".into()), TunSnapshot::INSTALLED);
        let s = ctl.status();
        assert_eq!(s["tun"]["interface"], "utun3");
        assert_eq!(s["tun"]["routes"], "installed");
    }

    #[test]
    fn token_file_is_private_and_replaced() {
        let dir = std::env::temp_dir().join(format!("segue-ctl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("control.json");
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        write_token_file(&p, addr, "aa").unwrap();
        write_token_file(&p, addr, "bb").unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(v, json!({"addr": "127.0.0.1:5000", "token": "bb"}));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn host_check() {
        for h in [
            "127.0.0.1:9",
            "localhost:1",
            "[::1]:5",
            "LOCALHOST",
            "127.0.0.1",
        ] {
            assert!(loopback_host(h), "{h}");
        }
        for h in [
            "evil.com:9",
            "10.0.0.1:1",
            "[fe80::1]:5",
            "",
            "localhost.evil.com",
        ] {
            assert!(!loopback_host(h), "{h}");
        }
    }

    #[test]
    fn token_is_random_hex() {
        let (a, b) = (new_token(), new_token());
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
        assert!(same(a.as_bytes(), a.as_bytes()));
        assert!(!same(a.as_bytes(), b.as_bytes()));
        assert!(!same(a.as_bytes(), &a.as_bytes()[..63]));
    }
}
