//! `segue-relay` binary.
//!
//! ```text
//! segue-relay run <relay.json>
//! segue-relay keygen <private-key-file>           # prints the public key
//! segue-relay issue-ticket --key <file> --key-id N --device D
//!             [--plan P] [--classes overseas,ai] [--ttl SECS] [--anchor NODE]
//! ```
//! `keygen` / `issue-ticket` are dev tools standing in for the control plane.

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use base64::Engine as _;
use segue_relay::config::Config;
use segue_relay::server::{serve, Relay};
use segue_relay::ticket::{generate_pkcs8, read_signer, Claims, ExitClass};
use segue_relay::{log, system_clock};

fn usage() -> ExitCode {
    eprintln!("usage: segue-relay run <relay.json> | keygen <key-file> | issue-ticket --key F --key-id N --device D [--plan P] [--classes overseas,ai] [--ttl SECS] [--anchor NODE]");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("run") if args.len() == 2 => run(Path::new(&args[1])),
        Some("keygen") if args.len() == 2 => keygen(Path::new(&args[1])),
        Some("issue-ticket") => issue(&args[1..]),
        _ => usage(),
    }
}

fn keygen(path: &Path) -> ExitCode {
    if path.exists() {
        eprintln!("{} exists; refusing to overwrite", path.display());
        return ExitCode::FAILURE;
    }
    let der = generate_pkcs8();
    let text = base64::engine::general_purpose::STANDARD.encode(&der);
    if let Err(e) = write_private(path, &text) {
        eprintln!("write {}: {e}", path.display());
        return ExitCode::FAILURE;
    }
    let s = read_signer(0, &text).expect("fresh key");
    println!(
        "{}",
        base64::engine::general_purpose::STANDARD.encode(s.public_key())
    );
    ExitCode::SUCCESS
}

#[cfg(unix)]
fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(text.as_bytes())
}

#[cfg(not(unix))]
fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    std::fs::write(path, text)
}

fn issue(args: &[String]) -> ExitCode {
    let mut key = None;
    let mut key_id = None;
    let mut device = None;
    let mut plan = String::from("dev");
    let mut classes = vec![ExitClass::Overseas];
    let mut ttl: u64 = 24 * 3600;
    let mut anchor = 0u64;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let Some(v) = it.next() else { return usage() };
        match a.as_str() {
            "--key" => key = Some(v.clone()),
            "--key-id" => key_id = v.parse::<u32>().ok(),
            "--device" => device = v.parse::<u64>().ok(),
            "--plan" => plan = v.clone(),
            "--ttl" => match v.parse() {
                Ok(t) => ttl = t,
                Err(_) => return usage(),
            },
            "--anchor" => match v.parse() {
                Ok(n) => anchor = n,
                Err(_) => return usage(),
            },
            "--classes" => {
                classes = Vec::new();
                for c in v.split(',') {
                    match c.trim() {
                        "overseas" => classes.push(ExitClass::Overseas),
                        "ai" => classes.push(ExitClass::Ai),
                        _ => return usage(),
                    }
                }
            }
            _ => return usage(),
        }
    }
    let (Some(key), Some(key_id), Some(device)) = (key, key_id, device) else {
        return usage();
    };
    let text = match std::fs::read_to_string(&key) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("read key: {e}");
            return ExitCode::FAILURE;
        }
    };
    let signer = match read_signer(key_id, &text) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let now = system_clock()();
    let claims = Claims {
        v: 1,
        key_id,
        device_id: device,
        account_id: 0,
        plan,
        exit_classes: classes,
        ai_anchor_node_id: anchor,
        not_before: now.saturating_sub(60),
        not_after: now + ttl,
    };
    println!("{}", String::from_utf8(signer.sign(&claims)).unwrap());
    ExitCode::SUCCESS
}

fn run(path: &Path) -> ExitCode {
    let cfg = match Config::load(path) {
        Ok(c) => c,
        Err(e) => {
            log!("error", "config", "error" = e);
            return ExitCode::FAILURE;
        }
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async move {
        let listen = cfg.listen;
        let relay = match Relay::new(cfg, system_clock(), None, None) {
            Ok(r) => Arc::new(r),
            Err(e) => {
                log!("error", "startup", "error" = e);
                return ExitCode::FAILURE;
            }
        };
        let listener = match tokio::net::TcpListener::bind(listen).await {
            Ok(l) => l,
            Err(e) => {
                log!(
                    "error",
                    "listen",
                    "addr" = listen.to_string(),
                    "error" = e.to_string()
                );
                return ExitCode::FAILURE;
            }
        };
        log!(
            "info",
            "relay listening",
            "addr" = listen.to_string(),
            "node_id" = relay.cfg.node_id,
            "home_lines" = relay.home.line_count(),
            "home_auto_failover" = relay.cfg.home_auto_failover
        );
        let (tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            wait_signal().await;
            let _ = tx.send(true);
        });
        serve(relay, listener, rx).await;
        ExitCode::SUCCESS
    })
}

async fn wait_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("sigterm");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
