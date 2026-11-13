//! segue-kernel run <kernel.json>        (or just `segue-kernel <kernel.json>`)
//! segue-kernel policy-keygen <key-file> # prints the public key (base64)
//! segue-kernel sign-bundle --key F --key-id N <body.json> > policy.bundle
//!
//! `policy-keygen` / `sign-bundle` are dev tools standing in for the
//! control plane's policy compiler (CONTROL_PLANE_SPEC §6).

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use segue_kernel::config::KernelConfig;
use segue_kernel::control::{self, Control};
use segue_kernel::dial::EngineDialer;
use segue_kernel::dns::{serve_tcp, serve_udp, SmartDns};
use segue_kernel::fakeip::FakeIpPool;
use segue_kernel::policy;
use segue_kernel::session::KernelDialer;
use segue_kernel::socks::{serve, Kernel};
use segue_kernel::udp::Udp;

fn usage() -> ExitCode {
    eprintln!(
        "usage: segue-kernel [run] <kernel.json> | policy-keygen <key-file> | sign-bundle --key F --key-id N <body.json>"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("run") if args.len() == 2 => run(&args[1]),
        Some("policy-keygen") if args.len() == 2 => keygen(Path::new(&args[1])),
        Some("sign-bundle") => sign(&args[1..]),
        Some(p) if args.len() == 1 && !p.starts_with('-') => run(p),
        _ => return usage(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("segue-kernel: {e}");
            ExitCode::FAILURE
        }
    }
}

fn keygen(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if path.exists() {
        return Err(format!("{} exists; refusing to overwrite", path.display()).into());
    }
    let (private, public) = policy::generate_key();
    policy::write_private_key(path, &private)?;
    println!("{public}");
    Ok(())
}

fn sign(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let (mut key, mut key_id, mut body) = (None, None, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--key" => key = it.next().cloned(),
            "--key-id" => key_id = it.next().map(|v| v.parse::<u32>()).transpose()?,
            p if body.is_none() && !p.starts_with('-') => body = Some(p.to_string()),
            other => return Err(format!("unexpected argument {other:?}").into()),
        }
    }
    let (Some(key), Some(key_id), Some(body)) = (key, key_id, body) else {
        return Err("sign-bundle needs --key, --key-id and a body file".into());
    };
    let private = policy::read_private_key(Path::new(&key))?;
    let body = std::fs::read(&body)?;
    println!("{}", policy::sign(&private, key_id, &body)?);
    Ok(())
}

fn run(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)?;
    let base = Path::new(path).parent().unwrap_or(Path::new("."));
    let config = KernelConfig::parse_in(&text, base)?;
    for line in &config.policy_log {
        eprintln!("segue-kernel: {line}");
    }
    // One worker thread: the target is a phone VPN extension.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let dialer = Arc::new(KernelDialer::new(
            Arc::new(EngineDialer::new(&config.outbounds)?),
            config.exits.clone(),
            config.segue.clone(),
            config.home.clone(),
        ));
        let listener = tokio::net::TcpListener::bind(config.listen).await?;
        eprintln!("segue-kernel: listening on {}", listener.local_addr()?);
        if let Some(c) = &config.control {
            let l = tokio::net::TcpListener::bind(c.listen).await?;
            let addr = l.local_addr()?;
            let token = control::new_token();
            control::write_token_file(&c.token_file, addr, &token)?;
            eprintln!(
                "segue-kernel: control on {addr} (token in {})",
                c.token_file.display()
            );
            let ctl = Arc::new(Control::new(dialer.clone(), config.policy.clone(), token));
            tokio::spawn(control::serve(l, ctl));
        }
        let mut fake_ip = None;
        if let Some(d) = config.dns {
            // Key + bindings persisted (spec §5.2.2), so a restart never
            // reinterprets an address a client still caches.
            let (pool, log) = FakeIpPool::open(
                d.fake_ip_base,
                d.fake_ip_prefix,
                d.fake_ip_ttl,
                d.fake_ip_grace,
                d.fake_ip_max_entries,
                d.fake_ip_state.as_deref(),
            )?;
            for line in log {
                eprintln!("segue-kernel: {line}");
            }
            let pool = Arc::new(pool);
            {
                // New bindings are journaled (on the pool's persistence
                // thread) before their answer; this only keeps last-use
                // times and compacts the journal, also off this thread.
                let pool = pool.clone();
                tokio::spawn(async move {
                    let mut tick = tokio::time::interval(segue_kernel::fakeip::SAVE_INTERVAL);
                    loop {
                        tick.tick().await;
                        if let Err(e) = pool.save_durable().await {
                            eprintln!("segue-kernel: fake-ip state: {e}");
                        }
                    }
                });
            }
            let dns = Arc::new(SmartDns::new(
                config.policy.clone(),
                pool.clone(),
                d.settings,
            ));
            let udp = tokio::net::UdpSocket::bind(d.listen).await?;
            let tcp = tokio::net::TcpListener::bind(d.listen).await?;
            eprintln!("segue-kernel: dns on {} (udp+tcp)", udp.local_addr()?);
            tokio::spawn(serve_udp(udp, dns.clone()));
            tokio::spawn(serve_tcp(tcp, dns));
            fake_ip = Some(pool);
        }
        let kernel = Arc::new(Kernel {
            policy: config.policy,
            dialer,
            fake_ip,
            sniff: config.sniff,
            udp: config.udp.map(|u| Arc::new(Udp::new(u))),
        });
        serve(listener, kernel).await?;
        Ok(())
    })
}
