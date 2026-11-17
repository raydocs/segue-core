//! segue-kernel run [--state-dir DIR] [--log PATH] <kernel.json>
//! segue-kernel policy-keygen <key-file> # prints the public key (base64)
//! segue-kernel sign-bundle --key F --key-id N <body.json> > policy.bundle
//!
//! `policy-keygen` / `sign-bundle` are dev tools standing in for the
//! control plane's policy compiler (CONTROL_PLANE_SPEC §6).
//!
//! Exit codes are [`segue_kernel::process::ExitCode`]: 0 clean (also
//! `--help`), 1 runtime, 2 usage, 3 config or state path, 4 tun setup.
//! `SIGTERM` and `SIGINT` flush the fake-IP journal, remove the control
//! token and exit 0. The same cleanup runs when a listener fails; that
//! path still exits 1.

use std::io;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use segue_kernel::config::KernelConfig;
use segue_kernel::control::{self, Control};
use segue_kernel::dial::EngineDialer;
use segue_kernel::dns::{serve_tcp, serve_udp, SmartDns};
use segue_kernel::fakeip::FakeIpPool;
use segue_kernel::killswitch::FlowPosture;
use segue_kernel::policy;
use segue_kernel::process::{self, Args, ExitCode as Code, Log, RunArgs, RunFailure};
use segue_kernel::session::KernelDialer;
use segue_kernel::socks::{serve, Kernel};
use segue_kernel::udp::Udp;

fn usage_text() {
    eprintln!(
        "\
usage:
  segue-kernel [run] [--state-dir DIR] [--log PATH] <kernel.json>
  segue-kernel policy-keygen <key-file>
  segue-kernel sign-bundle --key F --key-id N <body.json>

exit codes: 0 clean shutdown or --help, 1 runtime failure, 2 usage,
            3 config or state path rejected, 4 tun setup failed"
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match process::parse_args(&args) {
        Ok(Args::Help) => {
            usage_text();
            Code::Clean.to_process()
        }
        Ok(Args::Keygen(path)) => tool(keygen(&path)),
        Ok(Args::Sign(rest)) => tool(sign(&rest)),
        Ok(Args::Run(run)) => match run_kernel(&run) {
            Ok(code) => code.to_process(),
            Err(e) => {
                eprintln!("segue-kernel: {e}");
                e.code().to_process()
            }
        },
        Err(e) => {
            eprintln!("segue-kernel: {e}");
            usage_text();
            Code::Usage.to_process()
        }
    }
}

/// Dev tools keep the historical "1 on any error" status.
fn tool(result: Result<(), Box<dyn std::error::Error>>) -> ExitCode {
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

fn run_kernel(args: &RunArgs) -> Result<Code, RunFailure> {
    if let Some(dir) = &args.state_dir {
        process::create_state_dir(dir)
            .map_err(|e| RunFailure::config(format!("state dir {}: {e}", dir.display())))?;
    }
    let log = Log::open(args.log.as_deref()).map_err(|e| {
        let path = args.log.as_deref().unwrap_or(Path::new("-"));
        RunFailure::config(format!("log {}: {e}", path.display()))
    })?;
    let text = std::fs::read_to_string(&args.config)
        .map_err(|e| RunFailure::config(format!("{}: {e}", args.config.display())))?;
    let base = args.config.parent().unwrap_or(Path::new("."));
    let config = KernelConfig::parse_with(&text, base, args.state_dir.as_deref())
        .map_err(RunFailure::config)?;
    for line in &config.policy_log {
        log.line(line);
    }
    // One worker thread: the target is a phone VPN extension.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| RunFailure::runtime(format!("runtime: {e}")))?;
    runtime.block_on(run_session(&config, &log))
}

async fn run_session(config: &KernelConfig, log: &Log) -> Result<Code, RunFailure> {
    let dialer = Arc::new(KernelDialer::new(
        Arc::new(
            EngineDialer::new(&config.outbounds)
                .map_err(|e| RunFailure::runtime(format!("dialer: {e}")))?,
        ),
        config.exits.clone(),
        config.segue.clone(),
        config.home.clone(),
    ));
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|e| RunFailure::runtime(format!("listen {}: {e}", config.listen)))?;
    let listen_at = listener
        .local_addr()
        .map_err(|e| RunFailure::runtime(format!("listen: {e}")))?;
    log.line(format!("listening on {listen_at}"));
    if let Some(c) = &config.control {
        let l = tokio::net::TcpListener::bind(c.listen)
            .await
            .map_err(|e| RunFailure::runtime(format!("control {}: {e}", c.listen)))?;
        let addr = l
            .local_addr()
            .map_err(|e| RunFailure::runtime(format!("control: {e}")))?;
        let token = control::new_token();
        control::write_token_file(&c.token_file, addr, &token)
            .map_err(|e| RunFailure::runtime(format!("token {}: {e}", c.token_file.display())))?;
        log.line(format!(
            "control on {addr} (token in {})",
            c.token_file.display()
        ));
        let ctl = Arc::new(Control::new(dialer.clone(), config.policy.clone(), token));
        tokio::spawn(control::serve(l, ctl));
    }
    let mut fake_ip = None;
    if let Some(d) = &config.dns {
        // Key + bindings persisted (spec §5.2.2), so a restart never
        // reinterprets an address a client still caches.
        let (pool, lines) = FakeIpPool::open(
            d.fake_ip_base,
            d.fake_ip_prefix,
            d.fake_ip_ttl,
            d.fake_ip_grace,
            d.fake_ip_max_entries,
            d.fake_ip_state.as_deref(),
        )
        .map_err(|e| RunFailure::runtime(format!("fake-ip: {e}")))?;
        for line in lines {
            log.line(line);
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
            d.settings.clone(),
        ));
        let udp = tokio::net::UdpSocket::bind(d.listen)
            .await
            .map_err(|e| RunFailure::runtime(format!("dns {}: {e}", d.listen)))?;
        let tcp = tokio::net::TcpListener::bind(d.listen)
            .await
            .map_err(|e| RunFailure::runtime(format!("dns {}: {e}", d.listen)))?;
        let dns_at = udp
            .local_addr()
            .map_err(|e| RunFailure::runtime(format!("dns: {e}")))?;
        log.line(format!("dns on {dns_at} (udp+tcp)"));
        tokio::spawn(serve_udp(udp, dns.clone()));
        tokio::spawn(serve_tcp(tcp, dns));
        fake_ip = Some(pool);
    }
    let flows: Arc<dyn FlowPosture> = dialer.clone();
    let kernel = Arc::new(Kernel {
        policy: config.policy.clone(),
        dialer,
        fake_ip: fake_ip.clone(),
        sniff: config.sniff,
        udp: config.udp.clone().map(|u| Arc::new(Udp::new(u))),
        hidden: Default::default(),
        flows: Some(flows),
    });
    let stopped = tokio::select! {
        r = serve(listener, kernel) => Stop::Serve(r),
        name = wait_for_stop() => Stop::Signal(name),
    };
    if let Some(pool) = fake_ip {
        if let Err(e) = pool.save_durable().await {
            log.line(format!("fake-ip state: {e}"));
        }
    }
    if let Some(c) = &config.control {
        if let Err(e) = std::fs::remove_file(&c.token_file) {
            if e.kind() != io::ErrorKind::NotFound {
                log.line(format!("token {}: {e}", c.token_file.display()));
            }
        }
    }
    match stopped {
        Stop::Signal(name) => {
            log.line(format!("{name}, stopped"));
            Ok(Code::Clean)
        }
        Stop::Serve(Ok(())) => {
            log.line("stopped");
            Ok(Code::Clean)
        }
        Stop::Serve(Err(e)) => Err(RunFailure::runtime(format!("socks: {e}"))),
    }
}

enum Stop {
    Serve(io::Result<()>),
    Signal(&'static str),
}

/// `SIGTERM` or `SIGINT`. A handler that cannot be installed does not
/// pretend the signal arrived; the process keeps serving.
async fn wait_for_stop() -> &'static str {
    tokio::select! {
        name = wait_sigterm() => name,
        r = tokio::signal::ctrl_c() => {
            if let Err(e) = r {
                eprintln!("segue-kernel: SIGINT handler: {e}");
                std::future::pending::<()>().await;
            }
            "SIGINT"
        }
    }
}

#[cfg(unix)]
async fn wait_sigterm() -> &'static str {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut sig) => {
            sig.recv().await;
            "SIGTERM"
        }
        Err(e) => {
            eprintln!("segue-kernel: SIGTERM handler: {e}");
            std::future::pending::<&'static str>().await
        }
    }
}

#[cfg(not(unix))]
async fn wait_sigterm() -> &'static str {
    std::future::pending::<&'static str>().await
}
