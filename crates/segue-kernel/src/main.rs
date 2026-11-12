use std::path::Path;
use std::sync::Arc;

use segue_kernel::config::KernelConfig;
use segue_kernel::dial::EngineDialer;
use segue_kernel::dns::{serve_tcp, serve_udp, SmartDns};
use segue_kernel::fakeip::FakeIpPool;
use segue_kernel::socks::{serve, Kernel};
use segue_kernel::udp::Udp;

fn main() {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: segue-kernel <kernel.json>");
            std::process::exit(2);
        }
    };
    if let Err(e) = run(&path) {
        eprintln!("segue-kernel: {e}");
        std::process::exit(1);
    }
}

fn run(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)?;
    let base = Path::new(path).parent().unwrap_or(Path::new("."));
    let config = KernelConfig::parse_in(&text, base)?;
    // One worker thread: the target is a phone VPN extension.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let dialer = Arc::new(EngineDialer::new(&config.outbounds)?);
        let listener = tokio::net::TcpListener::bind(config.listen).await?;
        eprintln!("segue-kernel: listening on {}", listener.local_addr()?);
        let mut fake_ip = None;
        if let Some(d) = config.dns {
            // No persisted key yet (spec §5.2.2): fake-IPs are stable only
            // within one process lifetime.
            let pool = Arc::new(FakeIpPool::new(
                d.fake_ip_base,
                d.fake_ip_prefix,
                d.fake_ip_ttl,
                d.fake_ip_grace,
                rand::random(),
            )?);
            let dns = Arc::new(SmartDns::new(
                config.rules.clone(),
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
            rules: config.rules,
            dialer,
            fake_ip,
            sniff: config.sniff,
            udp: config.udp.map(|u| Arc::new(Udp::new(u))),
        });
        serve(listener, kernel).await?;
        Ok(())
    })
}
