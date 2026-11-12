use std::sync::Arc;

use segue_kernel::config::KernelConfig;
use segue_kernel::dial::EngineDialer;
use segue_kernel::socks::{serve, Kernel};

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
    let config = KernelConfig::parse(&text)?;
    // One worker thread: the target is a phone VPN extension.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let dialer = Arc::new(EngineDialer::new(&config.outbounds)?);
        let listener = tokio::net::TcpListener::bind(config.listen).await?;
        eprintln!("segue-kernel: listening on {}", listener.local_addr()?);
        let kernel = Arc::new(Kernel {
            rules: config.rules,
            dialer,
        });
        serve(listener, kernel).await?;
        Ok(())
    })
}
