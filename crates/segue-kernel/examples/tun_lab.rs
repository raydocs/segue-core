//! Lab only (macOS, needs root): run the TUN stack on a real utun device.
//! See lab/tun/README.md. Every TCP flow is "proxied" to a local target
//! (`--target 127.0.0.1:PORT`) over loopback, so nothing leaves the Mac;
//! UDP is echoed by an in-process fake proxy; DNS on port 53 is answered by
//! the smart DNS with fake-IPs.

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("tun_lab: macOS utun only");
}

#[cfg(target_os = "macos")]
fn main() -> std::io::Result<()> {
    mac::main()
}

#[cfg(target_os = "macos")]
mod mac {
    use std::io;
    use std::net::SocketAddr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use bytes::Bytes;
    use segue_kernel::dial::{Datagrams, DialError, Dialer, Stream, UdpSession};
    use segue_kernel::dns::{DnsSettings, SmartDns};
    use segue_kernel::fakeip::FakeIpPool;
    use segue_kernel::policy::{Policy, PolicyStore};
    use segue_kernel::rules::{Action, Cidr, CidrTable, Matcher, Rule, RuleSet};
    use segue_kernel::socks::{Kernel, SniffSettings};
    use segue_kernel::tun::{PacketIo, TunStack};
    use segue_kernel::udp::{Udp, UdpSettings};
    use segue_routing::TargetAddr;
    use tokio::io::unix::AsyncFd;
    use tokio::net::TcpStream;
    use tokio::sync::{mpsc, Mutex};

    const UTUN_CONTROL: &[u8] = b"com.apple.net.utun_control";
    const UTUN_OPT_IFNAME: libc::c_int = 2;

    struct Utun {
        fd: AsyncFd<OwnedFd>,
        name: String,
    }

    fn open_utun() -> io::Result<Utun> {
        // SAFETY: plain BSD socket calls on a fresh descriptor; every
        // struct is zero-initialised and sized as the kernel expects.
        unsafe {
            let fd = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = OwnedFd::from_raw_fd(fd);
            let mut info: libc::ctl_info = std::mem::zeroed();
            for (d, s) in info.ctl_name.iter_mut().zip(UTUN_CONTROL) {
                *d = *s as libc::c_char;
            }
            if libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &mut info) < 0 {
                return Err(io::Error::last_os_error());
            }
            let addr = libc::sockaddr_ctl {
                sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as u8,
                sc_family: libc::AF_SYSTEM as u8,
                ss_sysaddr: libc::AF_SYS_CONTROL as u16,
                sc_id: info.ctl_id,
                sc_unit: 0, // next free utunN
                sc_reserved: [0; 5],
            };
            if libc::connect(
                fd.as_raw_fd(),
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&addr) as libc::socklen_t,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut name = [0u8; 32];
            let mut len = name.len() as libc::socklen_t;
            if libc::getsockopt(
                fd.as_raw_fd(),
                libc::SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                name.as_mut_ptr().cast(),
                &mut len,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) < 0 {
                return Err(io::Error::last_os_error());
            }
            let end = name.iter().position(|b| *b == 0).unwrap_or(len as usize);
            let name = String::from_utf8_lossy(&name[..end]).into_owned();
            Ok(Utun {
                // OwnedFd keeps the descriptor open for the AsyncFd's life.
                fd: AsyncFd::register(fd)?,
                name,
            })
        }
    }

    #[async_trait]
    impl PacketIo for Utun {
        async fn recv(&self) -> io::Result<Bytes> {
            let mut buf = vec![0u8; 4 + 65_536];
            loop {
                let mut guard = self.fd.readable().await?;
                let r = guard.try_io(|fd| {
                    // SAFETY: reading into an owned buffer of its length.
                    let n =
                        unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                    if n < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                });
                match r {
                    // A 4-byte address-family header comes first.
                    Ok(Ok(n)) if n > 4 => return Ok(Bytes::copy_from_slice(&buf[4..n])),
                    Ok(Ok(_)) => continue,
                    Ok(Err(e)) => return Err(e),
                    Err(_would_block) => continue,
                }
            }
        }

        async fn send(&self, pkt: Bytes) -> io::Result<()> {
            let af = if pkt.first().map(|b| b >> 4) == Some(6) {
                libc::AF_INET6
            } else {
                libc::AF_INET
            } as u32;
            let mut frame = af.to_be_bytes().to_vec();
            frame.extend_from_slice(&pkt);
            loop {
                let mut guard = self.fd.writable().await?;
                let r = guard.try_io(|fd| {
                    // SAFETY: writing from an owned buffer of its length.
                    let n =
                        unsafe { libc::write(fd.as_raw_fd(), frame.as_ptr().cast(), frame.len()) };
                    if n < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                });
                match r {
                    Ok(Ok(())) => return Ok(()),
                    // A full interface queue drops the packet, like a NIC.
                    Ok(Err(e)) if e.raw_os_error() == Some(libc::ENOBUFS) => return Ok(()),
                    Ok(Err(e)) => return Err(e),
                    Err(_would_block) => continue,
                }
            }
        }
    }

    /// Every TCP flow goes to `target` on loopback (logged with its tag and
    /// requested destination); UDP is echoed back with an `echo:` prefix.
    struct LabDialer {
        target: SocketAddr,
    }

    #[async_trait]
    impl Dialer for LabDialer {
        async fn dial(
            &self,
            tag: Option<&str>,
            addr: &TargetAddr,
            port: u16,
        ) -> Result<Stream, DialError> {
            println!("DIAL tcp tag={tag:?} target={addr:?} port={port}");
            if tag == Some("broken") {
                return Err(DialError("lab: broken route".into()));
            }
            let s = TcpStream::connect(self.target)
                .await
                .map_err(|e| DialError(e.to_string()))?;
            Ok(Box::new(s))
        }

        async fn dial_udp(
            &self,
            tag: Option<&str>,
            addr: &TargetAddr,
            port: u16,
        ) -> Result<Datagrams, DialError> {
            println!("DIAL udp tag={tag:?} target={addr:?} port={port}");
            let (tx, rx) = mpsc::channel(8);
            Ok(Box::new(Echo {
                tx,
                rx: Mutex::new(rx),
                from: (addr.clone(), port),
            }))
        }
    }

    struct Echo {
        tx: mpsc::Sender<Vec<u8>>,
        rx: Mutex<mpsc::Receiver<Vec<u8>>>,
        from: (TargetAddr, u16),
    }

    #[async_trait]
    impl UdpSession for Echo {
        fn max_payload(&self, _: &TargetAddr, _: u16) -> usize {
            1200
        }
        async fn send(&self, _: &TargetAddr, _: u16, p: &[u8]) -> Result<(), DialError> {
            let mut v = b"echo:".to_vec();
            v.extend_from_slice(p);
            self.tx.send(v).await.map_err(|e| DialError(e.to_string()))
        }
        async fn recv(&self, buf: &mut Vec<u8>) -> Result<(TargetAddr, u16), DialError> {
            let v = self
                .rx
                .lock()
                .await
                .recv()
                .await
                .ok_or(DialError("closed".into()))?;
            buf.clear();
            buf.extend_from_slice(&v);
            Ok(self.from.clone())
        }
    }

    fn rules() -> RuleSet {
        let rule = |matcher, action| Rule { matcher, action };
        RuleSet::new(
            vec![
                rule(
                    Matcher::DomainSuffix("openai.com".into()),
                    Action::Proxy("ai".into()),
                ),
                rule(Matcher::DomainSuffix("blocked.test".into()), Action::Reject),
                rule(
                    Matcher::Cidr(Cidr::parse("198.51.100.200/32").unwrap()),
                    Action::Reject,
                ),
                rule(
                    Matcher::Cidr(Cidr::parse("198.51.100.201/32").unwrap()),
                    Action::Proxy("broken".into()),
                ),
            ],
            Action::Proxy("lab".into()),
        )
    }

    fn key() -> [u8; 32] {
        let mut k = [0u8; 32];
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes();
        k[..16].copy_from_slice(&t);
        k
    }

    pub fn main() -> io::Result<()> {
        let target: SocketAddr = std::env::args()
            .skip_while(|a| a != "--target")
            .nth(1)
            .unwrap_or_else(|| "127.0.0.1:8099".into())
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e}")))?;
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async move {
            let tun = Arc::new(open_utun()?);
            let pool = Arc::new(
                FakeIpPool::new(
                    "198.18.0.0".parse().unwrap(),
                    15,
                    Duration::from_secs(60),
                    Duration::from_secs(600),
                    key(),
                )
                .map_err(io::Error::other)?,
            );
            let policy = PolicyStore::inline(Policy::inline(rules(), CidrTable::default()));
            let kernel = Arc::new(Kernel {
                policy: policy.clone(),
                dialer: Arc::new(LabDialer { target }),
                fake_ip: Some(pool.clone()),
                sniff: Some(SniffSettings {
                    timeout: Duration::from_millis(300),
                    max_bytes: 16 * 1024,
                }),
                udp: Some(Arc::new(Udp::new(UdpSettings {
                    refuse: ["ai".to_string()].into(),
                    ..Default::default()
                }))),
            });
            let dns = Arc::new(SmartDns::new(
                policy,
                pool,
                DnsSettings {
                    // Only names with a rule are asked in this lab; anything
                    // else times out against the discard port.
                    domestic: vec!["127.0.0.1:9".parse().unwrap()],
                    foreign: Action::Proxy("lab".into()),
                    query_timeout: Duration::from_millis(500),
                    cache_size: 256,
                },
            ));
            let stack = TunStack::for_kernel(kernel, Some(dns));
            println!("BUDGET {:?}", stack.memory_budget());
            println!("UTUN {}", tun.name);
            stack.run(tun).await
        })
    }
}
