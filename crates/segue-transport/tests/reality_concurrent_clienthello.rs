//! Xray-core #7306: a burst of REALITY dials sent only the first TCP segment
//! of the ClientHello and never the tail. Every concurrent dial on loopback
//! must deliver a whole ClientHello record.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use segue_routing::{Network, Target, TargetAddr};
use segue_transport::{
    RealityClientConfig, RealityRuntimeEngine, RealityTlsEngine, RustlsRealityTlsSessionProvider,
};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const DIALS: usize = 16;

#[tokio::test]
async fn concurrent_reality_dials_send_complete_client_hellos() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind fake REALITY server");
    let addr = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let mut hellos = Vec::with_capacity(DIALS);
        for _ in 0..DIALS {
            let (socket, _) = timeout(Duration::from_secs(10), listener.accept())
                .await
                .expect("dial accepted in time")
                .expect("accept");
            hellos.push(
                timeout(Duration::from_secs(10), read_tls_record(socket))
                    .await
                    .expect("ClientHello arrived in time")
                    .expect("read ClientHello"),
            );
        }
        hellos
    });

    let engine = Arc::new(RealityRuntimeEngine::new(Arc::new(
        RustlsRealityTlsSessionProvider::new(),
    )));
    let target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp);
    let mut clients = Vec::with_capacity(DIALS);
    for _ in 0..DIALS {
        let engine = Arc::clone(&engine);
        let target = target.clone();
        clients.push(tokio::spawn(async move {
            let config = RealityClientConfig {
                server_name: "www.example.com".to_owned(),
                fingerprint: "chrome".to_owned(),
                public_key: [9; 32],
                short_id: vec![2, 3, 4, 5],
                spider_x: "/".to_owned(),
                mldsa65_verify: None,
            };
            // The fake server records the hello and drops the socket, so the
            // handshake itself fails. The assertion is on the bytes written.
            let _ = engine.connect_socket_addr(&config, &target, addr).await;
        }));
    }

    let hellos = timeout(Duration::from_secs(20), server)
        .await
        .expect("every dial produced a ClientHello")
        .expect("server task");
    assert_eq!(hellos.len(), DIALS);
    for hello in &hellos {
        assert!(hello.len() > 5, "empty ClientHello");
        assert_eq!(hello[0], 0x16, "not a handshake record");
        assert_eq!(hello[5], 0x01, "not a ClientHello");
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(
            hello.len(),
            5 + record_len,
            "ClientHello record truncated at {} bytes, header says {record_len}",
            hello.len()
        );
        let handshake_len =
            ((hello[6] as usize) << 16) | ((hello[7] as usize) << 8) | (hello[8] as usize);
        assert_eq!(
            handshake_len + 4,
            record_len,
            "ClientHello body does not fill its record"
        );
        // Chrome's hybrid hello is larger than a typical MSS. A first-segment
        // -only write would have failed the length check above; this pins the
        // size so a later fingerprint shrink does not hide the bug.
        assert!(
            hello.len() > 1452,
            "ClientHello is only {} bytes, shorter than one segment",
            hello.len()
        );
    }

    for client in clients {
        timeout(Duration::from_secs(5), client)
            .await
            .expect("dial task finished")
            .expect("dial task");
    }
}

async fn read_tls_record(mut socket: TcpStream) -> std::io::Result<Vec<u8>> {
    let mut header = [0_u8; 5];
    socket.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len > 20_000 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TLS record longer than a ClientHello",
        ));
    }
    let mut body = vec![0_u8; len];
    socket.read_exact(&mut body).await?;
    let mut record = header.to_vec();
    record.extend(body);
    Ok(record)
}
