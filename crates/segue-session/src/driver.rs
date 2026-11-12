//! Async glue: runs the sans-IO machines over any `AsyncRead + AsyncWrite`.
//!
//! Every carrier and site connection gets one reader task and one writer
//! task; the state machine itself lives in a single task. Writer channels
//! are small and frames are generated from state only when a channel has
//! room, so nothing queues without bound. Site reads are requested one at a
//! time and never larger than the session's replay capacity.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;

use crate::client::{ClientSession, CloseReason};
use crate::codec::{code, Frame, FrameDecoder, Kind, SessionId, Target};
use crate::relay::{RelayEvent, RelayTable};
use crate::ProtoError;

pub trait Carrier: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Carrier for T {}

pub type BoxCarrier = Box<dyn Carrier>;
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
/// Opens a new carrier to the relay (client side).
pub type Connector = Arc<dyn Fn() -> BoxFuture<io::Result<BoxCarrier>> + Send + Sync>;
/// Connects to a site (relay side).
pub type SiteConnector =
    Arc<dyn Fn(Target, Kind) -> BoxFuture<io::Result<BoxCarrier>> + Send + Sync>;

/// Frames per writer channel.
const WRITE_QUEUE: usize = 8;
const CHUNK: usize = 16 * 1024;

fn now() -> std::time::Instant {
    tokio::time::Instant::now().into_std()
}

enum CarrierEv {
    Frame(u64, Result<Frame, ProtoError>),
    Closed(u64),
}

/// Reader task: decode frames until EOF or a decode error.
fn spawn_reader<R: AsyncRead + Unpin + Send + 'static>(
    cid: u64,
    mut r: R,
    tx: mpsc::Sender<CarrierEv>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut dec = FrameDecoder::new();
        let mut buf = vec![0u8; CHUNK];
        loop {
            match r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => dec.push(&buf[..n]),
            }
            loop {
                match dec.next_frame() {
                    Ok(Some(f)) => {
                        if tx.send(CarrierEv::Frame(cid, Ok(f))).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        let _ = tx.send(CarrierEv::Frame(cid, Err(e))).await;
                        let _ = tx.send(CarrierEv::Closed(cid)).await;
                        return;
                    }
                }
            }
        }
        let _ = tx.send(CarrierEv::Closed(cid)).await;
    })
}

/// Writer task: write each message; an empty message shuts the write side.
/// Dropping the sender flushes what is queued and shuts down.
fn spawn_writer<W: AsyncWrite + Unpin + Send + 'static>(
    mut w: W,
    writable: Arc<Notify>,
) -> (mpsc::Sender<Vec<u8>>, JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(WRITE_QUEUE);
    let h = tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            let r = if m.is_empty() {
                w.shutdown().await
            } else {
                w.write_all(&m).await
            };
            writable.notify_one();
            if r.is_err() {
                // Keep draining so the sender never blocks on a dead peer.
                while rx.recv().await.is_some() {
                    writable.notify_one();
                }
                return;
            }
        }
        let _ = w.shutdown().await;
    });
    (tx, h)
}

struct CarrierIo {
    tx: mpsc::Sender<Vec<u8>>,
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
}

/// Run one client session over carriers from `connect`, bridging `app`.
/// Returns how the local connection ended.
pub async fn run_client<A>(mut s: ClientSession, app: A, connect: Connector) -> CloseReason
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let writable = Arc::new(Notify::new());
    let (mut app_r, app_w) = tokio::io::split(app);
    let (app_tx, app_writer) = spawn_writer(app_w, writable.clone());
    let (ev_tx, mut ev_rx) = mpsc::channel::<CarrierEv>(64);
    let (conn_tx, mut conn_rx) = mpsc::channel::<(u64, io::Result<BoxCarrier>)>(4);
    let mut carriers: HashMap<u64, CarrierIo> = HashMap::new();
    let mut finished: Vec<JoinHandle<()>> = Vec::new();
    let mut next_cid = 0u64;
    let mut connecting = false;
    let mut connect_backoff: Option<tokio::time::Instant> = None;
    let mut app_eof = false;
    let mut app_shut = false;
    let mut abuf = vec![0u8; CHUNK];
    let mut rbuf = vec![0u8; CHUNK];

    loop {
        let t = now();
        s.handle_timeout(t);
        let backoff_ok = connect_backoff.is_none_or(|b| tokio::time::Instant::now() >= b);
        if !connecting && backoff_ok && s.wants_attach(t) {
            connecting = true;
            next_cid += 1;
            let cid = next_cid;
            let fut = connect();
            let tx = conn_tx.clone();
            tokio::spawn(async move {
                let _ = tx.send((cid, fut.await)).await;
            });
        }
        for old in s.take_abandoned() {
            if let Some(io) = carriers.remove(&old) {
                io.reader.abort();
                finished.push(io.writer);
            }
        }
        // Carrier output, generated only while the writer has room.
        if let Some(cid) = s.carrier() {
            if let Some(io) = carriers.get(&cid) {
                while io.tx.capacity() > 0 {
                    match s.poll_transmit(cid, t) {
                        Some(f) => {
                            let _ = io.tx.try_send(f.to_bytes());
                        }
                        None => break,
                    }
                }
            }
        }
        // Data for the app.
        while app_tx.capacity() > 0 && !app_shut {
            let n = s.read(&mut rbuf, t);
            if n > 0 {
                let _ = app_tx.try_send(rbuf[..n].to_vec());
            } else {
                if s.read_eof() {
                    let _ = app_tx.try_send(Vec::new());
                    app_shut = true;
                }
                break;
            }
        }
        if s.is_closed() {
            break;
        }
        let cap = if app_eof {
            0
        } else {
            s.write_capacity().min(CHUNK)
        };
        let deadline = s.poll_timeout().map(tokio::time::Instant::from_std);
        let backoff = connect_backoff.filter(|_| !connecting);
        tokio::select! {
            ev = ev_rx.recv() => {
                let t = now();
                match ev {
                    Some(CarrierEv::Frame(cid, Ok(f))) => { let _ = s.on_frame(cid, f, t); }
                    Some(CarrierEv::Frame(cid, Err(e))) => s.on_decode_error(cid, e),
                    Some(CarrierEv::Closed(cid)) => {
                        s.on_carrier_closed(cid, t);
                        if let Some(io) = carriers.remove(&cid) {
                            finished.push(io.writer);
                        }
                    }
                    None => {}
                }
            }
            c = conn_rx.recv() => {
                connecting = false;
                if let Some((cid, res)) = c {
                    match res {
                        Ok(stream) => {
                            connect_backoff = None;
                            let (r, w) = tokio::io::split(stream);
                            let reader = spawn_reader(cid, r, ev_tx.clone());
                            let (tx, writer) = spawn_writer(w, writable.clone());
                            carriers.insert(cid, CarrierIo { tx, reader, writer });
                            s.attach(cid, now());
                        }
                        Err(_) => {
                            connect_backoff = Some(tokio::time::Instant::now() + std::time::Duration::from_millis(200));
                        }
                    }
                }
            }
            r = app_r.read(&mut abuf[..cap.max(1)]), if cap > 0 => {
                match r {
                    Ok(0) => { app_eof = true; s.close_write(); }
                    // A read error is not a clean end of the upload: reset,
                    // never FIN (the site must not see a truncated stream as
                    // complete).
                    Err(_) => { app_eof = true; s.abort(); }
                    Ok(n) => { let w = s.write(&abuf[..n]); debug_assert_eq!(w, n); }
                }
            }
            _ = writable.notified() => {}
            _ = tokio::time::sleep_until(deadline.unwrap_or_else(tokio::time::Instant::now)), if deadline.is_some() => {}
            _ = tokio::time::sleep_until(backoff.unwrap_or_else(tokio::time::Instant::now)), if backoff.is_some() => {}
        }
    }
    let reason = s
        .close_reason()
        .unwrap_or(CloseReason::Reset(code::INTERNAL));
    // A clean close can be learnt from a REJECT(closed) (B6) while received
    // data is still buffered: it belongs to the app.
    if reason == CloseReason::Clean && !app_shut {
        loop {
            let n = s.read(&mut rbuf, now());
            if n == 0 {
                break;
            }
            if app_tx.send(rbuf[..n].to_vec()).await.is_err() {
                break;
            }
        }
        if s.read_eof() {
            let _ = app_tx.send(Vec::new()).await;
        }
    }
    // Flush a final RST / ACK on the current carrier, then close everything.
    if let Some(cid) = s.carrier() {
        if let Some(io) = carriers.get(&cid) {
            while let Some(f) = s.poll_transmit(cid, now()) {
                if io.tx.try_send(f.to_bytes()).is_err() {
                    break;
                }
            }
        }
    }
    for (_, io) in carriers.drain() {
        io.reader.abort();
        finished.push(io.writer);
    }
    drop(app_tx);
    finished.push(app_writer);
    for h in finished {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), h).await;
    }
    reason
}

enum SiteEv {
    Connected(SessionId, io::Result<BoxCarrier>),
    /// Empty = EOF.
    Data(SessionId, Vec<u8>),
    Error(SessionId),
}

struct SiteIo {
    tx: mpsc::Sender<Vec<u8>>,
    req: mpsc::Sender<usize>,
    reader: JoinHandle<()>,
    outstanding: bool,
    shut: bool,
    eof: bool,
}

/// What the relay driver reports besides carrying data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayNotice {
    /// Would go on the device's control stream (not part of this crate).
    Stall {
        device: u64,
        session_id: SessionId,
        attach_gen: u32,
    },
    Closed {
        session_id: SessionId,
        close_code: u8,
    },
}

/// Run a relay table over carriers from `accept` and sites from `site`.
/// Returns when `accept` is closed and no carriers or sessions remain.
pub async fn run_relay(
    mut table: RelayTable,
    mut accept: mpsc::Receiver<BoxCarrier>,
    site: SiteConnector,
    notices: Option<mpsc::UnboundedSender<RelayNotice>>,
) {
    let writable = Arc::new(Notify::new());
    let (ev_tx, mut ev_rx) = mpsc::channel::<CarrierEv>(64);
    let (site_tx, mut site_rx) = mpsc::channel::<SiteEv>(64);
    let mut carriers: HashMap<u64, CarrierIo> = HashMap::new();
    let mut sites: HashMap<SessionId, SiteIo> = HashMap::new();
    let mut next_cid = 0u64;
    let mut accepting = true;
    let mut buf = vec![0u8; CHUNK];

    loop {
        let t = now();
        table.handle_timeout(t);
        while let Some(ev) = table.take_event() {
            match ev {
                RelayEvent::Connect {
                    session_id,
                    target,
                    kind,
                } => {
                    let fut = site(target, kind);
                    let tx = site_tx.clone();
                    tokio::spawn(async move {
                        let _ = tx.send(SiteEv::Connected(session_id, fut.await)).await;
                    });
                }
                RelayEvent::Stall {
                    device,
                    session_id,
                    attach_gen,
                } => {
                    if let Some(n) = &notices {
                        let _ = n.send(RelayNotice::Stall {
                            device,
                            session_id,
                            attach_gen,
                        });
                    }
                }
                RelayEvent::Closed {
                    session_id,
                    close_code,
                } => {
                    if let Some(io) = sites.remove(&session_id) {
                        io.reader.abort();
                    }
                    if let Some(n) = &notices {
                        let _ = n.send(RelayNotice::Closed {
                            session_id,
                            close_code,
                        });
                    }
                }
            }
        }
        for (&cid, io) in &carriers {
            while io.tx.capacity() > 0 {
                match table.poll_transmit(cid, t) {
                    Some(f) => {
                        let _ = io.tx.try_send(f.to_bytes());
                    }
                    None => break,
                }
            }
        }
        for cid in table.take_closed_carriers() {
            if let Some(io) = carriers.remove(&cid) {
                while let Some(f) = table.poll_transmit(cid, t) {
                    if io.tx.try_send(f.to_bytes()).is_err() {
                        break;
                    }
                }
                io.reader.abort();
            }
            table.on_carrier_closed(cid, t);
        }
        for (sid, io) in sites.iter_mut() {
            while io.tx.capacity() > 0 && !io.shut {
                let n = table.read(sid, &mut buf, t);
                if n > 0 {
                    let _ = io.tx.try_send(buf[..n].to_vec());
                } else {
                    if table.read_eof(sid) {
                        let _ = io.tx.try_send(Vec::new());
                        io.shut = true;
                    }
                    break;
                }
            }
            if !io.outstanding && !io.eof {
                let cap = table.site_read_capacity(sid).min(CHUNK);
                if cap > 0 && io.req.try_send(cap).is_ok() {
                    io.outstanding = true;
                }
            }
        }
        if !accepting && carriers.is_empty() && table.session_count() == 0 {
            return;
        }
        let deadline = table.poll_timeout().map(tokio::time::Instant::from_std);
        tokio::select! {
            c = accept.recv(), if accepting => match c {
                Some(stream) => {
                    next_cid += 1;
                    let cid = next_cid;
                    let (r, w) = tokio::io::split(stream);
                    let reader = spawn_reader(cid, r, ev_tx.clone());
                    let (tx, writer) = spawn_writer(w, writable.clone());
                    carriers.insert(cid, CarrierIo { tx, reader, writer });
                    table.add_carrier(cid);
                }
                None => accepting = false,
            },
            ev = ev_rx.recv() => {
                let t = now();
                match ev {
                    Some(CarrierEv::Frame(cid, Ok(f))) => table.on_frame(cid, f, t),
                    Some(CarrierEv::Frame(cid, Err(e))) => table.on_decode_error(cid, e),
                    Some(CarrierEv::Closed(cid)) => {
                        carriers.remove(&cid);
                        table.on_carrier_closed(cid, t);
                    }
                    None => {}
                }
            }
            ev = site_rx.recv() => {
                let t = now();
                match ev {
                    Some(SiteEv::Connected(sid, Ok(stream))) => {
                        if table.state(&sid).is_none() {
                            // Session ended while connecting (RST / timeout):
                            // drop the site connection instead of leaking it.
                            drop(stream);
                            continue;
                        }
                        let (mut r, w) = tokio::io::split(stream);
                        let (tx, _writer) = spawn_writer(w, writable.clone());
                        let (req, mut req_rx) = mpsc::channel::<usize>(1);
                        let stx = site_tx.clone();
                        let reader = tokio::spawn(async move {
                            let mut b = vec![0u8; CHUNK];
                            while let Some(n) = req_rx.recv().await {
                                match r.read(&mut b[..n]).await {
                                    Ok(0) => { let _ = stx.send(SiteEv::Data(sid, Vec::new())).await; return; }
                                    Ok(k) => { if stx.send(SiteEv::Data(sid, b[..k].to_vec())).await.is_err() { return; } }
                                    Err(_) => { let _ = stx.send(SiteEv::Error(sid)).await; return; }
                                }
                            }
                        });
                        sites.insert(sid, SiteIo { tx, req, reader, outstanding: false, shut: false, eof: false });
                        table.connect_done(&sid, Ok(()), t);
                    }
                    Some(SiteEv::Connected(sid, Err(_))) => table.connect_done(&sid, Err(code::CONNECT_REFUSED), t),
                    Some(SiteEv::Data(sid, d)) => {
                        if let Some(io) = sites.get_mut(&sid) {
                            io.outstanding = false;
                            if d.is_empty() {
                                io.eof = true;
                                table.site_fin(&sid);
                            } else {
                                let n = table.site_data(&sid, &d);
                                debug_assert_eq!(n, d.len());
                            }
                        }
                    }
                    Some(SiteEv::Error(sid)) => table.site_reset(&sid),
                    None => {}
                }
            }
            _ = writable.notified() => {}
            _ = tokio::time::sleep_until(deadline.unwrap_or_else(tokio::time::Instant::now)), if deadline.is_some() => {}
        }
    }
}
