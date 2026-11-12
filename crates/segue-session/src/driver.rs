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

use crate::client::{ClientSession, CloseReason, State};
use crate::codec::{code, Frame, FrameDecoder, Kind, SessionId, Target};
use crate::relay::{RelayEvent, RelayTable};
use crate::ProtoError;

pub trait Carrier: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Carrier for T {}

pub type BoxCarrier = Box<dyn Carrier>;
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
/// Opens a new carrier to the relay (client side).
pub type Connector = Arc<dyn Fn() -> BoxFuture<io::Result<BoxCarrier>> + Send + Sync>;
/// Connects to a site (relay side). An error carrying a [`SiteError`] is
/// answered with that code; any other error with `connect_refused`.
pub type SiteConnector =
    Arc<dyn Fn(Target, Kind) -> BoxFuture<io::Result<BoxCarrier>> + Send + Sync>;
/// Like [`SiteConnector`], also given the device the ticket authorized
/// and the client's (untrusted) exit class hint.
pub type DeviceSiteConnector =
    Arc<dyn Fn(SiteRequest) -> BoxFuture<io::Result<BoxCarrier>> + Send + Sync>;

/// One site connect request (relay side).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteRequest {
    pub session_id: SessionId,
    pub device: u64,
    pub target: Target,
    pub kind: Kind,
    pub exit_class: u8,
}

/// A site connect failure with a specific §8 code (e.g. `exit_denied`,
/// `target_denied`, `home_unavailable`). Wrap it with `io::Error::other`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SiteError(pub u8);

impl std::fmt::Display for SiteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "site connect refused with code {}", self.0)
    }
}

impl std::error::Error for SiteError {}

impl SiteError {
    pub fn io(code: u8) -> io::Error {
        io::Error::other(SiteError(code))
    }

    /// The code an error from a [`SiteConnector`] maps to.
    pub fn code_of(e: &io::Error) -> u8 {
        e.get_ref()
            .and_then(|x| x.downcast_ref::<SiteError>())
            .map_or(code::CONNECT_REFUSED, |x| x.0)
    }
}

/// Commands into a running relay driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayCtrl {
    /// RST every session of `device` with `close_code` (revocation, admin).
    ResetDevice { device: u64, close_code: u8 },
}

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
/// Dropping the sender flushes what is queued and shuts down (the owner
/// bounds that with [`Tasks::drain`] or aborts the task). A write failure
/// closes the queue (later sends fail, nothing is silently swallowed) and
/// runs `on_err`, which reports it to the state machine.
fn spawn_writer<W, F>(
    mut w: W,
    writable: Arc<Notify>,
    on_err: F,
) -> (mpsc::Sender<Vec<u8>>, JoinHandle<()>)
where
    W: AsyncWrite + Unpin + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
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
                drop(rx);
                on_err.await;
                return;
            }
        }
        let _ = w.shutdown().await;
    });
    (tx, h)
}

/// How long a cleanly closed connection may take to flush what is queued.
const DRAIN: std::time::Duration = std::time::Duration::from_secs(1);

/// Tasks a driver still owns after their connection left its tables:
/// writers flushing a clean close, each with a deadline after which it is
/// aborted. Everything left is aborted when the driver ends.
#[derive(Default)]
struct Tasks {
    draining: Vec<(tokio::time::Instant, JoinHandle<()>)>,
}

impl Tasks {
    fn drain(&mut self, h: JoinHandle<()>) {
        self.draining.push((tokio::time::Instant::now() + DRAIN, h));
    }

    /// Forget finished tasks and abort overdue ones.
    fn prune(&mut self) {
        let now = tokio::time::Instant::now();
        self.draining.retain(|(d, h)| {
            if h.is_finished() {
                false
            } else if *d <= now {
                h.abort();
                false
            } else {
                true
            }
        });
    }

    fn next_deadline(&self) -> Option<tokio::time::Instant> {
        self.draining.iter().map(|(d, _)| *d).min()
    }

    /// Wait for every draining task until its deadline, then abort it.
    async fn finish(mut self) {
        for (d, mut h) in std::mem::take(&mut self.draining) {
            if tokio::time::timeout_at(d, &mut h).await.is_err() {
                h.abort();
            }
        }
    }
}

impl Drop for Tasks {
    fn drop(&mut self) {
        for (_, h) in &self.draining {
            h.abort();
        }
    }
}

struct CarrierIo {
    tx: mpsc::Sender<Vec<u8>>,
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
}

/// Run one client session over carriers from `connect`, bridging `app`.
/// Returns how the local connection ended.
pub async fn run_client<A>(s: ClientSession, app: A, connect: Connector) -> CloseReason
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    run_client_ctl(s, app, connect, ClientCtl::default()).await
}

/// Optional hooks for [`run_client_ctl`].
#[derive(Default)]
pub struct ClientCtl {
    /// Every change (a network-change epoch) moves the session to a new
    /// carrier with RESUME (KERNEL_SPEC §7.2 "网络变化").
    pub reattach: Option<tokio::sync::watch::Receiver<u64>>,
    /// Receives how the session ended as soon as it is known, before the
    /// app stream is shut down, so the caller can tell a clean EOF from a
    /// reset (the app stream itself can only show EOF).
    pub closed: Option<tokio::sync::oneshot::Sender<CloseReason>>,
    /// Fires once, when the relay first answers OPENED, so the caller can
    /// report success to the app only after the relay accepted the flow.
    pub opened: Option<tokio::sync::oneshot::Sender<()>>,
}

/// [`run_client`] with hooks.
pub async fn run_client_ctl<A>(
    mut s: ClientSession,
    app: A,
    connect: Connector,
    ctl: ClientCtl,
) -> CloseReason
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ClientCtl {
        mut reattach,
        closed,
        mut opened,
    } = ctl;
    let writable = Arc::new(Notify::new());
    let (mut app_r, app_w) = tokio::io::split(app);
    // The app stopped taking data: the download cannot complete, reset.
    let (app_err_tx, mut app_err_rx) = tokio::sync::oneshot::channel::<()>();
    let (app_tx, app_writer) = spawn_writer(app_w, writable.clone(), async move {
        let _ = app_err_tx.send(());
    });
    let mut app_failed = false;
    let (ev_tx, mut ev_rx) = mpsc::channel::<CarrierEv>(64);
    let (conn_tx, mut conn_rx) = mpsc::channel::<(u64, io::Result<BoxCarrier>)>(4);
    let mut carriers: HashMap<u64, CarrierIo> = HashMap::new();
    let mut tasks = Tasks::default();
    let mut dial: Option<JoinHandle<()>> = None;
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
            dial = Some(tokio::spawn(async move {
                let _ = tx.send((cid, fut.await)).await;
            }));
        }
        for old in s.take_abandoned() {
            if let Some(io) = carriers.remove(&old) {
                io.reader.abort();
                io.writer.abort();
            }
        }
        tasks.prune();
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
        while app_tx.capacity() > 0 && !app_shut && !app_tx.is_closed() {
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
        if s.state() == State::Active {
            if let Some(tx) = opened.take() {
                let _ = tx.send(());
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
        let drain = tasks.next_deadline();
        tokio::select! {
            ev = ev_rx.recv() => {
                let t = now();
                match ev {
                    Some(CarrierEv::Frame(cid, Ok(f))) => { let _ = s.on_frame(cid, f, t); }
                    Some(CarrierEv::Frame(cid, Err(e))) => s.on_decode_error(cid, e),
                    Some(CarrierEv::Closed(cid)) => {
                        s.on_carrier_closed(cid, t);
                        if let Some(io) = carriers.remove(&cid) {
                            io.reader.abort();
                            io.writer.abort();
                        }
                    }
                    None => {}
                }
            }
            c = conn_rx.recv() => {
                connecting = false;
                dial = None;
                if let Some((cid, res)) = c {
                    match res {
                        Ok(stream) => {
                            connect_backoff = None;
                            let (r, w) = tokio::io::split(stream);
                            let reader = spawn_reader(cid, r, ev_tx.clone());
                            let etx = ev_tx.clone();
                            let (tx, writer) = spawn_writer(w, writable.clone(), async move {
                                let _ = etx.send(CarrierEv::Closed(cid)).await;
                            });
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
            r = async { reattach.as_mut().expect("guarded").changed().await }, if reattach.is_some() => {
                match r {
                    Ok(()) => s.reattach(now()),
                    Err(_) => reattach = None,
                }
            }
            r = &mut app_err_rx, if !app_failed => {
                app_failed = true;
                if r.is_ok() {
                    s.abort();
                }
            }
            _ = writable.notified() => {}
            _ = tokio::time::sleep_until(deadline.unwrap_or_else(tokio::time::Instant::now)), if deadline.is_some() => {}
            _ = tokio::time::sleep_until(backoff.unwrap_or_else(tokio::time::Instant::now)), if backoff.is_some() => {}
            _ = tokio::time::sleep_until(drain.unwrap_or_else(tokio::time::Instant::now)), if drain.is_some() => {}
        }
    }
    if let Some(h) = dial.take() {
        h.abort();
    }
    let reason = s
        .close_reason()
        .unwrap_or(CloseReason::Reset(code::INTERNAL));
    if let Some(tx) = closed {
        let _ = tx.send(reason);
    }
    // A clean close can be learnt from a REJECT(closed) (B6) while received
    // data is still buffered: it belongs to the app.
    // Bounded: an app that stopped reading cannot hold the session open.
    let until = tokio::time::Instant::now() + DRAIN;
    if reason == CloseReason::Clean && !app_shut {
        let _ = tokio::time::timeout_at(until, async {
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
        })
        .await;
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
    // The final RST / ACK gets a bounded flush; a dead carrier is not
    // waited for.
    for (_, io) in carriers.drain() {
        io.reader.abort();
        tasks.drain(io.writer);
    }
    drop(app_tx);
    if reason == CloseReason::Clean {
        tasks.drain(app_writer);
    } else {
        // Not clean: nothing more reaches the app; dropping the stream lets
        // the caller turn the reason into a reset.
        app_writer.abort();
    }
    tasks.finish().await;
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
    writer: JoinHandle<()>,
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
    table: RelayTable,
    accept: mpsc::Receiver<BoxCarrier>,
    site: SiteConnector,
    notices: Option<mpsc::UnboundedSender<RelayNotice>>,
) {
    let site: DeviceSiteConnector = Arc::new(move |r: SiteRequest| site(r.target, r.kind));
    run_relay_ctl(table, accept, site, notices, None).await
}

/// [`run_relay`] with a command channel (revocation resets).
pub async fn run_relay_ctl(
    mut table: RelayTable,
    mut accept: mpsc::Receiver<BoxCarrier>,
    site: DeviceSiteConnector,
    notices: Option<mpsc::UnboundedSender<RelayNotice>>,
    mut ctrl: Option<mpsc::Receiver<RelayCtrl>>,
) {
    let writable = Arc::new(Notify::new());
    let (ev_tx, mut ev_rx) = mpsc::channel::<CarrierEv>(64);
    let (site_tx, mut site_rx) = mpsc::channel::<SiteEv>(64);
    let mut carriers: HashMap<u64, CarrierIo> = HashMap::new();
    let mut sites: HashMap<SessionId, SiteIo> = HashMap::new();
    // Site connects in flight, cancelled when their session ends.
    let mut dials: HashMap<SessionId, JoinHandle<()>> = HashMap::new();
    let mut tasks = Tasks::default();
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
                    device,
                    target,
                    kind,
                    exit_class,
                } => {
                    let fut = site(SiteRequest {
                        session_id,
                        device,
                        target,
                        kind,
                        exit_class,
                    });
                    let tx = site_tx.clone();
                    let h = tokio::spawn(async move {
                        let _ = tx.send(SiteEv::Connected(session_id, fut.await)).await;
                    });
                    if let Some(old) = dials.insert(session_id, h) {
                        old.abort();
                    }
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
                    if let Some(h) = dials.remove(&session_id) {
                        h.abort();
                    }
                    if let Some(io) = sites.remove(&session_id) {
                        io.reader.abort();
                        if close_code == code::CLEAN {
                            // Everything was delivered to the relay; let the
                            // writer finish handing it to the site, bounded.
                            drop(io.tx);
                            tasks.drain(io.writer);
                        } else {
                            // Reset / revoke: queued data must not reach the
                            // site and its socket must not outlive the session.
                            io.writer.abort();
                        }
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
                // Flush the final RST / REJECT, bounded.
                drop(io.tx);
                tasks.drain(io.writer);
            }
            table.on_carrier_closed(cid, t);
        }
        tasks.prune();
        for (sid, io) in sites.iter_mut() {
            while io.tx.capacity() > 0 && !io.shut && !io.tx.is_closed() {
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
            for (_, h) in dials.drain() {
                h.abort();
            }
            tasks.finish().await;
            return;
        }
        let deadline = table.poll_timeout().map(tokio::time::Instant::from_std);
        let drain = tasks.next_deadline();
        tokio::select! {
            c = accept.recv(), if accepting => match c {
                Some(stream) => {
                    next_cid += 1;
                    let cid = next_cid;
                    let (r, w) = tokio::io::split(stream);
                    let reader = spawn_reader(cid, r, ev_tx.clone());
                    let etx = ev_tx.clone();
                    let (tx, writer) = spawn_writer(w, writable.clone(), async move {
                        let _ = etx.send(CarrierEv::Closed(cid)).await;
                    });
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
                        if let Some(io) = carriers.remove(&cid) {
                            io.reader.abort();
                            io.writer.abort();
                        }
                        table.on_carrier_closed(cid, t);
                    }
                    None => {}
                }
            }
            ev = site_rx.recv() => {
                let t = now();
                match ev {
                    Some(SiteEv::Connected(sid, Ok(stream))) => {
                        dials.remove(&sid);
                        if table.state(&sid).is_none() {
                            // Session ended while connecting (RST / timeout):
                            // drop the site connection instead of leaking it.
                            drop(stream);
                            continue;
                        }
                        let (mut r, w) = tokio::io::split(stream);
                        let etx = site_tx.clone();
                        let (tx, writer) = spawn_writer(w, writable.clone(), async move {
                            let _ = etx.send(SiteEv::Error(sid)).await;
                        });
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
                        sites.insert(sid, SiteIo { tx, req, reader, writer, outstanding: false, shut: false, eof: false });
                        table.connect_done(&sid, Ok(()), t);
                    }
                    Some(SiteEv::Connected(sid, Err(e))) => {
                        dials.remove(&sid);
                        table.connect_done(&sid, Err(SiteError::code_of(&e)), t);
                    }
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
            c = async { ctrl.as_mut().unwrap().recv().await }, if ctrl.is_some() => match c {
                Some(RelayCtrl::ResetDevice { device, close_code }) => table.reset_device(device, close_code),
                None => ctrl = None,
            },
            _ = writable.notified() => {}
            _ = tokio::time::sleep_until(deadline.unwrap_or_else(tokio::time::Instant::now)), if deadline.is_some() => {}
            _ = tokio::time::sleep_until(drain.unwrap_or_else(tokio::time::Instant::now)), if drain.is_some() => {}
        }
    }
}
