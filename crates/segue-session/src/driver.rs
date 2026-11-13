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
use crate::codec::{code, ty, CtrlHello, Frame, FrameDecoder, Kind, SessionId, Target};
use crate::pool::{Grant as PoolGrant, Loan, Pool, Reserve, FRAME_MAX};
use crate::relay::{Grant, RelayEvent, RelayTable};
use crate::ProtoError;

/// A spawned task owned by a driver: dropping it aborts the task, so a driver
/// future that is dropped or aborted (user disconnect, relay shutdown) takes
/// its dials, readers, writers and site sockets with it instead of leaving
/// them running detached (r5 N9).
struct Task(JoinHandle<()>);

impl Task {
    fn abort(&self) {
        self.0.abort();
    }

    fn is_finished(&self) -> bool {
        self.0.is_finished()
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn spawn<F: Future<Output = ()> + Send + 'static>(f: F) -> Task {
    Task(tokio::spawn(f))
}

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
    /// What this session's own OPEN ticket authorized.
    pub grant: Grant,
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

/// Messages per writer channel.
const WRITE_QUEUE: usize = 8;
const CHUNK: usize = 16 * 1024;

/// What covers a buffer: blocks from the pool, or a loan from the
/// session's reserve when the pool is spent (r5 N13: no buffer is outside
/// the pool, so its size is a real bound).
enum Charge {
    Pool(PoolGrant),
    Loan(Loan),
}

/// A message for a writer task, with what covers it until it is written
/// (client side: bytes leave the session's grants when they are queued, so
/// the queue is charged on its own).
struct Out {
    data: Vec<u8>,
    _charge: Option<Charge>,
}

impl From<Vec<u8>> for Out {
    fn from(data: Vec<u8>) -> Self {
        Self {
            data,
            _charge: None,
        }
    }
}

/// `data` charged with `c`, shrunk to what `data` holds.
fn charged(data: Vec<u8>, mut c: Charge) -> Out {
    match &mut c {
        Charge::Pool(g) => {
            g.try_resize(data.capacity());
        }
        Charge::Loan(l) => l.shrink(data.capacity()),
    }
    Out {
        data,
        _charge: Some(c),
    }
}

/// Cover `bytes` from the pool, else up to `loan_max` of them from
/// `reserve`. Returns the charge and how many bytes it covers; `None`:
/// wait for blocks or a returned loan.
fn try_charge(
    pool: &Arc<Pool>,
    reserve: &Arc<Reserve>,
    bytes: usize,
    loan_max: usize,
) -> Option<(Charge, usize)> {
    if let Some(g) = PoolGrant::fixed(pool, bytes) {
        return Some((Charge::Pool(g), bytes));
    }
    let n = bytes.min(loan_max);
    reserve.lend(n).map(|l| (Charge::Loan(l), n))
}

/// Until blocks or a loan come back. The short timeout only covers a
/// wake-up missed between the failed attempt and this call.
async fn freed(pool: &Pool, reserve: &Reserve) {
    tokio::select! {
        _ = pool.freed() => {}
        _ = reserve.returned() => {}
        _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
    }
}

async fn wait_charge(
    pool: &Arc<Pool>,
    reserve: &Arc<Reserve>,
    bytes: usize,
    loan_max: usize,
) -> (Charge, usize) {
    loop {
        if let Some(c) = try_charge(pool, reserve, bytes, loan_max) {
            return c;
        }
        freed(pool, reserve).await;
    }
}

/// The decoder's memory: pool blocks as far as they go, the rest lent.
struct DecoderCover {
    pool: Arc<Pool>,
    reserve: Arc<Reserve>,
    grant: PoolGrant,
    loan: Option<Loan>,
}

impl DecoderCover {
    fn try_cover(&mut self, bytes: usize) -> bool {
        if self.grant.bytes() > bytes {
            self.grant.try_resize(bytes);
        } else {
            self.grant.grow_towards(bytes);
        }
        let short = bytes.saturating_sub(self.grant.bytes());
        if short == 0 {
            self.loan = None;
            return true;
        }
        if let Some(l) = &mut self.loan {
            if l.bytes() >= short {
                l.shrink(short);
                return true;
            }
        }
        self.loan = None;
        self.loan = self.reserve.lend(short);
        self.loan.is_some()
    }

    async fn cover(&mut self, bytes: usize) {
        while !self.try_cover(bytes) {
            freed(&self.pool, &self.reserve).await;
        }
    }
}

fn now() -> std::time::Instant {
    tokio::time::Instant::now().into_std()
}

enum CarrierEv {
    /// With what covers the decoded frame until it is handled.
    Frame(u64, Result<Frame, ProtoError>, Option<Charge>),
    Closed(u64),
}

/// Reader task: decode frames until EOF or a decode error. With `pool`
/// (client side) the decoder and every decoded frame are covered by the
/// pool or `reserve`: the decoder never holds more than one frame
/// (reads stop at [`FRAME_MAX`]), and a frame that cannot be covered waits
/// before it is queued.
fn spawn_reader<R: AsyncRead + Unpin + Send + 'static>(
    cid: u64,
    mut r: R,
    tx: mpsc::Sender<CarrierEv>,
    pool: Option<(Arc<Pool>, Arc<Reserve>)>,
) -> Task {
    spawn(async move {
        let mut dec = FrameDecoder::new();
        let mut cover = pool.as_ref().map(|(p, r)| DecoderCover {
            pool: p.clone(),
            reserve: r.clone(),
            grant: PoolGrant::new(p, false),
            loan: None,
        });
        let mut buf = ReadBuffer::new(pool.as_ref().map(|(p, _)| p.clone()));
        loop {
            let mut room = buf.len();
            if let Some(c) = &mut cover {
                room = room.min(FRAME_MAX.saturating_sub(dec.buffered())).max(1);
                // `push` drops consumed bytes, then grows exactly.
                c.cover(dec.held_bytes().max(dec.buffered() + room)).await;
            }
            // A large buffer goes back once the stream has been quiet for
            // READ_IDLE (cancelling a pending read loses nothing).
            let idle = buf
                .idle_at()
                .or_else(|| (dec.held_bytes() > 0).then_some(buf.last + READ_IDLE));
            let read = match idle {
                Some(at) => match tokio::time::timeout_at(at, r.read(&mut buf.get()[..room])).await
                {
                    Ok(r) => r,
                    Err(_) => {
                        buf.shrink();
                        dec.release_idle();
                        if let Some(c) = &mut cover {
                            c.try_cover(dec.held_bytes());
                        }
                        if dec.held_bytes() > 0 {
                            // A partial frame: wait for the rest.
                            buf.last = tokio::time::Instant::now();
                        }
                        continue;
                    }
                },
                None => r.read(&mut buf.get()[..room]).await,
            };
            match read {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    dec.push(&buf.get()[..n]);
                    // A read cut short by `room` is not a slow stream.
                    buf.adapt(if n == room { buf.len() } else { n });
                }
            }
            loop {
                let before = dec.buffered();
                match dec.next_frame() {
                    Ok(Some(f)) => {
                        let charge = match &pool {
                            Some((p, r)) => {
                                let bytes = before - dec.buffered();
                                Some(wait_charge(p, r, bytes, bytes).await.0)
                            }
                            None => None,
                        };
                        if tx.send(CarrierEv::Frame(cid, Ok(f), charge)).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        let _ = tx.send(CarrierEv::Frame(cid, Err(e), None)).await;
                        let _ = tx.send(CarrierEv::Closed(cid)).await;
                        return;
                    }
                }
            }
        }
        let _ = tx.send(CarrierEv::Closed(cid)).await;
    })
}

/// A read buffer that is small while its stream is idle or slow and grows to
/// [`CHUNK`] while reads fill it, charged to `pool` when it has one (a
/// session's idle carrier or app stream then holds a few hundred bytes, not
/// 16 KiB). The decoder may still keep a partial frame.
struct ReadBuffer {
    buf: Vec<u8>,
    pool: Option<Arc<Pool>>,
    charge: Option<PoolGrant>,
    last: tokio::time::Instant,
}

const SMALL_READ: usize = 512;
/// Quiet time after which a large read buffer is released.
const READ_IDLE: std::time::Duration = std::time::Duration::from_secs(1);

impl ReadBuffer {
    fn new(pool: Option<Arc<Pool>>) -> Self {
        Self {
            buf: vec![0; SMALL_READ],
            pool,
            charge: None,
            last: tokio::time::Instant::now(),
        }
    }

    /// When a large buffer should be released if nothing is read.
    fn idle_at(&self) -> Option<tokio::time::Instant> {
        (self.buf.len() > SMALL_READ).then_some(self.last + READ_IDLE)
    }

    fn shrink(&mut self) {
        self.buf = vec![0; SMALL_READ];
        self.charge = None;
    }

    fn get(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    fn len(&self) -> usize {
        self.buf.len()
    }

    /// After a read of `n` bytes.
    fn adapt(&mut self, n: usize) {
        self.last = tokio::time::Instant::now();
        if n == self.buf.len() && self.buf.len() < CHUNK {
            let charge = match &self.pool {
                Some(p) => match PoolGrant::fixed(p, CHUNK) {
                    Some(g) => Some(g),
                    None => return,
                },
                None => None,
            };
            self.charge = charge;
            self.buf = vec![0; CHUNK];
        } else if self.buf.len() > SMALL_READ && n < SMALL_READ {
            self.shrink();
        }
    }
}

/// Writer task: write each message; an empty message shuts the write side.
/// Dropping the sender flushes what is queued and shuts down (the owner
/// bounds that with [`Tasks::drain`] or aborts the task). A write failure
/// closes the queue (later sends fail, nothing is silently swallowed) and
/// runs `on_err`, which reports it to the state machine.
fn spawn_writer<W, F>(mut w: W, writable: Arc<Notify>, on_err: F) -> (mpsc::Sender<Out>, Task)
where
    W: AsyncWrite + Unpin + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let (tx, mut rx) = mpsc::channel::<Out>(WRITE_QUEUE);
    let h = spawn(async move {
        while let Some(m) = rx.recv().await {
            let r = if m.data.is_empty() {
                w.shutdown().await
            } else {
                w.write_all(&m.data).await
            };
            drop(m);
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
    draining: Vec<(tokio::time::Instant, Task)>,
}

impl Tasks {
    fn drain(&mut self, h: Task) {
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
            if tokio::time::timeout_at(d, &mut h.0).await.is_err() {
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
    tx: mpsc::Sender<Out>,
    reader: Task,
    writer: Task,
    /// The reader's buffer (client side).
    _charge: Option<PoolGrant>,
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
    /// `STALL` hints for this session from the control stream: the
    /// relay's `attach_gen` that it saw stall (B1).
    pub stall: Option<mpsc::UnboundedReceiver<u32>>,
    /// Receives how the session ended, before the app stream is cut, so
    /// the caller can tell a clean EOF from a reset (the app stream itself
    /// can only show EOF). A reset is sent as soon as it is known; `Clean`
    /// only once every received byte reached the app, which may be after
    /// the app saw EOF. Data the app did not take within the drain bound
    /// turns a clean close into a reset.
    pub closed: Option<tokio::sync::oneshot::Sender<CloseReason>>,
    /// Fires once, when the relay first answers OPENED, so the caller can
    /// report success to the app only after the relay accepted the flow.
    pub opened: Option<tokio::sync::oneshot::Sender<()>>,
    /// Becomes `Some(code)` to reset the session locally with that code
    /// (the control stream said REVOKED, r5 N10): the reason reaches
    /// `closed` before the app stream ends, so the app sees a reset.
    pub cancel: Option<tokio::sync::watch::Receiver<Option<u8>>>,
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
        mut stall,
        mut closed,
        mut opened,
        mut cancel,
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
    let mut dial: Option<Task> = None;
    let mut next_cid = 0u64;
    let mut connecting = false;
    let mut connect_backoff: Option<tokio::time::Instant> = None;
    let mut app_eof = false;
    let mut app_shut = false;
    let pool = s.pool().clone();
    let reserve = s.reserve().clone();
    let mut abuf = ReadBuffer::new(Some(pool.clone()));
    // A queued message the pool could not cover is waiting for blocks.
    let mut pool_blocked;

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
            dial = Some(spawn(async move {
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
        pool_blocked = false;
        // Carrier output, generated only while the writer has room. Each
        // queued frame is charged to the pool, or with the pool spent to
        // the session's reserve (one frame), so the session always
        // progresses without memory outside the pool.
        if let Some(cid) = s.carrier() {
            if let Some(io) = carriers.get(&cid) {
                while io.tx.capacity() > 0 {
                    let Some((g, _)) = try_charge(&pool, &reserve.carrier, FRAME_MAX, FRAME_MAX)
                    else {
                        pool_blocked = true;
                        break;
                    };
                    match s.poll_transmit(cid, t) {
                        Some(f) => {
                            let _ = io.tx.try_send(charged(f.to_bytes(), g));
                        }
                        None => break,
                    }
                }
            }
        }
        // Data for the app, charged the same way.
        while app_tx.capacity() > 0 && !app_shut && !app_tx.is_closed() {
            let avail = s.recv_half().buffered().min(CHUNK);
            if avail > 0 {
                // Pool short: one reserved block at a time.
                let Some((g, avail)) = try_charge(&pool, &reserve.app, avail, crate::pool::BLOCK)
                else {
                    pool_blocked = true;
                    break;
                };
                let mut v = vec![0u8; avail];
                let n = s.read(&mut v, t);
                if n == 0 {
                    break;
                }
                v.truncate(n);
                let _ = app_tx.try_send(charged(v, g));
            } else {
                let _ = s.read(&mut [], t);
                if s.read_eof() {
                    let _ = app_tx.try_send(Vec::new().into());
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
        let abuf_idle = abuf.idle_at();
        let drain = tasks.next_deadline();
        tokio::select! {
            ev = ev_rx.recv() => {
                let t = now();
                match ev {
                    Some(CarrierEv::Frame(cid, Ok(f), _c)) => { let _ = s.on_frame(cid, f, t); }
                    Some(CarrierEv::Frame(cid, Err(e), _)) => s.on_decode_error(cid, e),
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
                            let reader = spawn_reader(
                                cid,
                                r,
                                ev_tx.clone(),
                                Some((pool.clone(), reserve.reader.clone())),
                            );
                            let etx = ev_tx.clone();
                            let (tx, writer) = spawn_writer(w, writable.clone(), async move {
                                let _ = etx.send(CarrierEv::Closed(cid)).await;
                            });
                            carriers.insert(cid, CarrierIo { tx, reader, writer, _charge: None });
                            s.attach(cid, now());
                        }
                        Err(_) => {
                            connect_backoff = Some(tokio::time::Instant::now() + std::time::Duration::from_millis(200));
                        }
                    }
                }
            }
            r = { let k = cap.min(abuf.len()).max(1); app_r.read(&mut abuf.get()[..k]) }, if cap > 0 => {
                match r {
                    Ok(0) => { app_eof = true; s.close_write(); }
                    // A read error is not a clean end of the upload: reset,
                    // never FIN (the site must not see a truncated stream as
                    // complete).
                    Err(_) => { app_eof = true; s.abort(); }
                    Ok(n) => {
                        let w = s.write(&abuf.get()[..n]);
                        debug_assert_eq!(w, n);
                        abuf.adapt(n);
                    }
                }
            }
            r = async { reattach.as_mut().expect("guarded").changed().await }, if reattach.is_some() => {
                match r {
                    Ok(()) => s.reattach(now()),
                    Err(_) => reattach = None,
                }
            }
            c = async {
                cancel.as_mut().expect("guarded").wait_for(Option::is_some).await.map(|c| c.unwrap_or(code::REVOKED))
            }, if cancel.is_some() => {
                match c {
                    Ok(c) => s.reset(c),
                    Err(_) => cancel = None,
                }
            }
            g = async { stall.as_mut().expect("guarded").recv().await }, if stall.is_some() => {
                match g {
                    Some(g) => s.on_stall(g, now()),
                    None => stall = None,
                }
            }
            r = &mut app_err_rx, if !app_failed => {
                app_failed = true;
                if r.is_ok() {
                    s.abort();
                }
            }
            _ = writable.notified() => {}
            _ = async {
                tokio::select! {
                    _ = pool.freed() => {}
                    _ = reserve.carrier.returned() => {}
                    _ = reserve.app.returned() => {}
                }
            }, if pool_blocked => {}
            _ = tokio::time::sleep_until(abuf_idle.unwrap_or_else(tokio::time::Instant::now)), if abuf_idle.is_some() => {
                abuf.shrink();
            }
            _ = tokio::time::sleep_until(deadline.unwrap_or_else(tokio::time::Instant::now)), if deadline.is_some() => {}
            _ = tokio::time::sleep_until(backoff.unwrap_or_else(tokio::time::Instant::now)), if backoff.is_some() => {}
            _ = tokio::time::sleep_until(drain.unwrap_or_else(tokio::time::Instant::now)), if drain.is_some() => {}
        }
    }
    if let Some(h) = dial.take() {
        h.abort();
    }
    let mut reason = s
        .close_reason()
        .unwrap_or(CloseReason::Reset(code::INTERNAL));
    // Not clean: nothing more reaches the app. The reason goes out before
    // the app stream ends, so the caller turns that end into a reset.
    if reason != CloseReason::Clean {
        if let Some(tx) = closed.take() {
            let _ = tx.send(reason);
        }
        app_writer.abort();
    }
    // A clean close can be learnt from a REJECT(closed) (B6) while received
    // data is still buffered: it belongs to the app.
    // Bounded: an app that stopped reading cannot hold the session open.
    // Clean is only reported once every byte reached the app (r5 N8): a
    // drain cut short by the deadline is a reset, never a short clean EOF.
    let until = tokio::time::Instant::now() + DRAIN;
    if reason == CloseReason::Clean {
        let mut delivered = app_shut;
        if !app_shut {
            delivered = tokio::time::timeout_at(until, async {
                loop {
                    let avail = s.recv_half().buffered().min(CHUNK);
                    if avail == 0 {
                        break;
                    }
                    let (g, avail) =
                        wait_charge(&pool, &reserve.app, avail, crate::pool::BLOCK).await;
                    let mut v = vec![0u8; avail];
                    let n = s.read(&mut v, now());
                    if n == 0 {
                        break;
                    }
                    v.truncate(n);
                    if app_tx.send(charged(v, g)).await.is_err() {
                        return false;
                    }
                }
                if s.read_eof() {
                    let _ = app_tx.send(Vec::new().into()).await;
                }
                true
            })
            .await
            .unwrap_or(false);
        }
        // The writer ends once its queue is flushed (channel closed).
        drop(app_tx);
        let mut app_writer = app_writer;
        let flushed = delivered
            && tokio::time::timeout_at(until, &mut app_writer.0)
                .await
                .is_ok_and(|r| r.is_ok())
            && app_err_rx.try_recv().is_err();
        if !flushed {
            reason = CloseReason::Reset(code::INTERNAL);
        }
        if let Some(tx) = closed.take() {
            let _ = tx.send(reason);
        }
        // Aborted only after the reason is out (no-op when finished).
        app_writer.abort();
    } else {
        drop(app_tx);
    }
    // Flush a final RST / ACK on the current carrier, then close everything.
    if let Some(cid) = s.carrier() {
        if let Some(io) = carriers.get(&cid) {
            while let Some(f) = s.poll_transmit(cid, now()) {
                if io.tx.try_send(f.to_bytes().into()).is_err() {
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
    tx: mpsc::Sender<Out>,
    req: mpsc::Sender<usize>,
    reader: Task,
    writer: Task,
    outstanding: bool,
    shut: bool,
    eof: bool,
    /// Resets the session if the site writer has not flushed the upload
    /// and shut down within [`SITE_FLUSH`] of the client's FIN.
    flush_timer: Option<Task>,
}

/// How long the site writer may take, after the client's FIN, to hand the
/// rest of the upload to the site and shut its write side down. Only then
/// is the FIN acknowledged and the session can end CLEAN (r6: a truncated
/// upload must never be reported clean); past this it is reset.
const SITE_FLUSH: std::time::Duration = std::time::Duration::from_secs(30);

/// The site's write half: reports once its shutdown completed, i.e. every
/// byte before it was written and the FIN went out.
struct SiteWrite<W> {
    inner: W,
    sid: SessionId,
    flushed: Option<mpsc::UnboundedSender<SessionId>>,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for SiteWrite<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let r = std::task::ready!(Pin::new(&mut self.inner).poll_shutdown(cx));
        if r.is_ok() {
            if let Some(tx) = self.flushed.take() {
                let _ = tx.send(self.sid);
            }
        }
        std::task::Poll::Ready(r)
    }
}

/// What the relay driver reports besides carrying data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayNotice {
    /// The table already queued `STALL` on the device's control stream(s)
    /// (B1); this is for metrics.
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
    let (flushed_tx, mut flushed_rx) = mpsc::unbounded_channel::<SessionId>();
    // The client's FIN is acknowledged only once the site writer flushed
    // (see `SITE_FLUSH`).
    table.confirm_site_flush(true);
    let mut carriers: HashMap<u64, CarrierIo> = HashMap::new();
    let mut sites: HashMap<SessionId, SiteIo> = HashMap::new();
    // Site connects in flight, cancelled when their session ends.
    let mut dials: HashMap<SessionId, Task> = HashMap::new();
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
                    grant,
                    target,
                    kind,
                    exit_class,
                } => {
                    let fut = site(SiteRequest {
                        session_id,
                        grant,
                        target,
                        kind,
                        exit_class,
                    });
                    let tx = site_tx.clone();
                    let h = spawn(async move {
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
                            // CLEAN needs the client's FIN acknowledged, which
                            // waits for the site writer to flush and shut down
                            // (`SITE_FLUSH`): it is done, only exiting.
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
                        let _ = io.tx.try_send(f.to_bytes().into());
                    }
                    None => break,
                }
            }
        }
        for cid in table.take_closed_carriers() {
            if let Some(io) = carriers.remove(&cid) {
                while let Some(f) = table.poll_transmit(cid, t) {
                    if io.tx.try_send(f.to_bytes().into()).is_err() {
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
                    let _ = io.tx.try_send(buf[..n].to_vec().into());
                } else {
                    if table.read_eof(sid) && io.tx.try_send(Vec::new().into()).is_ok() {
                        io.shut = true;
                        let (stx, sid) = (site_tx.clone(), *sid);
                        io.flush_timer = Some(spawn(async move {
                            tokio::time::sleep(SITE_FLUSH).await;
                            let _ = stx.send(SiteEv::Error(sid)).await;
                        }));
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
                    let reader = spawn_reader(cid, r, ev_tx.clone(), None);
                    let etx = ev_tx.clone();
                    let (tx, writer) = spawn_writer(w, writable.clone(), async move {
                        let _ = etx.send(CarrierEv::Closed(cid)).await;
                    });
                    carriers.insert(cid, CarrierIo { tx, reader, writer, _charge: None });
                    table.add_carrier(cid);
                }
                None => accepting = false,
            },
            ev = ev_rx.recv() => {
                let t = now();
                match ev {
                    Some(CarrierEv::Frame(cid, Ok(f), _)) => table.on_frame(cid, f, t),
                    Some(CarrierEv::Frame(cid, Err(e), _)) => table.on_decode_error(cid, e),
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
                        let w = SiteWrite { inner: w, sid, flushed: Some(flushed_tx.clone()) };
                        let etx = site_tx.clone();
                        let (tx, writer) = spawn_writer(w, writable.clone(), async move {
                            let _ = etx.send(SiteEv::Error(sid)).await;
                        });
                        let (req, mut req_rx) = mpsc::channel::<usize>(1);
                        let stx = site_tx.clone();
                        let reader = spawn(async move {
                            let mut b = vec![0u8; CHUNK];
                            while let Some(n) = req_rx.recv().await {
                                match r.read(&mut b[..n]).await {
                                    Ok(0) => { let _ = stx.send(SiteEv::Data(sid, Vec::new())).await; return; }
                                    Ok(k) => { if stx.send(SiteEv::Data(sid, b[..k].to_vec())).await.is_err() { return; } }
                                    Err(_) => { let _ = stx.send(SiteEv::Error(sid)).await; return; }
                                }
                            }
                        });
                        sites.insert(sid, SiteIo { tx, req, reader, writer, outstanding: false, shut: false, eof: false, flush_timer: None });
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
            Some(sid) = flushed_rx.recv() => {
                if let Some(io) = sites.get_mut(&sid) {
                    io.flush_timer = None;
                }
                table.site_flushed(&sid, now());
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

/// Health timing of a control stream.
#[derive(Clone, Debug)]
pub struct ControlTiming {
    /// PING period.
    pub ping_every: std::time::Duration,
    /// No frame from the relay for this long: the channel is dead.
    pub dead_after: std::time::Duration,
    /// Wait after a failed control-stream connect.
    pub retry: std::time::Duration,
}

impl Default for ControlTiming {
    fn default() -> Self {
        Self {
            ping_every: std::time::Duration::from_secs(5),
            dead_after: std::time::Duration::from_secs(12),
            retry: std::time::Duration::from_secs(2),
        }
    }
}

/// What a control stream tells the sessions of its channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlHint {
    /// The relay saw this session stall (`STALL`, B1): RESUME it.
    Stall {
        session_id: SessionId,
        attach_gen: u32,
    },
    /// The control stream answered nothing for `dead_after`, or broke: the
    /// channel is dead, move every session to a new carrier (§5.1 "通道判死").
    Dead,
    /// `REVOKED` on the control stream (§6).
    Revoked(u8),
}

/// Keep a control stream to the relay (§3, KERNEL_SPEC §7.2): CTRL_HELLO,
/// then PING every `ping_every`. Runs until `hints` is closed. A silent
/// stream (a blackhole that drops packets but never closes the socket) is
/// reported as [`ControlHint::Dead`] and replaced.
pub async fn run_control(
    connect: Connector,
    hello: CtrlHello,
    timing: ControlTiming,
    hints: mpsc::UnboundedSender<ControlHint>,
) {
    use tokio::time::{sleep, Instant};
    let mut nonce = 0u64;
    while !hints.is_closed() {
        let c = tokio::select! {
            c = connect() => c,
            _ = hints.closed() => return,
        };
        let c = match c {
            Ok(c) => c,
            Err(_) => {
                sleep(timing.retry).await;
                continue;
            }
        };
        let (mut r, mut w) = tokio::io::split(c);
        if !write_within(&mut w, hello.to_frame(), timing.dead_after).await {
            sleep(timing.retry).await;
            continue;
        }
        let mut dec = FrameDecoder::new();
        let mut buf = vec![0u8; 4096];
        let mut last_rx = Instant::now();
        let mut ping = tokio::time::interval(timing.ping_every);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut revoked = false;
        // Only a stream the relay accepted (answered CTRL_HELLO) can be
        // judged dead; a refused or unreachable one is just retried.
        let mut accepted = false;
        'stream: loop {
            tokio::select! {
                n = r.read(&mut buf) => {
                    let n = match n {
                        Ok(0) | Err(_) => break 'stream,
                        Ok(n) => n,
                    };
                    last_rx = Instant::now();
                    accepted = true;
                    dec.push(&buf[..n]);
                    loop {
                        match dec.next_frame() {
                            Ok(Some(Frame::Stall(entries))) => {
                                for (session_id, attach_gen) in entries {
                                    let _ = hints.send(ControlHint::Stall { session_id, attach_gen });
                                }
                            }
                            Ok(Some(Frame::Control { ty: ty::REVOKED, payload })) => {
                                let _ = hints.send(ControlHint::Revoked(
                                    payload.first().copied().unwrap_or(code::REVOKED),
                                ));
                                revoked = true;
                                break 'stream;
                            }
                            Ok(Some(_)) => {}
                            Ok(None) => break,
                            Err(_) => break 'stream,
                        }
                    }
                }
                _ = ping.tick() => {
                    if last_rx.elapsed() >= timing.dead_after {
                        break 'stream;
                    }
                    nonce += 1;
                    if !write_within(&mut w, Frame::Ping { nonce }, timing.dead_after).await {
                        break 'stream;
                    }
                }
                _ = sleep_until_dead(last_rx, timing.dead_after) => break 'stream,
                _ = hints.closed() => return,
            }
        }
        if revoked {
            return;
        }
        if accepted {
            let _ = hints.send(ControlHint::Dead);
        } else {
            sleep(timing.retry).await;
        }
    }
}

async fn write_within<W: AsyncWrite + Unpin>(w: &mut W, f: Frame, d: std::time::Duration) -> bool {
    matches!(
        tokio::time::timeout(d, w.write_all(&f.to_bytes())).await,
        Ok(Ok(()))
    )
}

async fn sleep_until_dead(last_rx: tokio::time::Instant, dead_after: std::time::Duration) {
    tokio::time::sleep_until(last_rx + dead_after).await
}
