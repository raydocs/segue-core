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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;

use crate::client::{ClientSession, CloseReason, Health, State, Tx};
use crate::codec::{code, ty, CtrlHello, Frame, FrameDecoder, Kind, SessionId, Target};
use crate::pool::{Grant as PoolGrant, Pool, Ticket, Tier, FRAME_MAX};
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

/// What covers a buffer (client side): pool blocks, and when they came
/// from the transport region the session's (or reader's) single slot in
/// it, so one stuck carrier holds at most one frame there (r6 R5).
struct Charge {
    /// Dropped first: a task woken by the returned blocks finds the slot
    /// free.
    _slot: Option<Slot>,
    grant: PoolGrant,
}

struct Slot(Arc<AtomicBool>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// A message for a writer task, with what covers it until it is written
/// (client side: bytes leave the session's grants when they are queued, so
/// the queue is charged on its own).
struct Out {
    data: Vec<u8>,
    _charge: Option<Charge>,
    /// Stamped by the writer when it starts writing this message.
    started: Option<Arc<Stamp>>,
}

impl From<Vec<u8>> for Out {
    fn from(data: Vec<u8>) -> Self {
        Self {
            data,
            _charge: None,
            started: None,
        }
    }
}

/// `data` charged with `c`, shrunk to what `data` holds.
fn charged(data: Vec<u8>, mut c: Charge) -> Out {
    c.grant.try_resize(data.capacity());
    Out {
        data,
        _charge: Some(c),
        started: None,
    }
}

/// A frame holding the transport slot (client side, r7 #1). It may hold
/// it while its carrier's writer keeps moving bytes (the frames queued
/// before it, then its own), for the pool's hold without progress, and
/// for the hold cap at most, counted from when the writer started on it
/// (r9: not from when it was queued, so frames waiting behind a slow one
/// do not use up their cap in the queue).
#[derive(Clone)]
struct TxHold {
    cid: u64,
    queued: tokio::time::Instant,
    started: Arc<Stamp>,
}

impl TxHold {
    fn deadline(&self, tx_at: Option<tokio::time::Instant>, pool: &Pool) -> tokio::time::Instant {
        let last = tx_at.map_or(self.queued, |m| m.max(self.queued));
        let idle = last + pool.transport_hold();
        match self.started.get() {
            Some(st) => idle.min(st + pool.transport_hold_max()),
            None => idle,
        }
    }
}

/// Room for one carrier frame of `min..=want` bytes: elastic blocks while
/// there are any, else the transport region, one frame per `slot` at a
/// time and in arrival order (`ticket` is the caller's place in line, kept
/// across attempts while it waits; r7 #1). `None`: wait for blocks.
fn take_charge(
    pool: &Arc<Pool>,
    slot: &Arc<AtomicBool>,
    ticket: &mut Option<Ticket>,
    min: usize,
    want: usize,
) -> Option<Charge> {
    if let Some(g) = PoolGrant::between(pool, min, want, Tier::Elastic) {
        *ticket = None;
        return Some(Charge {
            _slot: None,
            grant: g,
        });
    }
    if slot.swap(true, Ordering::AcqRel) {
        // This session already holds its frame there: it must not hold up
        // the line meanwhile.
        *ticket = None;
        return None;
    }
    let held = Slot(slot.clone());
    let t = ticket.get_or_insert_with(|| pool.ticket());
    // The ticket stays with the caller until the frame is built (a frame
    // that needs a larger charge keeps its place in line).
    let g = PoolGrant::transport(pool, min, want.min(min.max(TRANSPORT_FRAME)), t)?;
    Some(Charge {
        _slot: Some(held),
        grant: g,
    })
}

/// Largest frame a session builds from the transport region (DATA is cut
/// to it; OPEN may need more).
const TRANSPORT_FRAME: usize = 4 * crate::pool::BLOCK;

/// Write what `w` takes right now without waiting (`None`: it would
/// block; the caller then waits on a real write).
fn try_write<W: AsyncWrite + Unpin>(w: &mut W, buf: &[u8]) -> Option<io::Result<usize>> {
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match Pin::new(w).poll_write(&mut cx, buf) {
        std::task::Poll::Ready(r) => Some(r),
        std::task::Poll::Pending => None,
    }
}

fn now() -> std::time::Instant {
    tokio::time::Instant::now().into_std()
}

/// When bytes last moved through an I/O object: the time of the read or
/// write itself, not of when the driver happened to look (r8 N4/N5/N8).
#[derive(Debug)]
struct Stamp {
    base: tokio::time::Instant,
    /// Nanoseconds after `base`, plus one; 0 = never.
    at: AtomicU64,
}

impl Stamp {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            base: tokio::time::Instant::now(),
            at: AtomicU64::new(0),
        })
    }

    fn touch(&self) {
        let n = self.base.elapsed().as_nanos() as u64 + 1;
        self.at.fetch_max(n, Ordering::Relaxed);
    }

    fn get(&self) -> Option<tokio::time::Instant> {
        match self.at.load(Ordering::Relaxed) {
            0 => None,
            n => Some(self.base + std::time::Duration::from_nanos(n - 1)),
        }
    }
}

/// A writer that records in a [`Stamp`] each write that moved at least
/// one byte.
struct Touch<T> {
    inner: T,
    stamp: Arc<Stamp>,
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Touch<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let r = std::task::ready!(Pin::new(&mut self.inner).poll_write(cx, buf));
        if matches!(r, Ok(n) if n > 0) {
            self.stamp.touch();
        }
        std::task::Poll::Ready(r)
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
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A carrier's reader and writer; the writer records when it last sent
/// bytes.
fn split_carrier(
    stream: BoxCarrier,
) -> (
    tokio::io::ReadHalf<BoxCarrier>,
    Touch<tokio::io::WriteHalf<BoxCarrier>>,
    Arc<Stamp>,
) {
    let (r, w) = tokio::io::split(stream);
    let ws = Stamp::new();
    (
        r,
        Touch {
            inner: w,
            stamp: ws.clone(),
        },
        ws,
    )
}

/// How often a reader reports bytes of a frame still arriving
/// ([`CarrierEv::Progress`]).
const PROGRESS_EVERY: std::time::Duration = std::time::Duration::from_millis(250);

/// Rate-limited [`CarrierEv::Progress`] reports of one reader.
struct Progress {
    cid: u64,
    tx: mpsc::Sender<CarrierEv>,
    last: Option<tokio::time::Instant>,
}

impl Progress {
    fn new(cid: u64, tx: mpsc::Sender<CarrierEv>) -> Self {
        Self {
            cid,
            tx,
            last: None,
        }
    }

    /// Bytes arrived (or wait, already here, for local memory): report it
    /// unless reported within [`PROGRESS_EVERY`]. Never blocks; a report
    /// that finds the channel full is dropped (the frames in it show the
    /// carrier moving anyway).
    fn report(&mut self) {
        let now = tokio::time::Instant::now();
        if self.last.is_some_and(|l| now < l + PROGRESS_EVERY) {
            return;
        }
        self.last = Some(now);
        let _ = self.tx.try_send(CarrierEv::Progress(self.cid));
    }

    /// A whole frame went out to the driver: the next partial one reports
    /// at once.
    fn reset(&mut self) {
        self.last = None;
    }
}

enum CarrierEv {
    /// With what covers the decoded frame until it is handled.
    Frame(u64, Result<Frame, ProtoError>, Option<Charge>),
    /// Bytes of a frame not yet complete arrived on the carrier (or are
    /// there, waiting for memory): the peer and the path are alive though
    /// no frame came in (r8 N4/N5). See [`Progress`].
    Progress(u64),
    Closed(u64),
    /// The carrier ended in the middle of a frame, or a frame on it
    /// stopped arriving for the transport hold or outlived the hold cap:
    /// it owed us bytes it never delivered (r9 F2).
    Stuck(u64),
}

/// Reader task: decode frames until EOF or a decode error. With `pool`
/// (client side) frames are read header first and every frame body is
/// charged before it is allocated (r6 N13): elastic blocks while there are
/// any, else one frame at a time from the transport region, which the
/// driver frees as soon as it handled the frame. The only uncharged
/// memory is a [`SMALL_READ`] header buffer.
fn spawn_reader<R: AsyncRead + Unpin + Send + 'static>(
    cid: u64,
    r: R,
    tx: mpsc::Sender<CarrierEv>,
    pool: Option<Arc<Pool>>,
) -> Task {
    match pool {
        Some(p) => spawn(read_charged(cid, r, tx, p)),
        None => spawn(read_frames(cid, r, tx)),
    }
}

async fn read_charged<R: AsyncRead + Unpin>(
    cid: u64,
    r: R,
    tx: mpsc::Sender<CarrierEv>,
    pool: Arc<Pool>,
) {
    let mut r = tokio::io::BufReader::with_capacity(SMALL_READ, r);
    let slot = Arc::new(AtomicBool::new(false));
    let mut ticket = None;
    let mut progress = Progress::new(cid, tx.clone());
    loop {
        let mut hdr = [0u8; 10];
        if r.read_exact(&mut hdr[..3]).await.is_err() {
            break;
        }
        let vlen = 1usize << (hdr[2] >> 6);
        if r.read_exact(&mut hdr[3..2 + vlen]).await.is_err() {
            break;
        }
        let (len, _) = crate::codec::get_varint(&hdr[2..2 + vlen]).expect("complete varint");
        if len > crate::codec::MAX_PAYLOAD as u64 {
            let _ = tx
                .send(CarrierEv::Frame(cid, Err(ProtoError::FrameTooLong), None))
                .await;
            break;
        }
        let len = len as usize;
        let (ty, flags) = (hdr[0], hdr[1]);
        // DATA keeps the payload's allocation; anything else is decoded
        // into a copy while the payload is still held.
        let cover = if ty == ty::DATA { len } else { 2 * len };
        let (payload, charge) =
            match read_body(&mut r, &pool, &slot, &mut ticket, &mut progress, len, cover).await {
                Body::Read(p, c) => (p, c),
                Body::Ended | Body::Stuck => {
                    let _ = tx.send(CarrierEv::Stuck(cid)).await;
                    return;
                }
            };
        progress.reset();
        match Frame::decode_owned(ty, flags, payload) {
            Ok(Some(f)) => {
                if tx.send(CarrierEv::Frame(cid, Ok(f), charge)).await.is_err() {
                    return;
                }
            }
            Ok(None) => {}
            Err(e) => {
                let _ = tx.send(CarrierEv::Frame(cid, Err(e), None)).await;
                break;
            }
        }
    }
    let _ = tx.send(CarrierEv::Closed(cid)).await;
}

/// Read a frame body of `len` bytes whose memory (with what decoding it
/// needs, `cover`) is charged before it is held: elastic blocks when there
/// are any, else the whole frame from the transport region (in line, see
/// [`take_charge`]), and only once its first byte has arrived, so a
/// carrier that delivers a header and stalls holds nothing there. A frame
/// charged to the transport region must then keep arriving: a carrier that
/// moves none of it for the pool's hold, or does not finish it within the
/// hold cap, is closed (the peer replays on the next one; r7 #1, r8 N5). Whole frames only: a reader never
/// holds part of a frame while waiting for more blocks, so readers cannot
/// wait on each other.
async fn read_body<R: AsyncRead + Unpin>(
    r: &mut tokio::io::BufReader<R>,
    pool: &Arc<Pool>,
    slot: &Arc<AtomicBool>,
    ticket: &mut Option<Ticket>,
    progress: &mut Progress,
    len: usize,
    cover: usize,
) -> Body {
    use tokio::io::AsyncBufReadExt;
    if len == 0 {
        return Body::Read(Vec::new(), None);
    }
    let mut charge = PoolGrant::between(pool, cover, cover, Tier::Elastic).map(|g| Charge {
        _slot: None,
        grant: g,
    });
    if charge.is_none() {
        // Nothing is charged while the body has not started.
        if r.fill_buf().await.map_or(true, |b| b.is_empty()) {
            return Body::Ended;
        }
        // The body is here and waits only for local memory: the carrier
        // is not stalled.
        progress.report();
        let c = {
            let wait = wait_charge(pool, slot, ticket, cover);
            tokio::pin!(wait);
            let mut tick = tokio::time::interval(PROGRESS_EVERY);
            loop {
                tokio::select! {
                    c = &mut wait => break c,
                    _ = tick.tick() => progress.report(),
                }
            }
        };
        charge = Some(c);
        *ticket = None;
    }
    let mut payload = vec![0u8; len];
    let transport = charge
        .as_ref()
        .is_some_and(|c| c.grant.tier() == Tier::Transport);
    // A transport-region frame is held by progress (r8 N5): every read
    // that moves part of it restarts the hold; the cap bounds the whole
    // frame however it moves.
    let cap = transport.then(|| tokio::time::Instant::now() + pool.transport_hold_max());
    let mut got = 0;
    while got < len {
        let read = r.read(&mut payload[got..]);
        let n = match cap {
            Some(cap) => {
                let idle = (tokio::time::Instant::now() + pool.transport_hold()).min(cap);
                match tokio::time::timeout_at(idle, read).await {
                    Ok(r) => r,
                    Err(_) => return Body::Stuck,
                }
            }
            None => read.await,
        };
        match n {
            Ok(n) if n > 0 => got += n,
            _ => return Body::Ended,
        }
        if got < len {
            progress.report();
        }
    }
    Body::Read(payload, charge)
}

/// What [`read_body`] got.
enum Body {
    Read(Vec<u8>, Option<Charge>),
    /// The carrier ended (EOF or error).
    Ended,
    /// The transport hold or its cap ran out with the body incomplete.
    Stuck,
}

/// [`take_charge`] of `cover` bytes, waiting for blocks: listening before
/// the second try (nothing given in between is missed), and for its turn
/// when in line for the transport region.
async fn wait_charge(
    pool: &Arc<Pool>,
    slot: &Arc<AtomicBool>,
    ticket: &mut Option<Ticket>,
    cover: usize,
) -> Charge {
    loop {
        if let Some(c) = take_charge(pool, slot, ticket, cover, cover) {
            return c;
        }
        let freed = pool.armed();
        if let Some(c) = take_charge(pool, slot, ticket, cover, cover) {
            return c;
        }
        match ticket.as_ref() {
            Some(t) => {
                tokio::select! {
                    _ = t.ready() => {}
                    _ = freed.wait() => {}
                }
            }
            None => freed.wait().await,
        }
    }
}

/// Relay side: no pool, a [`FrameDecoder`] over adaptive reads.
async fn read_frames<R: AsyncRead + Unpin>(cid: u64, mut r: R, tx: mpsc::Sender<CarrierEv>) {
    let mut progress = Progress::new(cid, tx.clone());
    let mut dec = FrameDecoder::new();
    let mut buf = ReadBuffer::new(None);
    loop {
        let room = buf.len();
        // A large buffer goes back once the stream has been quiet for
        // READ_IDLE (cancelling a pending read loses nothing).
        let idle = buf
            .idle_at()
            .or_else(|| (dec.held_bytes() > 0).then_some(buf.last + READ_IDLE));
        let read = match idle {
            Some(at) => match tokio::time::timeout_at(at, r.read(&mut buf.get()[..room])).await {
                Ok(r) => r,
                Err(_) => {
                    buf.shrink();
                    dec.release_idle();
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
                buf.adapt(n);
            }
        }
        loop {
            match dec.next_frame() {
                Ok(Some(f)) => {
                    if tx.send(CarrierEv::Frame(cid, Ok(f), None)).await.is_err() {
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
        if dec.held_bytes() > 0 {
            progress.report();
        } else {
            progress.reset();
        }
    }
    let _ = tx.send(CarrierEv::Closed(cid)).await;
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
            if let Some(st) = &m.started {
                st.touch();
            }
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
    /// When the writer last sent a byte.
    tx_at: Arc<Stamp>,
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
    /// Session-level health reports (r9 F5, see [`Health`]): called
    /// from the driver task whenever the session's health changes.
    pub health: Option<HealthHook>,
}

/// Receives a session's [`Health`] reports.
pub type HealthHook = Arc<dyn Fn(Health) + Send + Sync>;

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
        health,
    } = ctl;
    let report = |s: &mut ClientSession| {
        if let Some(h) = s.take_health() {
            if let Some(f) = &health {
                f(h);
            }
        }
    };
    let writable = Arc::new(Notify::new());
    let (mut app_r, mut app_w) = tokio::io::split(app);
    // One received byte whose write to the app is pending, and a pending
    // shutdown of the app's read side (the relay's FIN reached it).
    let mut probe = [0u8; 1];
    let mut probe_len = 0usize;
    let mut shut_pending = false;
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
    let tx_slot = Arc::new(AtomicBool::new(false));
    let mut tx_ticket: Option<Ticket> = None;
    // The queued frame that holds the transport slot (see [`TxHold`]).
    let mut tx_hold: Option<TxHold> = None;
    let mut abuf = ReadBuffer::new(Some(pool.clone()));
    // A queued message the pool could not cover is waiting for blocks.
    let mut pool_blocked;

    loop {
        let t = now();
        // An attach's clock runs from the last byte of its hello the
        // carrier took: a slow carrier still taking a large OPEN is not
        // an unanswered one.
        for (&cid, io) in &carriers {
            if let Some(at) = io.tx_at.get() {
                s.on_carrier_sent(cid, at.into_std());
            }
        }
        s.handle_timeout(t);
        report(&mut s);
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
        let mut freed = None;
        // Carrier output, generated only while the writer has room and
        // there is something to send. Each queued frame is charged to the
        // pool before it is built (elastic blocks, else the session's one
        // slot in the transport region), so the session progresses with a
        // full pool and no memory of its own outside it (r6 R5/R6).
        if let Some(cid) = s.carrier() {
            if let Some(io) = carriers.get(&cid) {
                let mut min = 1;
                while io.tx.capacity() > 0 && s.has_transmit(cid, t) {
                    let c = match take_charge(&pool, &tx_slot, &mut tx_ticket, min, FRAME_MAX) {
                        Some(c) => Some(c),
                        None => {
                            // Listen before the second try, so blocks or a
                            // turn in line given in between wake the loop.
                            freed = Some(pool.armed());
                            take_charge(&pool, &tx_slot, &mut tx_ticket, min, FRAME_MAX)
                        }
                    };
                    let Some(c) = c else {
                        pool_blocked = true;
                        break;
                    };
                    freed = None;
                    let transport = c.grant.tier() == Tier::Transport;
                    let mut v = Vec::new();
                    match s.poll_transmit_into(cid, t, &mut v, c.grant.bytes()) {
                        Tx::Wrote => {
                            let mut out = charged(v, c);
                            if transport {
                                let h = TxHold {
                                    cid,
                                    queued: tokio::time::Instant::now(),
                                    started: Stamp::new(),
                                };
                                out.started = Some(h.started.clone());
                                tx_hold = Some(h);
                            }
                            let _ = io.tx.try_send(out);
                            tx_ticket = None;
                            min = 1;
                        }
                        Tx::Idle => break,
                        Tx::NeedRoom(n) => min = n,
                    }
                }
            }
        }
        if !pool_blocked {
            // Not waiting for blocks: leave the line for the transport
            // region.
            tx_ticket = None;
        }
        if !tx_slot.load(Ordering::Acquire) {
            tx_hold = None;
        }
        // Received bytes go from the receive buffer straight to the app,
        // with no buffer in between: when the app would block, one byte is
        // taken out and its write awaited below, which wakes the loop.
        if probe_len == 0 && !app_failed {
            loop {
                let data = s.readable();
                if data.is_empty() {
                    let _ = s.read(&mut [], t);
                    if s.read_eof() && !app_shut {
                        shut_pending = true;
                    }
                    break;
                }
                match try_write(&mut app_w, data) {
                    Some(Ok(n)) if n > 0 => s.consume(n, t),
                    Some(_) => {
                        // The app stopped taking data: the download cannot
                        // complete, reset.
                        app_failed = true;
                        s.abort();
                        break;
                    }
                    None => {
                        probe_len = s.read(&mut probe, t);
                        break;
                    }
                }
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
            // Promise (and hold) only what the next app read can fill: an
            // idle session's 512-byte read fits in its send floor, no
            // 16 KiB prefetch per connection (r7 #7).
            s.write_capacity_for(abuf.len().min(CHUNK))
        };
        let room = s
            .carrier()
            .and_then(|cid| carriers.get(&cid))
            .is_none_or(|io| io.tx.capacity() > 0);
        let deadline = s
            .poll_timeout_writable(room)
            .map(tokio::time::Instant::from_std);
        let backoff = connect_backoff.filter(|_| !connecting);
        let abuf_idle = abuf.idle_at();
        let drain = tasks.next_deadline();
        let hold_at = tx_hold
            .as_ref()
            .map(|h| h.deadline(carriers.get(&h.cid).and_then(|io| io.tx_at.get()), &pool));
        tokio::select! {
            ev = ev_rx.recv() => {
                let t = now();
                match ev {
                    Some(CarrierEv::Frame(cid, Ok(f), _c)) => { let _ = s.on_frame(cid, f, t); }
                    Some(CarrierEv::Frame(cid, Err(e), _)) => s.on_decode_error(cid, e),
                    Some(CarrierEv::Progress(cid)) => s.on_carrier_progress(cid, t),
                    Some(CarrierEv::Closed(cid)) => {
                        s.on_carrier_closed(cid, t);
                        if let Some(io) = carriers.remove(&cid) {
                            io.reader.abort();
                            io.writer.abort();
                        }
                    }
                    Some(CarrierEv::Stuck(cid)) => {
                        s.on_carrier_stuck(cid, t);
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
                            let (r, w, tx_at) = split_carrier(stream);
                            let reader = spawn_reader(
                                cid,
                                r,
                                ev_tx.clone(),
                                Some(pool.clone()),
                            );
                            let etx = ev_tx.clone();
                            let (tx, writer) = spawn_writer(w, writable.clone(), async move {
                                let _ = etx.send(CarrierEv::Closed(cid)).await;
                            });
                            carriers.insert(cid, CarrierIo { tx, reader, writer, tx_at, _charge: None });
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
            r = async {
                if probe_len > 0 {
                    app_w.write_all(&probe[..probe_len]).await
                } else {
                    app_w.shutdown().await
                }
            }, if !app_failed && (probe_len > 0 || shut_pending) => {
                match r {
                    Ok(()) if probe_len > 0 => probe_len = 0,
                    Ok(()) => {
                        shut_pending = false;
                        app_shut = true;
                    }
                    Err(_) => {
                        app_failed = true;
                        s.abort();
                    }
                }
            }
            _ = writable.notified() => {}
            // Armed before the last failed charge, so nothing given back
            // since is missed; the timeout is a backstop.
            _ = async {
                let freed = freed.take();
                tokio::select! {
                    _ = async {
                        let freed = async {
                            match freed {
                                Some(f) => f.wait().await,
                                None => pool.freed().await,
                            }
                        };
                        match &tx_ticket {
                            // First in line: also woken for its turn.
                            Some(t) => tokio::select! {
                                _ = t.ready() => {}
                                _ = freed => {}
                            },
                            None => freed.await,
                        }
                    } => {}
                    _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
                }
            }, if pool_blocked => {}
            _ = tokio::time::sleep_until(abuf_idle.unwrap_or_else(tokio::time::Instant::now)), if abuf_idle.is_some() => {
                abuf.shrink();
            }
            _ = tokio::time::sleep_until(deadline.unwrap_or_else(tokio::time::Instant::now)), if deadline.is_some() => {}
            _ = tokio::time::sleep_until(backoff.unwrap_or_else(tokio::time::Instant::now)), if backoff.is_some() => {}
            _ = tokio::time::sleep_until(drain.unwrap_or_else(tokio::time::Instant::now)), if drain.is_some() => {}
            // A frame held the transport region past the hold: its carrier
            // stopped moving. Give the carrier up (the frame's blocks go
            // back with its writer); the session resumes on a new one and
            // replays what was not acknowledged (r7 #1).
            _ = tokio::time::sleep_until(hold_at.unwrap_or_else(tokio::time::Instant::now)), if hold_at.is_some() => {
                // Bytes may have moved while this slept: the loop computes
                // the hold again from them.
                let at = tx_hold
                    .as_ref()
                    .map(|h| h.deadline(carriers.get(&h.cid).and_then(|io| io.tx_at.get()), &pool));
                if at.is_some_and(|at| at > tokio::time::Instant::now()) {
                    continue;
                }
                if let Some(TxHold { cid, .. }) = tx_hold.take() {
                    if tx_slot.load(Ordering::Acquire) {
                        s.on_carrier_stuck(cid, now());
                        if let Some(io) = carriers.remove(&cid) {
                            io.reader.abort();
                            io.writer.abort();
                        }
                    }
                }
            }
        }
    }
    if let Some(h) = dial.take() {
        h.abort();
    }
    report(&mut s);
    let mut reason = s
        .close_reason()
        .unwrap_or(CloseReason::Reset(code::INTERNAL));
    // Not clean: nothing more reaches the app. The reason goes out before
    // the app stream ends, so the caller turns that end into a reset.
    if reason != CloseReason::Clean {
        if let Some(tx) = closed.take() {
            let _ = tx.send(reason);
        }
        drop(app_w);
    } else {
        // A clean close can be learnt from a REJECT(closed) (B6) while
        // received data is still buffered: it belongs to the app.
        // Bounded: an app that stopped reading cannot hold the session
        // open. Clean is only reported once every byte reached the app
        // (r5 N8): a drain cut short by the deadline is a reset, never a
        // short clean EOF.
        let until = tokio::time::Instant::now() + DRAIN;
        let delivered = !app_failed
            && (app_shut
                || tokio::time::timeout_at(until, async {
                    if probe_len > 0 {
                        app_w.write_all(&probe[..probe_len]).await?;
                    }
                    loop {
                        let data = s.readable();
                        if data.is_empty() {
                            break;
                        }
                        let n = app_w.write(data).await?;
                        if n == 0 {
                            return Err(io::ErrorKind::WriteZero.into());
                        }
                        s.consume(n, now());
                    }
                    if s.read_eof() {
                        app_w.shutdown().await?;
                    }
                    io::Result::Ok(())
                })
                .await
                .is_ok_and(|r| r.is_ok()));
        if !delivered {
            reason = CloseReason::Reset(code::INTERNAL);
        }
        if let Some(tx) = closed.take() {
            let _ = tx.send(reason);
        }
        drop(app_w);
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
    /// When the site last accepted upload bytes (see [`SiteWrite`]).
    wrote: Arc<Stamp>,
    /// The upload drain after the client's FIN (see [`Flush`]).
    flush: Flush,
}

/// The upload drain after the client's FIN: the site writer must hand the
/// rest of the upload to the site and shut its write side down; only then
/// is the FIN acknowledged and the session can end CLEAN (r6: a truncated
/// upload must never be reported clean). Bounded by progress (review r7
/// #9): reset when the site accepts nothing for `site_flush_idle`, or when
/// the whole drain exceeds `site_flush_max`. Both count from the moment
/// the FIN and every byte before it arrived ([`RelayTable::upload_complete`]),
/// not from when the shutdown got into the writer queue, so a full queue
/// does not hold the clock back.
enum Flush {
    /// The client's upload is still arriving.
    Waiting,
    /// Since when; the site writer's [`Stamp`] says when the site last
    /// took a byte.
    Draining { since: tokio::time::Instant },
    /// The site writer shut down: the FIN is acknowledged.
    Done,
}

impl Flush {
    /// The idle bound counts from the site's last actual write (its
    /// [`Stamp`]), not from when the driver noticed it (r8 N8): a write
    /// that went unnoticed for a while does not stretch the bound.
    fn deadline(&self, wrote: &Stamp, t: &crate::Timing) -> Option<tokio::time::Instant> {
        match self {
            Flush::Draining { since } => {
                let moved = wrote.get().map_or(*since, |w| w.max(*since));
                Some((moved + t.site_flush_idle).min(*since + t.site_flush_max))
            }
            _ => None,
        }
    }

    /// Start the drain clock; true when it ran out.
    fn check(
        &mut self,
        complete: bool,
        wrote: &Stamp,
        now: tokio::time::Instant,
        t: &crate::Timing,
    ) -> bool {
        if matches!(self, Flush::Waiting) && complete {
            *self = Flush::Draining { since: now };
        }
        self.deadline(wrote, t).is_some_and(|d| d <= now)
    }
}

/// The site's write half: reports once its shutdown completed, i.e. every
/// byte before it was written and the FIN went out.
struct SiteWrite<W> {
    inner: W,
    sid: SessionId,
    flushed: Option<mpsc::UnboundedSender<SessionId>>,
    /// When the site last accepted bytes: the drain's progress (see
    /// [`Flush`]).
    wrote: Arc<Stamp>,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for SiteWrite<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let r = std::task::ready!(Pin::new(&mut self.inner).poll_write(cx, buf));
        if matches!(r, Ok(n) if n > 0) {
            self.wrote.touch();
        }
        std::task::Poll::Ready(r)
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
    // (see `Flush`).
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
        // Upload drains that stopped progressing or ran too long (`Flush`).
        let tnow = tokio::time::Instant::now();
        let stuck: Vec<SessionId> = sites
            .iter_mut()
            .filter_map(|(sid, io)| {
                let complete = table.upload_complete(sid);
                io.flush
                    .check(complete, &io.wrote, tnow, table.timing())
                    .then_some(*sid)
            })
            .collect();
        for sid in stuck {
            table.site_reset(&sid);
        }
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
                            // (`Flush`): it is done, only exiting.
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
        let deadline = table
            .poll_timeout_writable(|cid| carriers.get(&cid).is_some_and(|io| io.tx.capacity() > 0))
            .map(tokio::time::Instant::from_std);
        let drain = tasks.next_deadline();
        let tm = table.timing();
        let flush = sites
            .values()
            .filter_map(|io| io.flush.deadline(&io.wrote, tm))
            .min();
        tokio::select! {
            c = accept.recv(), if accepting => match c {
                Some(stream) => {
                    next_cid += 1;
                    let cid = next_cid;
                    let (r, w, tx_at) = split_carrier(stream);
                    let reader = spawn_reader(cid, r, ev_tx.clone(), None);
                    let etx = ev_tx.clone();
                    let (tx, writer) = spawn_writer(w, writable.clone(), async move {
                        let _ = etx.send(CarrierEv::Closed(cid)).await;
                    });
                    carriers.insert(cid, CarrierIo { tx, reader, writer, tx_at, _charge: None });
                    table.add_carrier(cid);
                }
                None => accepting = false,
            },
            ev = ev_rx.recv() => {
                let t = now();
                match ev {
                    Some(CarrierEv::Frame(cid, Ok(f), _)) => table.on_frame(cid, f, t),
                    Some(CarrierEv::Frame(cid, Err(e), _)) => table.on_decode_error(cid, e),
                    Some(CarrierEv::Progress(cid)) => table.on_carrier_progress(cid, t),
                    Some(CarrierEv::Closed(cid) | CarrierEv::Stuck(cid)) => {
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
                        let wrote = Stamp::new();
                        let w = SiteWrite { inner: w, sid, flushed: Some(flushed_tx.clone()), wrote: wrote.clone() };
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
                        sites.insert(sid, SiteIo { tx, req, reader, writer, outstanding: false, shut: false, eof: false, wrote, flush: Flush::Waiting });
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
                    io.flush = Flush::Done;
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
            _ = tokio::time::sleep_until(flush.unwrap_or_else(tokio::time::Instant::now)), if flush.is_some() => {}
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
