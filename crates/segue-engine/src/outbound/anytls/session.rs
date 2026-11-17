//! Bounded AnyTLS session pool and stream multiplexing.
//!
//! One TLS carrier session carries any number of streams (framed `Syn` /
//! `Push` / `Fin`). A session with no live stream becomes idle and the next
//! open reuses it; a cleanup task retires idle sessions after
//! `idle_session_timeout`, keeping `min_idle_session`. The shapes follow
//! `sing-anytls`'s `session.Client` and `session.Session`, with three
//! deliberate differences:
//!
//! * sessions and streams are hard-bounded, so a hostile or broken server
//!   cannot grow the process's memory;
//! * a stream's receive queue is bounded, so a stalled consumer pauses the
//!   session reader (head-of-line blocking, as the Go pipe does) instead of
//!   buffering without limit;
//! * no task outlives the pool: closing a session aborts both of its tasks.

use super::*;
use bytes::{Buf, Bytes};
use segue_proxy::anytls::{self as wire, Command, FrameHeader, PaddingFactory};
use std::sync::{
    atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize},
    Weak,
};
use tokio::{
    io::AsyncReadExt,
    sync::{mpsc, Notify},
    task::JoinHandle,
};

/// Sessions one outbound keeps at once, idle and busy. Each is a TLS carrier
/// plus two small tasks; on a phone this bounds the protocol's own state. The
/// parser refuses a `min_idle_session` above it.
pub(super) const MAX_SESSIONS: usize = segue_config::MAX_ANYTLS_IDLE_SESSIONS;
/// Streams one session carries at once. The reference has no cap; this one
/// matches Segue's Mux.Cool concurrency default.
const MAX_STREAMS: usize = 128;
/// Frames queued per stream before the session reader waits.
const STREAM_QUEUE: usize = 8;
/// Writes queued for the session's writer task.
const WRITE_QUEUE: usize = 64;
/// The reference's floor for both idle timings (`session/client.go`).
const MIN_IDLE_INTERVAL: Duration = Duration::from_secs(30);
/// A v2 server must acknowledge a stream with `SynAck` within this long, or
/// the session is presumed dead (`session/session.go`).
const SYNACK_WAIT: Duration = Duration::from_secs(3);

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "AnyTLS session closed")
}
fn full() -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        "AnyTLS session capacity exhausted",
    )
}
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

#[derive(Debug, Clone)]
pub(super) struct PoolOptions {
    pub(super) idle_check_interval: Duration,
    pub(super) idle_session_timeout: Duration,
    pub(super) min_idle_session: usize,
    pub(super) client_metadata: Option<String>,
}
impl PoolOptions {
    /// The reference floors an interval of five seconds or less to thirty;
    /// keep that, so a programmatic config cannot spin.
    fn normalized(mut self) -> Self {
        if self.idle_check_interval <= Duration::from_secs(5) {
            self.idle_check_interval = MIN_IDLE_INTERVAL;
        }
        if self.idle_session_timeout <= Duration::from_secs(5) {
            self.idle_session_timeout = MIN_IDLE_INTERVAL;
        }
        self
    }
}

/// One write handed to the session's writer task. Control frames are held
/// back until the first data frame, as the reference buffers Settings and Syn
/// to go out with the first stream's target in one padded record.
#[derive(Debug)]
enum WriteCommand {
    Control(Vec<u8>),
    Data(Vec<u8>),
    Close,
}

/// What a stream's owner receives from the session reader.
#[derive(Debug)]
enum StreamEvent {
    Data(Bytes),
    Finished,
    Failed(io::Error),
}

#[derive(Debug)]
pub(super) struct Pool(Arc<PoolShared>);

struct PoolShared {
    options: PoolOptions,
    padding: Arc<Mutex<PaddingFactory>>,
    /// Reusable sessions; `pop` takes the newest, as the reference does.
    idle: Mutex<Vec<Arc<Session>>>,
    /// Every live session, for shutdown.
    sessions: Mutex<Vec<Arc<Session>>>,
    seq: AtomicU64,
    closed: AtomicBool,
    cleanup: Mutex<Option<JoinHandle<()>>>,
}

impl Pool {
    pub(super) fn new(options: PoolOptions) -> Self {
        Self(Arc::new(PoolShared {
            options: options.normalized(),
            padding: Arc::new(Mutex::new(PaddingFactory::default())),
            idle: Mutex::new(Vec::new()),
            sessions: Mutex::new(Vec::new()),
            seq: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            cleanup: Mutex::new(None),
        }))
    }

    /// The hello's padding length under the current scheme, drawn from the
    /// scheme's counter-0 record size.
    pub(super) fn hello_padding(&self) -> u32 {
        lock(&self.0.padding).hello_padding(wire::random_jitter)
    }

    /// Open a stream, reusing an idle session or dialing `connect` for a new
    /// one. `connect` must return a carrier that has already sent the
    /// password hello.
    pub(super) async fn open<F>(&self, connect: F) -> Result<Stream, CoreError>
    where
        F: Future<Output = Result<BoxedTransportStream, CoreError>>,
    {
        if self.0.closed.load(Ordering::Acquire) {
            return Err(closed().into());
        }
        // A reused session costs no dial; a dead one is retired and the next
        // idle session, or a fresh dial, takes the stream. `connect` is
        // dropped unstarted when an idle session serves the open.
        while let Some(session) = self.take_idle() {
            match session.open_stream() {
                Ok(stream) => return Ok(stream),
                Err(_) => session.close(),
            }
        }
        let carrier = connect.await?;
        let session = self.start_session(carrier)?;
        match session.open_stream() {
            Ok(stream) => Ok(stream),
            Err(error) => {
                session.close();
                Err(error)
            }
        }
    }

    fn take_idle(&self) -> Option<Arc<Session>> {
        let mut idle = lock(&self.0.idle);
        while let Some(session) = idle.pop() {
            if !session.closed() {
                return Some(session);
            }
        }
        None
    }

    fn start_session(&self, carrier: BoxedTransportStream) -> Result<Arc<Session>, CoreError> {
        if self.0.closed.load(Ordering::Acquire) {
            return Err(closed().into());
        }
        if lock(&self.0.sessions).len() >= MAX_SESSIONS {
            return Err(full().into());
        }
        let seq = self.0.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let session = Session::spawn(&self.0, seq, carrier)?;
        lock(&self.0.sessions).push(session.clone());
        self.ensure_cleanup();
        Ok(session)
    }

    fn ensure_cleanup(&self) {
        let mut slot = lock(&self.0.cleanup);
        if slot.is_none() {
            *slot = Some(tokio::spawn(idle_cleanup(self.0.clone())));
        }
    }

    pub(super) fn close(&self) {
        self.0.closed.store(true, Ordering::Release);
        if let Some(task) = lock(&self.0.cleanup).take() {
            task.abort();
        }
        lock(&self.0.idle).clear();
        // Closing each session aborts its tasks, so nothing waits on a
        // socket. The list is snapshotted: a session's own close reaches
        // `forget`, which locks it again.
        let sessions = lock(&self.0.sessions).clone();
        for session in sessions {
            session.close();
        }
    }

    pub(super) async fn join(&self) {
        let sessions = std::mem::take(&mut *lock(&self.0.sessions));
        for session in sessions {
            session.join().await;
        }
        if let Some(task) = lock(&self.0.cleanup).take() {
            let _ = task.await;
        }
    }
}

impl PoolShared {
    /// Return a session that has no live stream. Called with `Arc<PoolShared>`
    /// from `Stream::drop`; `Pool` is only the outbound's handle.
    fn push_idle(&self, session: &Arc<Session>) {
        if self.closed.load(Ordering::Acquire) || session.closed() {
            return;
        }
        let mut idle = lock(&self.idle);
        if !idle.iter().any(|other| other.seq == session.seq) {
            idle.push(session.clone());
        }
    }

    /// Drop a closed session from the idle list and the shutdown list.
    fn forget(&self, seq: u64) {
        lock(&self.idle).retain(|session| session.seq != seq);
        lock(&self.sessions).retain(|session| session.seq != seq);
    }
}

impl std::fmt::Debug for PoolShared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsPool")
            .field("sessions", &lock(&self.sessions).len())
            .field("idle", &lock(&self.idle).len())
            .field("closed", &self.closed.load(Ordering::Acquire))
            .finish()
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsSession")
            .field("seq", &self.seq)
            .field("streams", &lock(&self.inner.streams).len())
            .field("closed", &self.closed())
            .finish()
    }
}

impl std::fmt::Debug for SessionInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsSessionInner")
            .field("seq", &self.seq)
            .field("closed", &self.closed.load(Ordering::Acquire))
            .finish()
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        // The router closes and joins explicitly; this covers a pool built
        // outside it, so no cleanup task outlives the outbound.
        self.close();
    }
}

/// Retire idle sessions past `idle_session_timeout`, keeping the newest
/// `min_idle_session`.
async fn idle_cleanup(pool: Arc<PoolShared>) {
    let interval = pool.options.idle_check_interval;
    loop {
        tokio::time::sleep(interval).await;
        if pool.closed.load(Ordering::Acquire) {
            return;
        }
        let now = std::time::Instant::now();
        // Snapshot under the lock, then decide outside it: `Stream::drop`
        // takes a session's `idle_since` lock before this one, so holding
        // both here would invert that order.
        let mut idle = lock(&pool.idle).clone();
        // Newest first, as the reference's skiplist iterates.
        idle.sort_by(|a, b| b.seq.cmp(&a.seq));
        let mut kept = 0usize;
        let mut retire = Vec::new();
        let mut refresh = Vec::new();
        for session in &idle {
            if session.closed() {
                continue;
            }
            let expired = session.idle_since().is_some_and(|since| {
                now.duration_since(since) >= pool.options.idle_session_timeout
            });
            if !expired {
                kept += 1;
            } else if kept < pool.options.min_idle_session {
                // The reference refreshes the timer rather than closing.
                refresh.push(session.seq);
                kept += 1;
            } else {
                retire.push(session.seq);
            }
        }
        for seq in &refresh {
            if let Some(session) = idle.iter().find(|session| session.seq == *seq) {
                session.refresh_idle();
            }
        }
        // Apply to the live list, which may have gained sessions meanwhile;
        // an expired session that left the idle list already is not closed.
        let mut removed = Vec::new();
        lock(&pool.idle).retain(|session| {
            if retire.contains(&session.seq) {
                removed.push(session.clone());
                false
            } else {
                true
            }
        });
        for session in removed {
            session.close();
        }
    }
}

struct Session {
    seq: u64,
    inner: Arc<SessionInner>,
}

struct SessionInner {
    seq: u64,
    pool: Weak<PoolShared>,
    padding: Arc<Mutex<PaddingFactory>>,
    streams: Mutex<HashMap<u32, mpsc::Sender<StreamEvent>>>,
    next_id: AtomicU32,
    active: AtomicUsize,
    idle_since: Mutex<Option<std::time::Instant>>,
    closed: AtomicBool,
    peer_version: AtomicU8,
    syn_generation: AtomicU64,
    writer: mpsc::Sender<WriteCommand>,
    /// Wakes the writer when the session closes without a `Close` command
    /// reaching its queue.
    stopped: Notify,
    /// The reader and writer tasks, aborted when the session closes.
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl Session {
    fn spawn(
        pool: &Arc<PoolShared>,
        seq: u64,
        carrier: BoxedTransportStream,
    ) -> Result<Arc<Self>, CoreError> {
        let (writer, writer_rx) = mpsc::channel(WRITE_QUEUE);
        let inner = Arc::new(SessionInner {
            seq,
            pool: Arc::downgrade(pool),
            padding: pool.padding.clone(),
            streams: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(0),
            active: AtomicUsize::new(0),
            idle_since: Mutex::new(None),
            closed: AtomicBool::new(false),
            peer_version: AtomicU8::new(0),
            syn_generation: AtomicU64::new(0),
            writer: writer.clone(),
            stopped: Notify::new(),
            tasks: Mutex::new(Vec::new()),
        });
        // The settings frame is queued first and buffered with the first
        // stream's Syn, as the reference does.
        let settings = wire::control_frame(
            Command::Settings,
            0,
            &wire::settings_payload(
                inner.padding_md5().as_str(),
                pool.options.client_metadata.as_deref(),
            ),
        );
        if writer.try_send(WriteCommand::Control(settings)).is_err() {
            return Err(closed().into());
        }
        let (read, write) = tokio::io::split(carrier);
        *lock(&inner.tasks) = vec![
            tokio::spawn(write_loop(inner.clone(), write, writer_rx)),
            tokio::spawn(read_loop(inner.clone(), read, writer)),
        ];
        Ok(Arc::new(Self { seq, inner }))
    }

    fn closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    fn idle_since(&self) -> Option<std::time::Instant> {
        *lock(&self.inner.idle_since)
    }

    fn refresh_idle(&self) {
        *lock(&self.inner.idle_since) = Some(std::time::Instant::now());
    }

    fn close(&self) {
        self.inner.close();
    }

    async fn join(&self) {
        // The router closes before it joins; closing here too makes a join on
        // its own terminate instead of waiting for the carrier.
        self.close();
        let tasks = std::mem::take(&mut *lock(&self.inner.tasks));
        for task in tasks {
            let _ = task.await;
        }
    }

    fn open_stream(self: &Arc<Self>) -> Result<Stream, CoreError> {
        let inner = &self.inner;
        if inner.closed.load(Ordering::Acquire) {
            return Err(closed().into());
        }
        if inner.active.load(Ordering::Acquire) >= MAX_STREAMS {
            return Err(full().into());
        }
        let id = inner.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = mpsc::channel(STREAM_QUEUE);
        {
            let mut streams = lock(&inner.streams);
            if streams.len() >= MAX_STREAMS {
                return Err(full().into());
            }
            streams.insert(id, tx);
        }
        inner.active.fetch_add(1, Ordering::AcqRel);
        *lock(&inner.idle_since) = None;
        // Syn goes out buffered with the first data frame.
        if inner
            .writer
            .try_send(WriteCommand::Control(wire::control_frame(
                Command::Syn,
                id,
                &[],
            )))
            .is_err()
        {
            lock(&inner.streams).remove(&id);
            inner.release_stream();
            return Err(closed().into());
        }
        // A v2 peer acknowledges each stream; silence for three seconds means
        // the session is dead, as the reference's deadline watcher decides.
        if id >= 2 && inner.peer_version.load(Ordering::Acquire) >= 2 {
            inner.arm_synack_watchdog();
        }
        Ok(Stream {
            id,
            session: self.clone(),
            writer: inner.writer.clone(),
            rx,
            pending: Bytes::new(),
            fin_sent: false,
        })
    }
}

impl SessionInner {
    fn padding_md5(&self) -> String {
        lock(&self.padding).md5_hex().to_owned()
    }

    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = self.writer.try_send(WriteCommand::Close);
        self.stopped.notify_one();
        // Both halves of the carrier go with their tasks; aborting is what
        // guarantees neither one waits on the other's socket. The handles
        // stay in place so a `join` racing this close can still await them.
        for task in lock(&self.tasks).iter() {
            task.abort();
        }
        // Dropping the senders ends every stream's reader at EOF.
        lock(&self.streams).clear();
        if let Some(pool) = self.pool.upgrade() {
            pool.forget(self.seq);
        }
    }

    fn release_stream(&self) {
        if self.active.fetch_sub(1, Ordering::AcqRel) == 1 && !self.closed.load(Ordering::Acquire) {
            *lock(&self.idle_since) = Some(std::time::Instant::now());
        }
    }

    fn arm_synack_watchdog(self: &Arc<Self>) {
        let generation = self.syn_generation.fetch_add(1, Ordering::AcqRel) + 1;
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            tokio::time::sleep(SYNACK_WAIT).await;
            if let Some(inner) = weak.upgrade() {
                // A SynAck bumps the generation; only an unanswered one
                // reaches the session.
                if inner.syn_generation.load(Ordering::Acquire) == generation
                    && !inner.closed.load(Ordering::Acquire)
                {
                    inner.close();
                }
            }
        });
    }
}

async fn write_loop(
    inner: Arc<SessionInner>,
    mut conn: tokio::io::WriteHalf<BoxedTransportStream>,
    mut rx: mpsc::Receiver<WriteCommand>,
) {
    let mut buffering = true;
    let mut buffer: Vec<u8> = Vec::new();
    let mut packet = 0u32;
    let mut padding = true;
    loop {
        let command = tokio::select! {
            biased;
            () = inner.stopped.notified() => break,
            command = rx.recv() => match command {
                Some(command) => command,
                None => break,
            },
        };
        let bytes = match command {
            WriteCommand::Control(bytes) => {
                if buffering {
                    buffer.extend_from_slice(&bytes);
                    continue;
                }
                bytes
            }
            WriteCommand::Data(bytes) => {
                buffering = false;
                if buffer.is_empty() {
                    bytes
                } else {
                    let mut joined = std::mem::take(&mut buffer);
                    joined.extend_from_slice(&bytes);
                    joined
                }
            }
            WriteCommand::Close => break,
        };
        if bytes.is_empty() {
            continue;
        }
        let writes = if padding {
            packet += 1;
            let factory = lock(&inner.padding).clone();
            if packet < factory.stop() {
                wire::pad_record(&factory, packet, bytes, wire::random_jitter)
            } else {
                padding = false;
                vec![bytes]
            }
        } else {
            vec![bytes]
        };
        for chunk in writes {
            if conn.write_all(&chunk).await.is_err() {
                inner.close();
                return;
            }
        }
        if conn.flush().await.is_err() {
            inner.close();
            return;
        }
    }
    // The writer ending closes the carrier, which ends the reader too.
    let _ = conn.shutdown().await;
    inner.close();
}

async fn read_loop(
    inner: Arc<SessionInner>,
    mut conn: tokio::io::ReadHalf<BoxedTransportStream>,
    writer: mpsc::Sender<WriteCommand>,
) {
    let mut header = [0u8; wire::HEADER_LENGTH];
    let mut payload = Vec::new();
    loop {
        if conn.read_exact(&mut header).await.is_err() {
            break;
        }
        let Ok(Some(frame)) = FrameHeader::decode(&header) else {
            break;
        };
        let length = usize::from(frame.length);
        payload.clear();
        payload.resize(length, 0);
        if length > 0 && conn.read_exact(&mut payload).await.is_err() {
            break;
        }
        if !dispatch(&inner, &writer, frame, &payload).await {
            break;
        }
    }
    inner.close();
}

/// Apply one frame. `false` stops the reader: the session is finished.
async fn dispatch(
    inner: &Arc<SessionInner>,
    writer: &mpsc::Sender<WriteCommand>,
    frame: FrameHeader,
    payload: &[u8],
) -> bool {
    match frame.command {
        Command::Push => {
            if payload.is_empty() {
                return true;
            }
            let Some(tx) = lock(&inner.streams).get(&frame.stream_id).cloned() else {
                // A frame for a stream that already ended is discarded.
                return true;
            };
            // A full queue pauses the whole session until its consumer
            // drains, as the Go pipe blocks the reader.
            if tx
                .send(StreamEvent::Data(Bytes::copy_from_slice(payload)))
                .await
                .is_err()
            {
                lock(&inner.streams).remove(&frame.stream_id);
            }
            true
        }
        // A server never opens streams toward a client; ignoring one is what
        // the reference does.
        Command::Syn => true,
        Command::SynAck => {
            inner.syn_generation.fetch_add(1, Ordering::AcqRel);
            if !payload.is_empty() {
                let message = String::from_utf8_lossy(payload).into_owned();
                if let Some(tx) = lock(&inner.streams).remove(&frame.stream_id) {
                    let _ = tx.try_send(StreamEvent::Failed(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        message,
                    )));
                }
            }
            true
        }
        Command::Fin => {
            if let Some(tx) = lock(&inner.streams).remove(&frame.stream_id) {
                let _ = tx.try_send(StreamEvent::Finished);
            }
            true
        }
        Command::Waste | Command::Settings => true,
        Command::ServerSettings => {
            if let Ok(map) = wire::parse_settings(payload) {
                // `str::parse` does not coerce `&String` when passed as a function item.
                if let Some(Ok(version)) = map.get("v").map(|value| value.parse::<u8>()) {
                    inner.peer_version.store(version, Ordering::Release);
                }
            }
            true
        }
        Command::UpdatePaddingScheme => {
            // Only a well-formed scheme replaces the current one.
            if let Some(factory) = PaddingFactory::new(payload) {
                *lock(&inner.padding) = factory;
            }
            true
        }
        Command::Alert => {
            let message = String::from_utf8_lossy(payload).into_owned();
            let message = if message.is_empty() {
                "AnyTLS server alert".to_owned()
            } else {
                message
            };
            for tx in std::mem::take(&mut *lock(&inner.streams)).into_values() {
                let _ = tx.try_send(StreamEvent::Failed(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    message.clone(),
                )));
            }
            false
        }
        Command::HeartRequest => {
            let reply = wire::control_frame(Command::HeartResponse, frame.stream_id, &[]);
            let _ = writer.try_send(WriteCommand::Control(reply));
            true
        }
        Command::HeartResponse => true,
    }
}

/// One multiplexed stream. Dropping it sends `Fin` and returns the session to
/// the idle pool once its last stream ends.
#[derive(Debug)]
pub(super) struct Stream {
    id: u32,
    session: Arc<Session>,
    writer: mpsc::Sender<WriteCommand>,
    rx: mpsc::Receiver<StreamEvent>,
    pending: Bytes,
    fin_sent: bool,
}

impl Stream {
    fn send_fin(&mut self) {
        if self.fin_sent {
            return;
        }
        self.fin_sent = true;
        let frame = wire::control_frame(Command::Fin, self.id, &[]);
        if self.writer.try_send(WriteCommand::Control(frame)).is_err() {
            // A full queue means the writer is not draining. Closing the
            // session tells the server the same thing a `Fin` would, and
            // releases every other stream on it.
            self.session.inner.close();
        }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.send_fin();
        let inner = &self.session.inner;
        lock(&inner.streams).remove(&self.id);
        inner.release_stream();
        if inner.active.load(Ordering::Acquire) == 0 {
            if let Some(pool) = inner.pool.upgrade() {
                pool.push_idle(&self.session);
            }
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.pending.is_empty() {
                let take = out.remaining().min(self.pending.len());
                out.put_slice(&self.pending[..take]);
                self.pending.advance(take);
                return Poll::Ready(Ok(()));
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(StreamEvent::Data(bytes))) => self.pending = bytes,
                Poll::Ready(Some(StreamEvent::Finished)) | Poll::Ready(None) => {
                    return Poll::Ready(Ok(()))
                }
                Poll::Ready(Some(StreamEvent::Failed(error))) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.session.closed() {
            return Poll::Ready(Err(closed()));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let frames = wire::push_frames(self.id, input);
        match self.writer.poll_reserve(cx) {
            Poll::Ready(Ok(permit)) => {
                let written = input.len();
                permit.send(WriteCommand::Data(frames));
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(closed())),
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Writes are queued whole; the writer task flushes each one.
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.send_fin();
        Poll::Ready(Ok(()))
    }
}

impl TransportStream for Stream {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_read(cx, out)
    }
    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write(cx, input)
    }
}
