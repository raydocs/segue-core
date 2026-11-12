//! In-memory byte pipe between an app stream and a session driver whose
//! buffers are charged to the pool and freed when drained.
//!
//! `tokio::io::duplex` keeps the capacity of its buffers after they were
//! read, so a pipe that once carried a burst holds that memory for its
//! whole life, outside any budget. Here each direction holds at most `max`
//! bytes, its memory is covered by a [`Grant`] and released as soon as the
//! reader empties it. When the pool cannot cover more, an empty direction
//! may still take one block (so a session always makes progress); a
//! non-empty one waits for its reader.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::pool::{Grant, Pool, BLOCK};

struct Dir {
    buf: VecDeque<u8>,
    grant: Grant,
    /// The writing end shut down or was dropped: EOF once drained.
    write_closed: bool,
    /// The reading end was dropped: writes fail.
    read_closed: bool,
    reader: Option<Waker>,
    writer: Option<Waker>,
}

impl Dir {
    fn new(pool: &Arc<Pool>) -> Self {
        Self {
            buf: VecDeque::new(),
            grant: Grant::new(pool, false),
            write_closed: false,
            read_closed: false,
            reader: None,
            writer: None,
        }
    }

    fn release(&mut self) {
        self.buf = VecDeque::new();
        self.grant.try_resize(0);
    }
}

struct Shared {
    /// `dirs[i]` is written by end `i` and read by end `1 - i`.
    dirs: [Mutex<Dir>; 2],
    max: usize,
}

/// One end of a [`pipe`].
pub struct PipeEnd {
    shared: Arc<Shared>,
    side: usize,
}

/// A bidirectional pipe holding at most `max` bytes per direction.
pub fn pipe(pool: &Arc<Pool>, max: usize) -> (PipeEnd, PipeEnd) {
    let shared = Arc::new(Shared {
        dirs: [Mutex::new(Dir::new(pool)), Mutex::new(Dir::new(pool))],
        max: max.max(1),
    });
    (
        PipeEnd {
            shared: shared.clone(),
            side: 0,
        },
        PipeEnd { shared, side: 1 },
    )
}

impl PipeEnd {
    fn tx(&self) -> std::sync::MutexGuard<'_, Dir> {
        self.shared.dirs[self.side].lock().unwrap()
    }

    fn rx(&self) -> std::sync::MutexGuard<'_, Dir> {
        self.shared.dirs[1 - self.side].lock().unwrap()
    }

    /// Memory currently held by both directions' buffers.
    pub fn held_bytes(&self) -> usize {
        self.tx().buf.capacity() + self.rx().buf.capacity()
    }
}

impl AsyncRead for PipeEnd {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut d = self.rx();
        if d.buf.is_empty() {
            if d.write_closed {
                return Poll::Ready(Ok(()));
            }
            d.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = d.buf.len().min(out.remaining());
        let (a, b) = d.buf.as_slices();
        let k = a.len().min(n);
        out.put_slice(&a[..k]);
        out.put_slice(&b[..n - k]);
        d.buf.drain(..n);
        if d.buf.is_empty() {
            d.release();
        }
        if let Some(w) = d.writer.take() {
            w.wake();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for PipeEnd {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let max = self.shared.max;
        let mut d = self.tx();
        if d.read_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if d.write_closed {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let len = d.buf.len();
        let mut room = max.saturating_sub(len).min(data.len());
        if room > 0 && len + room > d.buf.capacity() {
            // Grow (doubling, within `max`) only as far as the grant covers.
            let target = (d.buf.capacity() * 2).max(len + room).min(max);
            let covered = d.grant.grow_towards(target);
            let floor = if len == 0 { BLOCK.min(max) } else { 0 };
            let cap = covered.max(floor).min(target);
            room = room.min(cap.saturating_sub(len));
            if room > 0 {
                let want = cap.max(len + room);
                d.buf.reserve_exact(want - len);
            }
        }
        if room == 0 {
            d.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        d.buf.extend(&data[..room]);
        if let Some(w) = d.reader.take() {
            w.wake();
        }
        Poll::Ready(Ok(room))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut d = self.tx();
        d.write_closed = true;
        if let Some(w) = d.reader.take() {
            w.wake();
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for PipeEnd {
    fn drop(&mut self) {
        {
            let mut d = self.tx();
            d.write_closed = true;
            if let Some(w) = d.reader.take() {
                w.wake();
            }
        }
        let mut d = self.rx();
        d.read_closed = true;
        d.release();
        if let Some(w) = d.writer.take() {
            w.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn drained_pipe_returns_its_memory() {
        let pool = Pool::new(1 << 20);
        let (mut a, mut b) = pipe(&pool, 16 * 1024);
        a.write_all(&[7u8; 16 * 1024]).await.unwrap();
        assert!(a.held_bytes() >= 16 * 1024);
        assert!(pool.used_bytes() >= 16 * 1024);
        let mut out = vec![0u8; 16 * 1024];
        b.read_exact(&mut out).await.unwrap();
        assert_eq!(a.held_bytes(), 0);
        assert_eq!(pool.used_bytes(), 0);
        a.shutdown().await.unwrap();
        assert_eq!(b.read(&mut out).await.unwrap(), 0);
        drop(b);
        assert!(a.write(b"x").await.is_err());
    }

    #[tokio::test]
    async fn exhausted_pool_still_moves_one_block_at_a_time() {
        let pool = Pool::new(BLOCK);
        let _hog = Grant::fixed(&pool, BLOCK).unwrap();
        let (mut a, mut b) = pipe(&pool, 64 * 1024);
        let w = tokio::spawn(async move {
            a.write_all(&[1u8; 40_000]).await.unwrap();
        });
        let mut got = Vec::new();
        let mut buf = [0u8; 8192];
        while got.len() < 40_000 {
            let n = b.read(&mut buf).await.unwrap();
            assert!(n <= BLOCK, "more than the progress floor uncharged");
            got.extend_from_slice(&buf[..n]);
        }
        w.await.unwrap();
    }
}
