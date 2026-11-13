//! The app side of a session: a pipe that remembers how the session ended.
//!
//! The driver can only end the pipe one way (EOF), so on its own a revoked,
//! reset or failed session would look like a complete response. This wrapper
//! turns an end that is not a clean FIN into an error (SESSION_PROTOCOL
//! §5.5: anything but a clean close is a local RST), which SOCKS and TUN
//! map to RST.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use segue_session::client::CloseReason;
use segue_session::pipe::PipeEnd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;

pub struct SessionStream<P = PipeEnd> {
    pipe: P,
    closed: oneshot::Receiver<CloseReason>,
    /// None: the session has not ended (yet). Some(None): it ended without
    /// a reason (the driver was dropped).
    reason: Option<Option<CloseReason>>,
}

impl<P> SessionStream<P> {
    pub fn new(pipe: P, closed: oneshot::Receiver<CloseReason>) -> Self {
        Self {
            pipe,
            closed,
            reason: None,
        }
    }

    /// How the session ended, if it has. The driver reports the reason
    /// before it shuts the pipe, so at EOF it is already here unless the
    /// EOF is the peer's FIN on a session that is still open.
    fn reason(&mut self) -> Option<Option<CloseReason>> {
        if self.reason.is_none() {
            match self.closed.try_recv() {
                Ok(r) => self.reason = Some(Some(r)),
                Err(oneshot::error::TryRecvError::Closed) => self.reason = Some(None),
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
        }
        self.reason
    }

    fn failure(&mut self) -> Option<io::Error> {
        match self.reason()? {
            Some(CloseReason::Clean) => None,
            r => Some(io::Error::new(
                io::ErrorKind::ConnectionReset,
                super::closed_text(r),
            )),
        }
    }
}

impl<P: AsyncRead + AsyncWrite + Unpin> AsyncRead for SessionStream<P> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.pipe).poll_read(cx, buf) {
            Poll::Ready(Ok(())) if buf.filled().len() == before && buf.remaining() > 0 => {
                // EOF: only a clean end (or a FIN on a live session) is one.
                match this.failure() {
                    Some(e) => Poll::Ready(Err(e)),
                    None => Poll::Ready(Ok(())),
                }
            }
            other => other,
        }
    }
}

impl<P: AsyncRead + AsyncWrite + Unpin> AsyncWrite for SessionStream<P> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.pipe).poll_write(cx, data) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(this.failure().unwrap_or(e))),
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().pipe).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().pipe).poll_shutdown(cx)
    }
}

impl<P: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static> segue_transport::TransportStream
    for SessionStream<P>
{
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_read(cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write(cx, input)
    }
}
