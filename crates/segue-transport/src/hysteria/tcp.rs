use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use quinn::{RecvStream, SendStream, VarInt};
use segue_proxy::hysteria::{
    decode_tcp_response, encode_tcp_request, TcpRequest, WireError, MAX_MESSAGE_LENGTH,
    MAX_PADDING_LENGTH,
};
use segue_routing::{Network, Target};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, TryAcquireError};
use tokio::time::timeout;

use super::client::{random_padding, Shared};
use super::{HysteriaClient, HysteriaError};
use crate::stream::QUIC_SEND_WINDOW_SAMPLE_BYTES;
use crate::TransportStream;

const RESPONSE_HEADER_LIMIT: usize = 1 + 8 + MAX_MESSAGE_LENGTH + 8 + MAX_PADDING_LENGTH;

struct PendingStream {
    streams: Option<(SendStream, RecvStream)>,
}
impl Drop for PendingStream {
    fn drop(&mut self) {
        if let Some((send, recv)) = &mut self.streams {
            let _ = send.reset(VarInt::from_u32(0));
            let _ = recv.stop(VarInt::from_u32(0));
        }
    }
}

pub struct HysteriaTcpStream {
    send: SendStream,
    recv: RecvStream,
    /// TCP request frame still to be written. Emptied once it has been handed
    /// to Quinn, whether alone or in front of the first payload.
    header: Vec<u8>,
    header_pos: usize,
    /// The first read gives a concurrent write one poll to attach its payload
    /// to `header` before the request goes out by itself.
    read_yielded: bool,
    response_buf: Vec<u8>,
    response_pending: bool,
    /// Server bytes that arrived in the same chunk as the response header.
    prefix: Bytes,
    /// Sticky failure from a bad response, so the server message is not kept.
    failed: Option<HysteriaError>,
    send_finished: bool,
    bytes_since_window_sample: usize,
    _connection: Arc<Shared>,
    _slot: OwnedSemaphorePermit,
}

impl HysteriaClient {
    /// Opens a TCP stream without waiting for the server's response.
    ///
    /// sing-box writes the Hysteria request and the first payload in one
    /// `Write`, and only reads the status on the first `Read`. Waiting for
    /// that status here held every SOCKS flow for a full round trip before
    /// the client's bytes could leave, so time-to-first-byte was two RTTs
    /// on a reused connection. The request stays in `header` until the first
    /// write (in front of that payload), flush, shutdown, or a read that
    /// finds no payload waiting.
    pub async fn open_tcp(&self, target: &Target) -> Result<HysteriaTcpStream, HysteriaError> {
        let address = super::address(target, Network::Tcp)?;
        if !self.is_live() {
            return Err(HysteriaError::Closed);
        }
        let slot = Arc::clone(&self.shared.tcp_slots)
            .try_acquire_owned()
            .map_err(|error| match error {
                TryAcquireError::Closed => HysteriaError::Closed,
                TryAcquireError::NoPermits => HysteriaError::SessionLimit,
            })?;
        let connection = self.shared.connection()?;
        let opened = timeout(self.shared.limits.operation_timeout, connection.open_bi())
            .await
            .map_err(|_| HysteriaError::Timeout)?
            .map_err(|_| HysteriaError::Stream)?;
        let mut pending = PendingStream {
            streams: Some(opened),
        };
        let padding = random_padding(64, 512);
        let request = encode_tcp_request(&TcpRequest {
            address: &address,
            padding: padding.as_bytes(),
        })
        .map_err(|_| HysteriaError::Target)?;
        let (send, recv) = pending.streams.take().expect("opened stream");
        Ok(HysteriaTcpStream {
            send,
            recv,
            header: request,
            header_pos: 0,
            read_yielded: false,
            response_buf: Vec::new(),
            response_pending: true,
            prefix: Bytes::new(),
            failed: None,
            send_finished: false,
            bytes_since_window_sample: 0,
            _connection: Arc::clone(&self.shared),
            _slot: slot,
        })
    }
}

impl HysteriaTcpStream {
    fn observe_send(&mut self, written: usize) {
        self.bytes_since_window_sample += written;
        if self.bytes_since_window_sample >= QUIC_SEND_WINDOW_SAMPLE_BYTES {
            self.bytes_since_window_sample = 0;
            self._connection.grow_send_window();
        }
    }

    fn poll_send(&mut self, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        // The inherent method returns Quinn's `WriteError`; the trait maps it.
        match AsyncWrite::poll_write(Pin::new(&mut self.send), cx, bytes) {
            Poll::Ready(Ok(0)) if !bytes.is_empty() => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "Hysteria stream failed",
            ))),
            Poll::Ready(Ok(written)) => {
                self.observe_send(written);
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(redact_error(error))),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Hands the TCP request to Quinn. A caller that then writes the payload
    /// in the same poll does so before the driver is scheduled, so both share
    /// one send.
    fn poll_flush_header(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.header_pos < self.header.len() {
            // Disjoint fields: `send` is borrowed mutably and `header` immutably.
            let written = match AsyncWrite::poll_write(
                Pin::new(&mut self.send),
                cx,
                &self.header[self.header_pos..],
            ) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(redact_error(error))),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Hysteria stream failed",
                    )))
                }
                Poll::Ready(Ok(written)) => written,
            };
            self.header_pos += written;
            self.observe_send(written);
        }
        if !self.header.is_empty() {
            self.header.clear();
            self.header_pos = 0;
        }
        Poll::Ready(Ok(()))
    }

    fn fail(&mut self, error: HysteriaError) -> io::Error {
        // Drop the server's message bytes; the error text must not carry them.
        self.response_buf.clear();
        self.failed = Some(error);
        io::Error::other(error)
    }

    fn poll_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = self.failed {
            return Poll::Ready(Err(io::Error::other(error)));
        }
        if !self.response_pending {
            return Poll::Ready(Ok(()));
        }
        // A read with no write yet still has to open the target. Yield once
        // so a payload already queued on the other half can lead the request.
        if self.header_pos < self.header.len() {
            if !self.read_yielded {
                self.read_yielded = true;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if let Poll::Ready(error) = self.poll_flush_header(cx) {
                error?;
            } else {
                return Poll::Pending;
            }
        }
        loop {
            match decode_tcp_response(&self.response_buf) {
                Ok((response, consumed)) => {
                    if response.status != 0 {
                        return Poll::Ready(Err(self.fail(HysteriaError::TcpRejected)));
                    }
                    let rest = &self.response_buf[consumed..];
                    self.prefix = if rest.is_empty() {
                        Bytes::new()
                    } else {
                        Bytes::copy_from_slice(rest)
                    };
                    self.response_buf.clear();
                    self.response_pending = false;
                    return Poll::Ready(Ok(()));
                }
                Err(WireError::Incomplete) => {}
                Err(_) => return Poll::Ready(Err(self.fail(HysteriaError::TcpResponse))),
            }
            if self.response_buf.len() >= RESPONSE_HEADER_LIMIT {
                return Poll::Ready(Err(self.fail(HysteriaError::TcpResponse)));
            }
            let mut chunk = [0u8; 1024];
            let mut read = ReadBuf::new(&mut chunk);
            let received = match Pin::new(&mut self.recv).poll_read(cx, &mut read) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(redact_error(error))),
                Poll::Ready(Ok(())) => read.filled().len(),
            };
            if received == 0 {
                return Poll::Ready(Err(self.fail(HysteriaError::TcpResponse)));
            }
            self.response_buf.extend_from_slice(read.filled());
        }
    }
}

impl AsyncRead for HysteriaTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Poll::Ready(error) = this.poll_response(cx) {
            error?;
        } else {
            return Poll::Pending;
        }
        if !this.prefix.is_empty() {
            let count = output.remaining().min(this.prefix.len());
            output.put_slice(&this.prefix[..count]);
            this.prefix.advance(count);
            if this.prefix.is_empty() {
                this.prefix = Bytes::new();
            }
            return Poll::Ready(Ok(()));
        }
        redact_io(AsyncRead::poll_read(Pin::new(&mut this.recv), cx, output))
    }
}

impl AsyncWrite for HysteriaTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // Finish the request and accept payload before returning, so Quinn
        // sees both before its driver is polled.
        if this.header_pos < this.header.len() {
            if let Poll::Ready(error) = this.poll_flush_header(cx) {
                error?;
            } else {
                return Poll::Pending;
            }
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.poll_send(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Poll::Ready(error) = this.poll_flush_header(cx) {
            error?;
        } else {
            return Poll::Pending;
        }
        redact_io(AsyncWrite::poll_flush(Pin::new(&mut this.send), cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Poll::Ready(error) = this.poll_flush_header(cx) {
            error?;
        } else {
            return Poll::Pending;
        }
        let result = redact_io(AsyncWrite::poll_shutdown(Pin::new(&mut this.send), cx));
        if matches!(result, Poll::Ready(Ok(()))) {
            this.send_finished = true;
        }
        result
    }
}

impl TransportStream for HysteriaTcpStream {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }
    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

impl Drop for HysteriaTcpStream {
    fn drop(&mut self) {
        if !self.send_finished {
            let _ = self.send.reset(VarInt::from_u32(0));
        }
        let _ = self.recv.stop(VarInt::from_u32(0));
    }
}

fn redact_error(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), "Hysteria stream failed")
}

fn redact_io<T>(result: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
    match result {
        Poll::Ready(Err(error)) => Poll::Ready(Err(redact_error(error))),
        other => other,
    }
}
