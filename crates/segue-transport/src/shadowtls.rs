//! ShadowTLS v3 stream security.
//!
//! The real TLS server remains the certificate endpoint. During the handshake
//! the server relays its records, transforming each application-data record so
//! only a client holding the password can unwrap it. After that switch the
//! inner proxy is carried directly in TLS-shaped, chained-HMAC records.
//!
//! Wire semantics follow sing-shadowtls v3 (`v3_client.go`, `v3_conn.go` and
//! `v3_server.go`). Version 2 has a different hash connection; it is deliberately
//! not hidden behind this connector.

use std::{
    fmt, io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, BytesMut};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use rustls::{
    client::{
        ClientHelloContext, ClientHelloCustomizer, ClientHelloPlan, ClientHelloSessionId,
        FinalizesClientHello,
    },
    pki_types::ServerName,
    Error as RustlsError,
};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    utls_shaping::{apply_utls_profile, HelloDraws},
    utls_tls::{alpn_override_for, unshaped_alpn_protocols, TlsAlpnPolicy},
    BoxedTransportStream, TlsClientConfig, TlsConnector, TransportError, TransportStream,
};

const TLS_HEADER_LEN: usize = 5;
const HMAC_LEN: usize = 4;
const TLS_HMAC_HEADER_LEN: usize = TLS_HEADER_LEN + HMAC_LEN;
const TLS_RANDOM_LEN: usize = 32;
const TLS_SESSION_ID_LEN: usize = 32;
const CLIENT_HELLO_SESSION_ID_START: usize = 1 + 3 + 2 + TLS_RANDOM_LEN + 1;
const SERVER_RANDOM_START: usize = TLS_HEADER_LEN + 1 + 3 + 2;
const MAX_PLAINTEXT_RECORD: usize = 16 * 1024;
const HANDSHAKE: u8 = 22;
const APPLICATION_DATA: u8 = 23;
const ALERT: u8 = 21;
const SERVER_HELLO: u8 = 2;

type Sha1Hmac = Hmac<Sha1>;

/// The connector's resolved settings. `password` authenticates the handshake
/// and both directions of the post-switch stream; `tls` controls the genuine
/// TLS certificate handshake, its SNI and its uTLS fingerprint.
#[derive(Clone)]
pub struct ShadowTlsConfig {
    pub password: Zeroizing<String>,
    pub tls: TlsClientConfig,
}

impl fmt::Debug for ShadowTlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShadowTlsConfig")
            .field("password", &"<redacted>")
            .field("tls", &self.tls)
            .finish()
    }
}

/// One connection's TLS material. The customizer is attached after cloning
/// the shared fingerprint config: passwords and finalizers never enter the
/// ordinary TLS connector's cache.
pub struct PreparedShadowTls {
    password: Zeroizing<String>,
    client_config: Arc<rustls::ClientConfig>,
    server_name: ServerName<'static>,
}

impl TlsConnector {
    pub fn prepare_shadow_tls_stream(
        &self,
        config: &ShadowTlsConfig,
    ) -> Result<PreparedShadowTls, TransportError> {
        let base = self.client_config_for(&config.tls)?;
        let server_name = crate::tls::parse_tls_server_name(&config.tls.server_name)?;
        let profile = match config.tls.fingerprint.as_deref() {
            Some(fingerprint) => crate::utls_tls::shaping_profile(Some(fingerprint))?,
            // Programmatic callers that leave this unset get the same defaults
            // as an ordinary TLS config. Parsed ShadowTLS always defaults to Chrome.
            None => None,
        };
        let mut client_config = (*base).clone();
        // ShadowTLS authenticates every ClientHello. A resumed hello would
        // need a fresh binder too, which a finalizer must not rewrite.
        client_config.resumption = rustls::client::Resumption::disabled();
        client_config.enable_early_data = false;
        client_config.alpn_protocols =
            unshaped_alpn_protocols(&config.tls.alpn, TlsAlpnPolicy::Raw);
        client_config.client_hello_customizer = Some(Arc::new(ShadowTlsHello {
            password: config.password.clone(),
            profile: profile.map(|(_, profile)| profile),
            alpn_override: alpn_override_for(&config.tls.alpn, TlsAlpnPolicy::Raw),
        }));
        Ok(PreparedShadowTls {
            password: config.password.clone(),
            client_config: Arc::new(client_config),
            server_name,
        })
    }
}

/// Runs the relayed TLS handshake and switches the same carrier to ShadowTLS
/// application framing. No bytes are passed to the inner proxy without the
/// server having proved possession of the password (or negotiated TLS 1.2,
/// which v3 accepts without its TLS-1.3 dummy-record proof).
pub(crate) async fn connect_shadow_tls_stream(
    carrier: BoxedTransportStream,
    prepared: PreparedShadowTls,
) -> Result<BoxedTransportStream, TransportError> {
    let password = prepared.password.clone();
    let relay = HandshakeRelay::new(carrier, password.clone());
    let stream = tokio_rustls::TlsConnector::from(prepared.client_config)
        .connect(prepared.server_name, relay)
        .await
        .map_err(TransportError::Tls)?;
    let (relay, mut session) = stream.into_inner();
    let mut plaintext = Vec::new();
    session.reader().read_to_end(&mut plaintext).map_err(TransportError::Tls)?;
    if !plaintext.is_empty() {
        return Err(TransportError::ShadowTls(
            "unconsumed TLS dummy plaintext at the switch".to_owned(),
        ));
    }
    let (carrier, server_random, handshake_read_mac, authorized) = relay.finish();
    if !authorized {
        return Err(TransportError::ShadowTls(
            "the TLS relay did not authenticate as ShadowTLS v3".to_owned(),
        ));
    }
    let mut stream = ShadowTlsStream::new(carrier, password, server_random);
    stream.handshake_read_mac = handshake_read_mac;
    Ok(Box::new(stream))
}

struct ShadowTlsHello {
    password: Zeroizing<String>,
    profile: Option<&'static crate::utls_profiles::UtlsClientHelloProfile>,
    alpn_override: Option<Vec<Vec<u8>>>,
}

impl fmt::Debug for ShadowTlsHello {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShadowTlsHello")
            .field("password", &"<redacted>")
            .field("has_profile", &self.profile.is_some())
            .finish_non_exhaustive()
    }
}

impl ClientHelloCustomizer for ShadowTlsHello {
    fn build_client_hello_plan(
        &self,
        context: ClientHelloContext<'_>,
    ) -> Result<Option<ClientHelloPlan>, RustlsError> {
        if context.is_quic {
            return Err(RustlsError::General(
                "ShadowTLS v3 is only available on TCP".to_owned(),
            ));
        }
        // A placeholder determines the field's length. The finalizer replaces
        // it after every extension has been encoded but before the handshake
        // transcript and socket see the hello.
        let mut plan = ClientHelloPlan::new()
            .with_session_id(ClientHelloSessionId::try_from(vec![0; 32])?)
            .with_finalizer(Arc::new(ShadowTlsHelloFinalizer {
                password: self.password.clone(),
            }));
        if let Some(profile) = self.profile {
            plan = apply_utls_profile(
                plan,
                profile,
                context,
                &HelloDraws::draw(profile)?,
                self.alpn_override.as_deref(),
            )?;
        }
        Ok(Some(plan))
    }
}

struct ShadowTlsHelloFinalizer {
    password: Zeroizing<String>,
}

impl fmt::Debug for ShadowTlsHelloFinalizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ShadowTlsHelloFinalizer(<redacted>)")
    }
}

impl FinalizesClientHello for ShadowTlsHelloFinalizer {
    fn finalize_client_hello(&self, hello: &mut Vec<u8>) -> Result<(), RustlsError> {
        generate_session_id(self.password.as_bytes(), hello).map_err(|error| {
            RustlsError::General(format!("ShadowTLS ClientHello authentication failed: {error}"))
        })
    }
}

/// The handshake message includes its four-byte handshake header but not the
/// record header. Go's generator sees the same bytes with the record header;
/// both index calculations therefore hash exactly the same logical message.
fn generate_session_id(password: &[u8], hello: &mut [u8]) -> Result<(), &'static str> {
    let mut random = [0u8; TLS_SESSION_ID_LEN - HMAC_LEN];
    OsRng.fill_bytes(&mut random);
    let result = seal_session_id(password, hello, random);
    random.zeroize();
    result
}

fn seal_session_id(
    password: &[u8],
    hello: &mut [u8],
    random: [u8; TLS_SESSION_ID_LEN - HMAC_LEN],
) -> Result<(), &'static str> {
    let session_end = CLIENT_HELLO_SESSION_ID_START + TLS_SESSION_ID_LEN;
    if hello.len() < session_end {
        return Err("ClientHello is too short for a v3 session ID");
    }
    let mut session_id = [0u8; TLS_SESSION_ID_LEN];
    session_id[..TLS_SESSION_ID_LEN - HMAC_LEN].copy_from_slice(&random);
    let mut hmac = <Sha1Hmac as Mac>::new_from_slice(password)
        .map_err(|_| "ShadowTLS password could not initialize HMAC")?;
    hmac.update(&hello[..CLIENT_HELLO_SESSION_ID_START]);
    hmac.update(&session_id);
    hmac.update(&hello[session_end..]);
    session_id[TLS_SESSION_ID_LEN - HMAC_LEN..]
        .copy_from_slice(&hmac.finalize().into_bytes()[..HMAC_LEN]);
    hello[CLIENT_HELLO_SESSION_ID_START..session_end].copy_from_slice(&session_id);
    session_id.zeroize();
    Ok(())
}

/// Server-side verification form: the stored tag contributes four zero bytes.
fn client_hello_tag_valid(password: &[u8], record: &[u8]) -> bool {
    let hmac_start = TLS_HEADER_LEN + CLIENT_HELLO_SESSION_ID_START + 28;
    if record.len() < hmac_start + HMAC_LEN
        || record[0] != HANDSHAKE
        || record[5] != 1
        || record[TLS_HEADER_LEN + CLIENT_HELLO_SESSION_ID_START - 1]
            != TLS_SESSION_ID_LEN as u8
    {
        return false;
    }
    let mut hmac = match <Sha1Hmac as Mac>::new_from_slice(password) {
        Ok(hmac) => hmac,
        Err(_) => return false,
    };
    hmac.update(&record[TLS_HEADER_LEN..hmac_start]);
    hmac.update(&[0; HMAC_LEN]);
    hmac.update(&record[hmac_start + HMAC_LEN..]);
    hmac_equal(
        &record[hmac_start..hmac_start + HMAC_LEN],
        &hmac.finalize().into_bytes()[..HMAC_LEN],
    )
}

fn hmac_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |different, (left, right)| different | (left ^ right))
            == 0
}

fn server_random(record: &[u8]) -> Option<[u8; TLS_RANDOM_LEN]> {
    if record.len() < SERVER_RANDOM_START + TLS_RANDOM_LEN
        || record[0] != HANDSHAKE
        || record[5] != SERVER_HELLO
    {
        return None;
    }
    record[SERVER_RANDOM_START..SERVER_RANDOM_START + TLS_RANDOM_LEN]
        .try_into()
        .ok()
}

/// The TLS 1.3 supported_versions extension in a ServerHello handshake body.
/// HRR is a ServerHello too, and goes through exactly the same extraction.
fn hello_supports_tls13(record: &[u8]) -> bool {
    let mut offset = TLS_HEADER_LEN + 4 + 2 + TLS_RANDOM_LEN;
    let Some(&session_len) = record.get(offset) else {
        return false;
    };
    offset += 1 + usize::from(session_len) + 2 + 1;
    let Some(extension_bytes) = record.get(offset..offset + 2) else {
        return false;
    };
    let mut remaining = usize::from(u16::from_be_bytes([extension_bytes[0], extension_bytes[1]]));
    offset += 2;
    while remaining >= 4 {
        let Some(header) = record.get(offset..offset + 4) else {
            return false;
        };
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        offset += 4;
        remaining -= 4;
        if length > remaining {
            return false;
        }
        if kind == 43 {
            return length == 2 && record.get(offset..offset + 2) == Some(&[3, 4]);
        }
        offset += length;
        remaining -= length;
    }
    false
}

fn xor_wrap_key(password: &[u8], server_random: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password);
    hasher.update(server_random);
    hasher.finalize().into()
}

fn xor_wrap(payload: &mut [u8], key: &[u8; 32]) {
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[index % key.len()];
    }
}

/// One direction's rolling MAC. The digest includes the new record's four-byte
/// tag before the next record, exactly as Go's `hmacAdd.Write(hmacHash)` does.
struct FrameMac {
    inner: Sha1Hmac,
}

impl FrameMac {
    fn new(password: &[u8], server_random: &[u8; 32], direction: u8) -> Self {
        let mut inner = <Sha1Hmac as Mac>::new_from_slice(password)
            .expect("HMAC-SHA1 accepts a key of every length");
        inner.update(server_random);
        inner.update(&[direction]);
        Self { inner }
    }

    fn seal(&mut self, payload: &[u8]) -> [u8; HMAC_LEN] {
        self.inner.update(payload);
        let tag: [u8; HMAC_LEN] = self.inner.clone().finalize().into_bytes()[..HMAC_LEN]
            .try_into()
            .expect("the tag prefix has four bytes");
        self.inner.update(&tag);
        tag
    }

    fn open(&mut self, payload: &[u8], tag: &[u8]) -> bool {
        let mut next = self.inner.clone();
        next.update(payload);
        let expected = next.clone().finalize().into_bytes();
        if !hmac_equal(tag, &expected[..HMAC_LEN]) {
            return false;
        }
        next.update(tag);
        self.inner = next;
        true
    }
}

/// Complete-record reader shared by the relay and application phases. The TLS
/// length field bounds buffering to 65,540 bytes even for a malformed peer.
struct RecordReader<S> {
    inner: S,
    buffered: BytesMut,
    eof: bool,
}

impl<S> RecordReader<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn new(inner: S) -> Self {
        Self {
            inner,
            buffered: BytesMut::with_capacity(MAX_PLAINTEXT_RECORD + TLS_HEADER_LEN),
            eof: false,
        }
    }

    fn poll_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Vec<u8>>>> {
        let mut scratch = [0u8; 16 * 1024];
        loop {
            if self.buffered.len() >= TLS_HEADER_LEN {
                let payload_len = usize::from(u16::from_be_bytes([
                    self.buffered[3],
                    self.buffered[4],
                ]));
                if self.buffered.len() >= TLS_HEADER_LEN + payload_len {
                    return Poll::Ready(Ok(Some(
                        self.buffered.split_to(TLS_HEADER_LEN + payload_len).to_vec(),
                    )));
                }
            }
            if self.eof {
                return if self.buffered.is_empty() {
                    Poll::Ready(Ok(None))
                } else {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated TLS record",
                    )))
                };
            }
            let mut read = ReadBuf::new(&mut scratch);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read) {
                Poll::Ready(Ok(())) if read.filled().is_empty() => self.eof = true,
                Poll::Ready(Ok(())) => self.buffered.extend_from_slice(read.filled()),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }


}

fn is_handshake_dummy(record: &[u8], mac: &Sha1Hmac) -> bool {
    if record.len() <= TLS_HMAC_HEADER_LEN || record[..3] != [HANDSHAKE, 3, 3] {
        return false;
    }
    let mut next = mac.clone();
    next.update(&record[TLS_HMAC_HEADER_LEN..]);
    hmac_equal(
        &record[TLS_HEADER_LEN..TLS_HMAC_HEADER_LEN],
        &next.finalize().into_bytes()[..HMAC_LEN],
    )
}

struct RawBufferedStream {
    inner: BoxedTransportStream,
    buffered: BytesMut,
}

impl AsyncRead for RawBufferedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.buffered.is_empty() {
            let count = self.buffered.len().min(output.remaining());
            output.put_slice(&self.buffered[..count]);
            self.buffered.advance(count);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, output)
    }
}

impl AsyncWrite for RawBufferedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, input)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl TransportStream for RawBufferedStream {
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

struct HandshakeRelay {
    records: RecordReader<BoxedTransportStream>,
    pending_text: BytesMut,
    password: Zeroizing<String>,
    server_random: Option<[u8; 32]>,
    handshake_mac: Option<Sha1Hmac>,
    xor_key: Option<[u8; 32]>,
    authorized: bool,
    tls13: bool,
}

impl HandshakeRelay {
    fn new(carrier: BoxedTransportStream, password: Zeroizing<String>) -> Self {
        Self {
            records: RecordReader::new(carrier),
            pending_text: BytesMut::new(),
            password,
            server_random: None,
            handshake_mac: None,
            xor_key: None,
            authorized: false,
            tls13: false,
        }
    }

    fn finish(self) -> (BoxedTransportStream, [u8; 32], Option<Sha1Hmac>, bool) {
        if self.records.buffered.is_empty() {
            return (
                self.records.inner,
                self.server_random.unwrap_or([0; 32]),
                self.handshake_mac,
                self.authorized && self.server_random.is_some(),
            );
        }
        (
            Box::new(RawBufferedStream {
                inner: self.records.inner,
                buffered: self.records.buffered,
            }),
            self.server_random.unwrap_or([0; 32]),
            self.handshake_mac,
            self.authorized && self.server_random.is_some(),
        )
    }

    fn protocol_error(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    fn unwrap_record(&mut self, mut record: Vec<u8>) -> io::Result<Vec<u8>> {
        if record.is_empty() {
            return Err(Self::protocol_error("empty TLS record"));
        }
        if record[0] == HANDSHAKE {
            if self.handshake_mac.is_none() {
                if let Some(random) = server_random(&record) {
                    let mut mac = <Sha1Hmac as Mac>::new_from_slice(self.password.as_bytes())
                        .expect("HMAC-SHA1 accepts every key length");
                    mac.update(&random);
                    self.xor_key = Some(xor_wrap_key(self.password.as_bytes(), &random));
                    self.handshake_mac = Some(mac);
                    self.tls13 = hello_supports_tls13(&record);
                    self.authorized = !self.tls13;
                    self.server_random = Some(random);
                }
            }
            return Ok(record);
        }
        if record[0] != APPLICATION_DATA || record.len() < TLS_HMAC_HEADER_LEN {
            return Ok(record);
        }
        self.authorized = false;
        let Some(mac) = &mut self.handshake_mac else {
            return Err(Self::protocol_error("application data before ServerHello"));
        };
        mac.update(&record[TLS_HMAC_HEADER_LEN..]);
        let expected = mac.clone().finalize().into_bytes();
        if !hmac_equal(&record[TLS_HEADER_LEN..TLS_HMAC_HEADER_LEN], &expected[..HMAC_LEN]) {
            return Err(Self::protocol_error("ShadowTLS handshake HMAC mismatch"));
        }
        xor_wrap(
            &mut record[TLS_HMAC_HEADER_LEN..],
            self.xor_key.as_ref().expect("HMAC starts at ServerHello"),
        );
        self.authorized = true;
        record.drain(TLS_HEADER_LEN..TLS_HMAC_HEADER_LEN);
        let length = record.len() - TLS_HEADER_LEN;
        record[3..5].copy_from_slice(&(length as u16).to_be_bytes());
        Ok(record)
    }
}

impl AsyncRead for HandshakeRelay {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.pending_text.is_empty() {
                let count = this.pending_text.len().min(output.remaining());
                output.put_slice(&this.pending_text[..count]);
                this.pending_text.advance(count);
                return Poll::Ready(Ok(()));
            }
            let record = match this.records.poll_record(cx) {
                Poll::Ready(Ok(Some(record))) => record,
                Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            };
            match this.unwrap_record(record) {
                Ok(record) => this.pending_text = BytesMut::from(record.as_slice()),
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }
}

impl AsyncWrite for HandshakeRelay {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().records.inner).poll_write(cx, input)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().records.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().records.inner).poll_shutdown(cx)
    }
}

struct ShadowTlsStream<S> {
    records: RecordReader<S>,
    write_mac: FrameMac,
    read_mac: FrameMac,
    /// Keeps the handshake HMAC chain after the switch only for the first
    /// application record. This is sing-shadowtls' `hmacIgnore`.
    handshake_read_mac: Option<Sha1Hmac>,
    input: BytesMut,
    output: Vec<u8>,
    output_pos: usize,
}

impl<S> ShadowTlsStream<S> where S: AsyncRead + AsyncWrite + Unpin {
    fn new(carrier: S, password: Zeroizing<String>, server_random: [u8; 32]) -> Self {
        let write_mac = FrameMac::new(password.as_bytes(), &server_random, b'C');
        let read_mac = FrameMac::new(password.as_bytes(), &server_random, b'S');
        Self {
            records: RecordReader::new(carrier),
            write_mac,
            read_mac,
            handshake_read_mac: None,
            input: BytesMut::new(),
            output: Vec::new(),
            output_pos: 0,
        }
    }

    fn protocol_error(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    fn poll_flush_output(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.output_pos < self.output.len() {
            match Pin::new(&mut self.records.inner)
                .poll_write(cx, &self.output[self.output_pos..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "ShadowTLS carrier closed while writing",
                    )))
                }
                Poll::Ready(Ok(written)) => self.output_pos += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.output.clear();
        self.output_pos = 0;
        Poll::Ready(Ok(()))
    }

    fn open_record(&mut self, record: &[u8]) -> io::Result<Vec<u8>> {
        if let Some(mac) = self.handshake_read_mac.take() {
            if is_handshake_dummy(record, &mac) {
                self.handshake_read_mac = Some(mac);
                return Ok(Vec::new());
            }
            // The first application frame can replace the dummy and use the
            // handshake HMAC directly before switching to the S chain.
            if record.len() > TLS_HMAC_HEADER_LEN && record[..3] == [APPLICATION_DATA, 3, 3] {
                let mut next = mac;
                next.update(&record[TLS_HMAC_HEADER_LEN..]);
                let expected = next.clone().finalize().into_bytes();
                if hmac_equal(
                    &record[TLS_HEADER_LEN..TLS_HMAC_HEADER_LEN],
                    &expected[..HMAC_LEN],
                ) {
                    next.update(&record[TLS_HEADER_LEN..TLS_HMAC_HEADER_LEN]);
                    self.read_mac = FrameMac { inner: next };
                    return Ok(record[TLS_HMAC_HEADER_LEN..].to_vec());
                }
            }
        }
        match record[0] {
            ALERT => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "ShadowTLS peer alert")),
            APPLICATION_DATA
                if record.len() >= TLS_HMAC_HEADER_LEN && record[1..3] == [3, 3] =>
            {
                if self.read_mac.open(
                    &record[TLS_HMAC_HEADER_LEN..],
                    &record[TLS_HEADER_LEN..TLS_HMAC_HEADER_LEN],
                ) {
                    Ok(record[TLS_HMAC_HEADER_LEN..].to_vec())
                } else {
                    Err(Self::protocol_error("ShadowTLS application-data HMAC mismatch"))
                }
            }
            _ => Err(Self::protocol_error("unexpected ShadowTLS record")),
        }
    }
}

impl<S> AsyncRead for ShadowTlsStream<S> where S: AsyncRead + AsyncWrite + Unpin {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_flush_output(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => {}
        }
        loop {
            if !this.input.is_empty() {
                let count = this.input.len().min(output.remaining());
                output.put_slice(&this.input[..count]);
                this.input.advance(count);
                return Poll::Ready(Ok(()));
            }
            match this.records.poll_record(cx) {
                Poll::Ready(Ok(Some(record))) => match this.open_record(&record) {
                    Ok(payload) => this.input = BytesMut::from(payload.as_slice()),
                    Err(error) => return Poll::Ready(Err(error)),
                },
                Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for ShadowTlsStream<S> where S: AsyncRead + AsyncWrite + Unpin {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.poll_flush_output(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let count = input.len().min(MAX_PLAINTEXT_RECORD);
        let payload = &input[..count];
        let tag = this.write_mac.seal(payload);
        let mut record = Vec::with_capacity(TLS_HMAC_HEADER_LEN + count);
        record.extend_from_slice(&[APPLICATION_DATA, 3, 3]);
        record.extend_from_slice(&((count + HMAC_LEN) as u16).to_be_bytes());
        record.extend_from_slice(&tag);
        record.extend_from_slice(payload);
        this.output = record;
        this.output_pos = 0;
        match this.poll_flush_output(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            _ => Poll::Ready(Ok(count)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_flush_output(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.records.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_flush_output(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.records.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

impl TransportStream for ShadowTlsStream<BoxedTransportStream> {
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

#[cfg(test)]
mod tests;
