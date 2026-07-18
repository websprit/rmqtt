//! QUIC bidirectional stream adapter for MQTT over QUIC transport.
//!
//! Wraps Quinn's separate [`SendStream`] and [`RecvStream`] into a single [`QuinnBiStream`]
//! that implements [`AsyncRead`] and [`AsyncWrite`], allowing it to be used as a uniform
//! I/O transport for MQTT connections.

use anyhow::anyhow;
use quinn::{
    Connecting, Connection, Incoming, ReadError, RecvStream, SendStream, VarInt, WriteError, ZeroRttAccepted,
};
use std::{
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::Instant;

use crate::quic_link::QuicMultiStreamLink;
use crate::stream::Dispatcher;
use crate::{Builder, MqttStream, Result as MqttResult};

const QUIC_HANDSHAKE_FAILURE_CODE: u32 = 0x4d51_5448;

/// A lightweight incoming QUIC connection which has not yet accepted its MQTT control stream.
pub struct QuicIncoming {
    connecting: Connecting,
    cfg: Arc<Builder>,
    handshake_permit: OwnedSemaphorePermit,
}

impl QuicIncoming {
    pub(crate) fn new(
        incoming: Incoming,
        cfg: Arc<Builder>,
        handshake_permit: OwnedSemaphorePermit,
    ) -> MqttResult<Self> {
        Ok(Self { connecting: incoming.accept()?, cfg, handshake_permit })
    }

    /// Accepts and verifies the first server-visible MQTT control stream.
    pub async fn accept_control(self) -> MqttResult<AcceptedQuicControl> {
        let QuicIncoming { connecting, cfg, handshake_permit } = self;
        let deadline = Instant::now() + cfg.handshake_timeout;
        let (connection, completion) = if cfg.enable_quic_0rtt {
            let (connection, completion) = connecting
                .into_0rtt()
                .map_err(|_| anyhow!("Failed to enable early stream processing for QUIC connection"))?;
            (connection, Some(completion))
        } else {
            let connection = tokio::time::timeout_at(deadline, connecting)
                .await
                .map_err(|_| anyhow!("Timed out establishing QUIC connection"))??;
            (connection, None)
        };

        let remote_addr = connection.remote_address();
        let accepted_stream = tokio::time::timeout_at(deadline, connection.accept_bi()).await;
        let (send, recv) = match accepted_stream {
            Ok(result) => result?,
            Err(_) => {
                connection.close(VarInt::from_u32(QUIC_HANDSHAKE_FAILURE_CODE), b"mqtt-control-timeout");
                return Err(anyhow!("Timed out waiting for MQTT control stream"));
            }
        };
        let is_0rtt = recv.is_0rtt();

        if let Some(completion) = completion {
            if let Err(error) = await_verified_finished(&connection, completion, deadline).await {
                connection.close(
                    VarInt::from_u32(QUIC_HANDSHAKE_FAILURE_CODE),
                    b"tls-finished-verification-failed",
                );
                return Err(error);
            }
        }
        drop(handshake_permit);

        Ok(AcceptedQuicControl {
            socket: QuinnBiStream::new(send, recv),
            activation: QuicActivation { connection },
            meta: QuicIngressMeta { is_0rtt, remote_addr },
            cfg,
        })
    }
}

async fn await_verified_finished(
    connection: &Connection,
    completion: ZeroRttAccepted,
    deadline: Instant,
) -> MqttResult<()> {
    // On incoming/server connections Quinn documents the boolean value as meaningless.
    // Awaiting the future is the completion barrier; the connection state below is the verdict.
    let _ = tokio::time::timeout_at(deadline, completion)
        .await
        .map_err(|_| anyhow!("Timed out waiting for authenticated QUIC Finished"))?;
    if connection.handshake_data().is_none() {
        return Err(anyhow!("QUIC handshake data is unavailable"));
    }
    if let Some(reason) = connection.close_reason() {
        return Err(anyhow!("QUIC handshake did not establish a usable connection: {reason}"));
    }
    Ok(())
}

/// Metadata collected while accepting the MQTT control stream.
#[derive(Clone, Copy, Debug)]
pub struct QuicIngressMeta {
    /// Whether the accepted control stream carried QUIC 0-RTT data.
    ///
    /// The server exposes this only after the TLS Finished barrier has completed.
    pub is_0rtt: bool,
    /// Address of the remote QUIC endpoint.
    pub remote_addr: SocketAddr,
}

/// A verified MQTT control stream which has not yet completed MQTT CONNECT/CONNACK.
pub struct AcceptedQuicControl {
    socket: QuinnBiStream,
    activation: QuicActivation,
    meta: QuicIngressMeta,
    cfg: Arc<Builder>,
}

impl AcceptedQuicControl {
    /// Detects the MQTT protocol version while retaining the QUIC connection activation handle.
    pub async fn mqtt(self) -> MqttResult<AcceptedQuicMqtt> {
        let stream = Dispatcher::new(self.socket, self.meta.remote_addr, None, self.cfg).mqtt().await?;
        Ok(AcceptedQuicMqtt { stream, activation: self.activation, meta: self.meta })
    }

    /// Returns metadata captured while accepting the control stream.
    pub fn meta(&self) -> QuicIngressMeta {
        self.meta
    }

    pub(crate) fn into_legacy_parts(self) -> (QuinnBiStream, QuicIngressMeta, Arc<Builder>) {
        (self.socket, self.meta, self.cfg)
    }
}

/// A verified, version-detected MQTT control stream and its post-CONNACK activation handle.
pub struct AcceptedQuicMqtt {
    stream: MqttStream<QuinnBiStream>,
    activation: QuicActivation,
    meta: QuicIngressMeta,
}

impl AcceptedQuicMqtt {
    /// Separates the MQTT control stream, post-CONNACK activation handle, and ingress metadata.
    pub fn into_parts(self) -> (MqttStream<QuinnBiStream>, QuicActivation, QuicIngressMeta) {
        (self.stream, self.activation, self.meta)
    }
}

/// Owns connection-level QUIC state that may only be activated after MQTT CONNACK commits.
pub struct QuicActivation {
    pub(crate) connection: Connection,
}

impl QuicActivation {
    /// Sends and flushes an MQTT 3 CONNACK before minting the activation token.
    pub async fn send_v3_connack_and_commit(
        self,
        control: &mut crate::v3::MqttStream<QuinnBiStream>,
        return_code: rmqtt_codec::v3::ConnectAckReason,
        session_present: bool,
    ) -> MqttResult<ConnackCommitted> {
        control.send_connect_ack(return_code, session_present).await?;
        control.flush().await?;
        Ok(ConnackCommitted { activation: self })
    }

    /// Sends and flushes an MQTT 5 CONNACK before minting the activation token.
    pub async fn send_v5_connack_and_commit(
        self,
        control: &mut crate::v5::MqttStream<QuinnBiStream>,
        ack: rmqtt_codec::v5::ConnectAck,
    ) -> MqttResult<ConnackCommitted> {
        control.send_connect_ack(ack).await?;
        control.flush().await?;
        Ok(ConnackCommitted { activation: self })
    }
}

/// Proof that the successful MQTT CONNACK was submitted and flushed on the Control Flow.
pub struct ConnackCommitted {
    activation: QuicActivation,
}

impl ConnackCommitted {
    /// Activates the flow supervisor, then raises remote bidi stream credit to `1 + max_data_streams`.
    pub fn activate_multistream(
        self,
        control: MqttStream<QuinnBiStream>,
        max_data_streams: u32,
    ) -> QuicMultiStreamLink {
        QuicMultiStreamLink::new(self.activation, control, max_data_streams)
    }
}

/// Bidirectional QUIC stream wrapping separate send/recv streams into a unified I/O type.
///
/// Combines Quinn's [`SendStream`] and [`RecvStream`] into a single struct that
/// implements [`AsyncRead`] and [`AsyncWrite`], enabling use as a transport for MQTT.
#[allow(dead_code)]
pub struct QuinnBiStream {
    send: SendStream,
    recv: RecvStream,
    is_0rtt: bool,
    last_read_error: Option<ReadError>,
    last_write_error: Option<WriteError>,
}

impl QuinnBiStream {
    /// Creates a bidirectional adapter from Quinn send and receive stream halves.
    #[allow(dead_code)]
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        let is_0rtt = recv.is_0rtt();
        Self { send, recv, is_0rtt, last_read_error: None, last_write_error: None }
    }

    /// Returns whether this stream was opened using QUIC 0-RTT data.
    pub fn is_0rtt(&self) -> bool {
        self.is_0rtt
    }

    /// Aborts both stream directions with an application error code.
    pub fn abort(&mut self, application_code: u32) -> MqttResult<()> {
        let code = VarInt::from_u32(application_code);
        self.send.reset(code)?;
        self.recv.stop(code)?;
        Ok(())
    }

    /// Asks the peer to stop sending on this stream direction.
    pub fn stop_receiving(&mut self, application_code: u32) -> MqttResult<()> {
        self.recv.stop(VarInt::from_u32(application_code))?;
        Ok(())
    }

    pub(crate) fn take_read_error(&mut self) -> Option<ReadError> {
        self.last_read_error.take()
    }

    pub(crate) fn take_write_error(&mut self) -> Option<WriteError> {
        self.last_write_error.take()
    }

    fn remember_write_error(&mut self, error: &WriteError) {
        self.last_write_error = Some(error.clone());
    }

    fn remember_io_write_error(&mut self, error: &std::io::Error) {
        self.last_write_error =
            error.get_ref().and_then(|source| source.downcast_ref::<WriteError>()).cloned();
    }
}

impl AsyncRead for QuinnBiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        match Pin::new(&mut this.recv).poll_read_buf(cx, buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => {
                this.last_read_error = Some(error.clone());
                Poll::Ready(Err(std::io::Error::other(error)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for QuinnBiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.as_mut().get_mut();
        match Pin::new(&mut this.send).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => Poll::Ready(Ok(written)),
            Poll::Ready(Err(error)) => {
                this.remember_write_error(&error);
                Poll::Ready(Err(error.into()))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let this = self.as_mut().get_mut();
        match Pin::new(&mut this.send).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => {
                this.remember_io_write_error(&error);
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let this = self.as_mut().get_mut();
        match Pin::new(&mut this.send).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => {
                this.remember_io_write_error(&error);
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Unpin for QuinnBiStream {}
