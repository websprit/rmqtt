use tokio::io::{AsyncRead, AsyncWrite};

use anyhow::anyhow;
use futures::StreamExt;
use rmqtt_codec::MqttPacket;

use crate::{MqttStream, Result};

/// Opaque identifier for one logical MQTT flow within a connection.
///
/// Identifiers are scoped to a link generation; use [`ReplyPath`] when retaining
/// a destination across asynchronous work.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct FlowId(u64);

impl FlowId {
    /// Identifier reserved for the connection's MQTT control flow.
    pub const CONTROL: Self = Self(0);

    /// Creates a flow identifier from its connection-local numeric value.
    #[inline]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the connection-local numeric value.
    #[inline]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Stable reply destination for the flow that originated an MQTT packet.
///
/// The generation prevents a path from being reused after its underlying flow
/// has been replaced.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ReplyPath {
    flow_id: FlowId,
    flow_kind: FlowKind,
    generation: u64,
}

impl ReplyPath {
    /// Generation-independent control path used by serial links.
    pub const CONTROL: Self = Self { flow_id: FlowId::CONTROL, flow_kind: FlowKind::Control, generation: 0 };

    /// Creates a reply path for a flow in a specific link generation.
    #[inline]
    pub const fn new(flow_id: FlowId, flow_kind: FlowKind, generation: u64) -> Self {
        Self { flow_id, flow_kind, generation }
    }

    /// Returns the generation-independent control path used by serial links.
    #[inline]
    pub const fn control() -> Self {
        Self::CONTROL
    }

    /// Returns the destination flow identifier.
    #[inline]
    pub const fn flow_id(self) -> FlowId {
        self.flow_id
    }

    /// Returns whether the destination is the control flow or a data flow.
    #[inline]
    pub const fn flow_kind(self) -> FlowKind {
        self.flow_kind
    }

    /// Returns the link generation in which this path was issued.
    #[inline]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Role of a logical MQTT flow within a transport connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FlowKind {
    /// The single flow carrying CONNECT, CONNACK, and connection-wide control traffic.
    Control,
    /// An auxiliary flow carrying allowed MQTT application packets.
    Data,
}

/// Event produced by a transport-neutral MQTT link.
#[derive(Debug)]
pub enum LinkEvent {
    /// A decoded MQTT packet and the path on which its response must be sent.
    Packet {
        /// Decoded MQTT packet.
        packet: MqttPacket,
        /// Generation-scoped path on which replies must be sent.
        reply_path: ReplyPath,
    },
    /// One logical flow ended while the connection may remain usable.
    FlowClosed {
        /// Identifier of the flow that ended.
        flow_id: FlowId,
        /// Cause of the flow closure.
        reason: FlowCloseReason,
    },
    /// The entire transport connection ended.
    ConnectionClosed {
        /// Cause of the connection closure.
        reason: ConnectionCloseReason,
    },
}

/// Destination policy for an outbound MQTT packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SendTarget {
    /// Send on the connection's MQTT control flow.
    Control,
    /// Reply on the exact path supplied with an inbound packet.
    Reply(
        /// Generation-scoped path to the originating flow.
        ReplyPath,
    ),
    /// Send on the currently active generation of a flow identifier.
    Bound(
        /// Identifier of the flow to resolve at send time.
        FlowId,
    ),
}

/// Confirmed path used for an outbound MQTT packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendReceipt {
    path: ReplyPath,
}

impl SendReceipt {
    /// Creates a receipt for a successfully selected reply path.
    #[inline]
    pub const fn new(path: ReplyPath) -> Self {
        Self { path }
    }

    /// Returns the path used by the send operation.
    #[inline]
    pub const fn path(self) -> ReplyPath {
        self.path
    }
}

/// Reason that one logical MQTT flow was closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowCloseReason {
    /// The peer cleanly finished its receive direction.
    RecvFinished,
    /// The peer reset its send direction with the given application error code.
    RecvReset(
        /// Peer-provided QUIC application error code.
        u64,
    ),
    /// The peer requested that the local endpoint stop sending, with the given error code.
    SendStopped(
        /// Peer-provided QUIC application error code.
        u64,
    ),
    /// Writing to the flow failed without a more specific transport classification.
    SendFailed,
    /// The flow exceeded its configured idle timeout.
    IdleTimeout,
    /// The flow contained malformed MQTT framing or packet data.
    CodecMalformed,
    /// The flow exceeded a configured resource limit.
    ResourceLimit,
    /// The underlying transport connection was lost.
    ConnectionLost,
    /// The flow violated MQTT-over-transport rules.
    ProtocolViolation,
}

/// Reason that an entire MQTT transport connection was closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionCloseReason {
    /// The mandatory MQTT control flow ended.
    ControlFlowClosed,
    /// A packet or flow violated connection-level protocol rules.
    ProtocolViolation,
    /// A flow carrying stateful MQTT work failed and could not be isolated safely.
    StatefulFlowFailure,
    /// The MQTT keep-alive deadline expired.
    KeepAliveTimeout,
    /// The connection exceeded a configured resource limit.
    ResourceLimit,
    /// The local broker intentionally shut down the link.
    LocalShutdown,
    /// The underlying transport connection was lost.
    TransportLost,
}

/// Transport-neutral asynchronous I/O for MQTT packets and logical flows.
#[allow(async_fn_in_trait)]
pub trait MqttLink {
    /// Receives the next packet or lifecycle event, or `None` after the link terminates.
    async fn recv(&mut self) -> Result<Option<LinkEvent>>;

    /// Sends one MQTT packet to `target` and returns the concrete path used.
    async fn send(&mut self, target: SendTarget, packet: MqttPacket) -> Result<SendReceipt>;

    /// Flushes pending writes according to the link's ordering guarantees.
    async fn flush(&mut self) -> Result<()>;

    /// Resets one logical flow for `reason`.
    async fn reset_flow(&mut self, flow_id: FlowId, reason: FlowCloseReason) -> Result<()>;

    /// Closes the entire transport connection for `reason`.
    async fn close_connection(&mut self, reason: ConnectionCloseReason) -> Result<()>;

    /// Closes the link as a local shutdown.
    async fn close(&mut self) -> Result<()> {
        self.close_connection(ConnectionCloseReason::LocalShutdown).await
    }
}

/// [`MqttLink`] adapter for transports that carry MQTT on one ordered byte stream.
pub struct SerialMqttLink<Io> {
    stream: MqttStream<Io>,
}

impl<Io> SerialMqttLink<Io> {
    /// Wraps a version-detected MQTT stream as a serial link.
    #[inline]
    pub fn new(stream: MqttStream<Io>) -> Self {
        Self { stream }
    }

    /// Returns the wrapped MQTT stream.
    #[inline]
    pub fn into_inner(self) -> MqttStream<Io> {
        self.stream
    }
}

impl<Io> MqttLink for SerialMqttLink<Io>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    async fn recv(&mut self) -> Result<Option<LinkEvent>> {
        match &mut self.stream {
            MqttStream::V3(stream) => match stream.next().await {
                Some(Ok(packet)) => Ok(Some(LinkEvent::Packet {
                    packet: MqttPacket::V3(packet),
                    reply_path: ReplyPath::control(),
                })),
                Some(Err(error)) => Err(error),
                None => Ok(None),
            },
            MqttStream::V5(stream) => match stream.next().await {
                Some(Ok(packet)) => Ok(Some(LinkEvent::Packet {
                    packet: MqttPacket::V5(packet),
                    reply_path: ReplyPath::control(),
                })),
                Some(Err(error)) => Err(error),
                None => Ok(None),
            },
        }
    }

    async fn send(&mut self, target: SendTarget, packet: MqttPacket) -> Result<SendReceipt> {
        if !is_serial_target(target) {
            return Err(anyhow!("serial MQTT link only supports the control flow"));
        }

        match (&mut self.stream, packet) {
            (MqttStream::V3(stream), MqttPacket::V3(packet)) => stream.send(packet).await,
            (MqttStream::V5(stream), MqttPacket::V5(packet)) => stream.send(packet).await,
            _ => Err(anyhow!("MQTT packet version does not match stream version")),
        }?;
        Ok(SendReceipt::new(ReplyPath::control()))
    }

    async fn flush(&mut self) -> Result<()> {
        match &mut self.stream {
            MqttStream::V3(stream) => stream.flush().await,
            MqttStream::V5(stream) => stream.flush().await,
        }
    }

    async fn reset_flow(&mut self, flow_id: FlowId, _reason: FlowCloseReason) -> Result<()> {
        if flow_id != FlowId::CONTROL {
            return Err(anyhow!("serial MQTT link has no data flow to reset"));
        }
        self.close_connection(ConnectionCloseReason::ControlFlowClosed).await
    }

    async fn close_connection(&mut self, _reason: ConnectionCloseReason) -> Result<()> {
        match &mut self.stream {
            MqttStream::V3(stream) => stream.close().await,
            MqttStream::V5(stream) => stream.close().await,
        }
    }
}

#[inline]
fn is_serial_target(target: SendTarget) -> bool {
    match target {
        SendTarget::Control => true,
        SendTarget::Reply(reply_path) => reply_path == ReplyPath::CONTROL,
        SendTarget::Bound(flow_id) => flow_id == FlowId::CONTROL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_flow_id_is_opaque_zero() {
        assert_eq!(FlowId::CONTROL.get(), 0);
        assert_eq!(FlowId::new(7).get(), 7);
        assert_eq!(ReplyPath::control().flow_id(), FlowId::CONTROL);
        assert_eq!(ReplyPath::control().flow_kind(), FlowKind::Control);
    }
}
