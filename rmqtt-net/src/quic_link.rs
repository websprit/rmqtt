use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use futures::StreamExt;
use quinn::{Connection, ReadError, VarInt, WriteError};
use rmqtt_codec::{MqttCodec, MqttPacket};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::codec::Framed;

use crate::link::{
    ConnectionCloseReason, FlowCloseReason, FlowId, FlowKind, LinkEvent, MqttLink, ReplyPath, SendReceipt,
    SendTarget,
};
use crate::quic::{QuicActivation, QuinnBiStream};
use crate::{Builder, MqttStream, Result};

const DEFAULT_FLOW_COMMANDS: usize = 16;
const QUIC_APP_ERROR_PROTOCOL: u32 = 0x4d51_5450;
const QUIC_APP_ERROR_SHUTDOWN: u32 = 0x4d51_5400;

/// Activated MQTT-over-QUIC link that supervises one control stream and bounded data flows.
///
/// Construction is crate-private so callers can obtain this type only through
/// [`crate::ConnackCommitted::activate_multistream`] after MQTT CONNACK has committed.
pub struct QuicMultiStreamLink {
    connection: Connection,
    generation: u64,
    control_tx: mpsc::Sender<FlowCommand>,
    control_events: mpsc::Receiver<QueuedLinkEvent>,
    data_events: mpsc::Receiver<QueuedLinkEvent>,
    supervisor_events: mpsc::Receiver<SupervisorEvent>,
    supervisor_handle: JoinHandle<()>,
    flows: HashMap<FlowId, FlowHandle>,
    buffer_budget: Arc<ConnectionBufferBudget>,
    control_closed: bool,
    closed: bool,
}

impl QuicMultiStreamLink {
    pub(crate) fn new(
        activation: QuicActivation,
        control: MqttStream<QuinnBiStream>,
        max_data_streams: u32,
    ) -> Self {
        let connection = activation.connection;
        let generation = connection.stable_id() as u64;
        let cfg = mqtt_stream_cfg(&control);
        let max_data_streams = max_data_streams.min(cfg.multistream_max_data_streams).min(u32::MAX - 1);
        let version = stream_version(&control);
        let remote_addr = mqtt_stream_remote_addr(&control);
        let mailbox_packets = cfg.multistream_connection_mailbox_packets.max(1);
        let buffer_budget =
            Arc::new(ConnectionBufferBudget::new(cfg.multistream_connection_buffer_bytes.max(1)));
        let (control_event_tx, control_events) = mpsc::channel(mailbox_packets);
        let (data_event_tx, data_events) = mpsc::channel(mailbox_packets);
        let (supervisor_tx, supervisor_events) = mpsc::channel(mailbox_packets);
        let (control_tx, control_rx) = mpsc::channel(DEFAULT_FLOW_COMMANDS);

        tokio::spawn(run_flow(
            FlowContext::control(generation),
            control,
            control_rx,
            control_event_tx,
            buffer_budget.clone(),
            Duration::ZERO,
        ));

        let supervisor_handle = tokio::spawn(run_supervisor(SupervisorContext {
            connection: connection.clone(),
            cfg: cfg.clone(),
            generation,
            version,
            remote_addr,
            max_data_streams,
            data_event_tx,
            buffer_budget: buffer_budget.clone(),
            supervisor_tx,
        }));

        // The supervisor and its phase guard exist before the peer can observe new stream credit.
        connection.set_receive_window(VarInt::from_u32(
            cfg.multistream_connection_buffer_bytes.clamp(1, u32::MAX as usize) as u32,
        ));
        connection.set_max_concurrent_bi_streams(VarInt::from_u32(1 + max_data_streams));

        Self {
            connection,
            generation,
            control_tx,
            control_events,
            data_events,
            supervisor_events,
            supervisor_handle,
            flows: HashMap::new(),
            buffer_budget,
            control_closed: false,
            closed: false,
        }
    }

    fn resolve_send_target(&self, target: SendTarget) -> Result<ResolvedTarget> {
        match target {
            SendTarget::Control => Ok(ResolvedTarget {
                flow_id: FlowId::CONTROL,
                path: ReplyPath::new(FlowId::CONTROL, FlowKind::Control, self.generation),
            }),
            SendTarget::Bound(flow_id) => {
                if flow_id == FlowId::CONTROL {
                    return Ok(ResolvedTarget {
                        flow_id,
                        path: ReplyPath::new(flow_id, FlowKind::Control, self.generation),
                    });
                }
                if !self.flows.contains_key(&flow_id) {
                    return Err(anyhow!("QUIC data flow {} is not active", flow_id.get()));
                }
                Ok(ResolvedTarget { flow_id, path: ReplyPath::new(flow_id, FlowKind::Data, self.generation) })
            }
            SendTarget::Reply(path) => {
                if path.generation() != self.generation {
                    return Err(anyhow!("stale QUIC reply path generation"));
                }
                match path.flow_kind() {
                    FlowKind::Control if path.flow_id() == FlowId::CONTROL => {
                        Ok(ResolvedTarget { flow_id: FlowId::CONTROL, path })
                    }
                    FlowKind::Data if self.flows.contains_key(&path.flow_id()) => {
                        Ok(ResolvedTarget { flow_id: path.flow_id(), path })
                    }
                    FlowKind::Control => Err(anyhow!("invalid QUIC control reply path")),
                    FlowKind::Data => Err(anyhow!("QUIC data flow {} is not active", path.flow_id().get())),
                }
            }
        }
    }

    async fn dispatch_command(
        &mut self,
        target: ResolvedTarget,
        request: FlowCommandKind,
    ) -> Result<SendReceipt> {
        let sender = if target.flow_id == FlowId::CONTROL {
            &self.control_tx
        } else {
            &self
                .flows
                .get(&target.flow_id)
                .ok_or_else(|| anyhow!("QUIC data flow {} is not active", target.flow_id.get()))?
                .commands
        };

        let (completion_tx, completion_rx) = oneshot::channel();
        sender
            .send(FlowCommand { request, completion: completion_tx })
            .await
            .map_err(|_| anyhow!("QUIC flow {} command mailbox is closed", target.flow_id.get()))?;
        completion_rx
            .await
            .map_err(|_| anyhow!("QUIC flow {} command completion was dropped", target.flow_id.get()))??;
        Ok(SendReceipt::new(target.path))
    }

    fn absorb_supervisor_event(&mut self, event: SupervisorEvent) -> Option<LinkEvent> {
        match event {
            SupervisorEvent::FlowOpened { flow_id, commands, handle } => {
                self.flows.insert(flow_id, FlowHandle { commands, handle });
                None
            }
            SupervisorEvent::ConnectionClosed { reason } => {
                self.closed = true;
                self.close_quic(reason.clone());
                Some(LinkEvent::ConnectionClosed { reason })
            }
        }
    }

    fn absorb_link_event(&mut self, event: LinkEvent) -> LinkEvent {
        match &event {
            LinkEvent::FlowClosed { flow_id, .. } => {
                if *flow_id == FlowId::CONTROL {
                    self.control_closed = true;
                    self.closed = true;
                } else {
                    self.flows.remove(flow_id);
                }
            }
            LinkEvent::ConnectionClosed { reason } => {
                self.closed = true;
                self.close_quic(reason.clone());
            }
            LinkEvent::Packet { .. } => {}
        }
        event
    }

    fn absorb_queued_link_event(&mut self, queued: QueuedLinkEvent) -> LinkEvent {
        self.buffer_budget.release(queued.buffered_bytes);
        self.absorb_link_event(queued.event)
    }

    fn close_quic(&self, reason: ConnectionCloseReason) {
        let code = match reason {
            ConnectionCloseReason::ProtocolViolation => QUIC_APP_ERROR_PROTOCOL,
            _ => QUIC_APP_ERROR_SHUTDOWN,
        };
        self.connection.close(VarInt::from_u32(code), reason_label(&reason).as_bytes());
    }
}

#[allow(async_fn_in_trait)]
impl MqttLink for QuicMultiStreamLink {
    async fn recv(&mut self) -> Result<Option<LinkEvent>> {
        loop {
            if self.closed
                && self.control_events.is_closed()
                && self.data_events.is_closed()
                && self.supervisor_events.is_closed()
            {
                return Ok(None);
            }

            match self.control_events.try_recv() {
                Ok(event) => return Ok(Some(self.absorb_queued_link_event(event))),
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    if !self.control_closed {
                        self.control_closed = true;
                        self.closed = true;
                        return Ok(Some(LinkEvent::ConnectionClosed {
                            reason: ConnectionCloseReason::ControlFlowClosed,
                        }));
                    }
                }
            }

            tokio::select! {
                biased;

                event = self.control_events.recv() => {
                    return Ok(event.map(|event| self.absorb_queued_link_event(event)))
                },
                event = self.supervisor_events.recv() => {
                    if let Some(event) = event {
                        if let Some(event) = self.absorb_supervisor_event(event) {
                            return Ok(Some(event));
                        }
                    } else if self.closed {
                        return Ok(None);
                    }
                }
                event = self.data_events.recv() => {
                    return Ok(event.map(|event| self.absorb_queued_link_event(event)))
                },
            }
        }
    }

    async fn send(&mut self, target: SendTarget, packet: MqttPacket) -> Result<SendReceipt> {
        let target = self.resolve_send_target(target)?;
        self.dispatch_command(target, FlowCommandKind::Send(packet)).await
    }

    async fn flush(&mut self) -> Result<()> {
        let control = ResolvedTarget {
            flow_id: FlowId::CONTROL,
            path: ReplyPath::new(FlowId::CONTROL, FlowKind::Control, self.generation),
        };
        self.dispatch_command(control, FlowCommandKind::Flush).await?;
        for flow_id in self.flows.keys().copied().collect::<Vec<_>>() {
            if let Ok(target) = self.resolve_send_target(SendTarget::Bound(flow_id)) {
                let _ = self.dispatch_command(target, FlowCommandKind::Flush).await?;
            }
        }
        Ok(())
    }

    async fn reset_flow(&mut self, flow_id: FlowId, reason: FlowCloseReason) -> Result<()> {
        if flow_id == FlowId::CONTROL {
            self.close_connection(ConnectionCloseReason::ControlFlowClosed).await?;
            return Ok(());
        }

        let Some(flow) = self.flows.remove(&flow_id) else {
            return Err(anyhow!("QUIC data flow {} is not active", flow_id.get()));
        };
        let (completion_tx, completion_rx) = oneshot::channel();
        flow.commands
            .send(FlowCommand { request: FlowCommandKind::Close(reason), completion: completion_tx })
            .await
            .map_err(|_| anyhow!("QUIC data flow {} command mailbox is closed", flow_id.get()))?;
        completion_rx
            .await
            .map_err(|_| anyhow!("QUIC data flow {} close completion was dropped", flow_id.get()))??;
        Ok(())
    }

    async fn close_connection(&mut self, reason: ConnectionCloseReason) -> Result<()> {
        self.closed = true;
        self.close_quic(reason.clone());
        let (control_completion, _) = oneshot::channel();
        let _ = self
            .control_tx
            .send(FlowCommand {
                request: FlowCommandKind::Close(FlowCloseReason::ConnectionLost),
                completion: control_completion,
            })
            .await;
        for (_, flow) in self.flows.drain() {
            let (completion, _) = oneshot::channel();
            let _ = flow
                .commands
                .send(FlowCommand {
                    request: FlowCommandKind::Close(FlowCloseReason::ConnectionLost),
                    completion,
                })
                .await;
        }
        self.supervisor_handle.abort();
        Ok(())
    }
}

impl Drop for QuicMultiStreamLink {
    fn drop(&mut self) {
        self.supervisor_handle.abort();
        self.close_quic(ConnectionCloseReason::LocalShutdown);
        for (_, flow) in self.flows.drain() {
            flow.handle.abort();
        }
    }
}

struct ResolvedTarget {
    flow_id: FlowId,
    path: ReplyPath,
}

struct FlowHandle {
    commands: mpsc::Sender<FlowCommand>,
    handle: JoinHandle<()>,
}

struct FlowCommand {
    request: FlowCommandKind,
    completion: oneshot::Sender<Result<()>>,
}

enum FlowCommandKind {
    Send(MqttPacket),
    Flush,
    Close(FlowCloseReason),
}

enum SupervisorEvent {
    FlowOpened { flow_id: FlowId, commands: mpsc::Sender<FlowCommand>, handle: JoinHandle<()> },
    ConnectionClosed { reason: ConnectionCloseReason },
}

struct QueuedLinkEvent {
    event: LinkEvent,
    buffered_bytes: usize,
}

impl QueuedLinkEvent {
    fn unbuffered(event: LinkEvent) -> Self {
        Self { event, buffered_bytes: 0 }
    }

    fn packet(packet: MqttPacket, reply_path: ReplyPath, buffered_bytes: usize) -> Self {
        Self { event: LinkEvent::Packet { packet, reply_path }, buffered_bytes }
    }
}

struct ConnectionBufferBudget {
    limit: usize,
    used: AtomicUsize,
}

impl ConnectionBufferBudget {
    fn new(limit: usize) -> Self {
        Self { limit, used: AtomicUsize::new(0) }
    }

    fn try_reserve(&self, bytes: usize) -> bool {
        let mut used = self.used.load(Ordering::Relaxed);
        loop {
            let Some(next) = used.checked_add(bytes) else {
                return false;
            };
            if next > self.limit {
                return false;
            }
            match self.used.compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(actual) => used = actual,
            }
        }
    }

    fn release(&self, bytes: usize) {
        if bytes != 0 {
            self.used.fetch_sub(bytes, Ordering::AcqRel);
        }
    }
}

#[derive(Clone, Copy)]
struct FlowContext {
    flow_id: FlowId,
    flow_kind: FlowKind,
    generation: u64,
}

impl FlowContext {
    fn control(generation: u64) -> Self {
        Self { flow_id: FlowId::CONTROL, flow_kind: FlowKind::Control, generation }
    }

    fn data(flow_id: FlowId, generation: u64) -> Self {
        Self { flow_id, flow_kind: FlowKind::Data, generation }
    }

    fn reply_path(self) -> ReplyPath {
        ReplyPath::new(self.flow_id, self.flow_kind, self.generation)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DataPacketAction {
    Emit,
    ResetFlow,
    CloseConnection,
}

struct SupervisorContext {
    connection: Connection,
    cfg: Arc<Builder>,
    generation: u64,
    version: StreamVersion,
    remote_addr: std::net::SocketAddr,
    max_data_streams: u32,
    data_event_tx: mpsc::Sender<QueuedLinkEvent>,
    buffer_budget: Arc<ConnectionBufferBudget>,
    supervisor_tx: mpsc::Sender<SupervisorEvent>,
}

async fn run_supervisor(context: SupervisorContext) {
    let SupervisorContext {
        connection,
        cfg,
        generation,
        version,
        remote_addr,
        max_data_streams,
        data_event_tx,
        buffer_budget,
        supervisor_tx,
    } = context;
    let stream_open_rate = cfg.multistream_stream_open_rate.max(1);
    let idle_timeout = cfg.multistream_stream_idle_timeout;
    let mut next_ordinal = 1_u64;
    let mut rate_window_start = Instant::now();
    let mut opened_in_window = 0_u32;

    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                if max_data_streams == 0 {
                    let _ = supervisor_tx
                        .send(SupervisorEvent::ConnectionClosed {
                            reason: ConnectionCloseReason::ProtocolViolation,
                        })
                        .await;
                    return;
                }
                if rate_window_start.elapsed() >= Duration::from_secs(1) {
                    rate_window_start = Instant::now();
                    opened_in_window = 0;
                }
                if opened_in_window >= stream_open_rate {
                    let _ = supervisor_tx
                        .send(SupervisorEvent::ConnectionClosed {
                            reason: ConnectionCloseReason::ProtocolViolation,
                        })
                        .await;
                    return;
                }
                opened_in_window += 1;
                let flow_id = FlowId::new(next_ordinal);
                next_ordinal = next_ordinal.saturating_add(1);
                let stream = stream_for_version(version, QuinnBiStream::new(send, recv), &cfg, remote_addr);
                let (commands, command_rx) = mpsc::channel(DEFAULT_FLOW_COMMANDS);
                let (start_tx, start_rx) = oneshot::channel();
                let data_event_tx_for_flow = data_event_tx.clone();
                let buffer_budget_for_flow = buffer_budget.clone();
                let handle = tokio::spawn(async move {
                    if start_rx.await.is_err() {
                        return;
                    }
                    run_flow(
                        FlowContext::data(flow_id, generation),
                        stream,
                        command_rx,
                        data_event_tx_for_flow,
                        buffer_budget_for_flow,
                        idle_timeout,
                    )
                    .await;
                });

                if supervisor_tx
                    .send(SupervisorEvent::FlowOpened { flow_id, commands, handle })
                    .await
                    .is_err()
                {
                    return;
                }
                let _ = start_tx.send(());
            }
            Err(_) => {
                let _ = supervisor_tx
                    .send(SupervisorEvent::ConnectionClosed { reason: ConnectionCloseReason::TransportLost })
                    .await;
                return;
            }
        }
    }
}

async fn run_flow(
    context: FlowContext,
    mut stream: MqttStream<QuinnBiStream>,
    mut commands: mpsc::Receiver<FlowCommand>,
    events: mpsc::Sender<QueuedLinkEvent>,
    buffer_budget: Arc<ConnectionBufferBudget>,
    idle_timeout: Duration,
) {
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);

    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else {
                    let _ = close_stream(&mut stream).await;
                    return;
                };
                let result = handle_flow_command(&mut stream, command.request).await;
                match result {
                    Ok(FlowCommandResult::Continue) => {}
                    Ok(FlowCommandResult::Closed(reason)) => {
                        let _ = command.completion.send(Ok(()));
                        emit_flow_closed(&events, context, reason).await;
                        return;
                    }
                    Err(error) => {
                        let write_error = take_stream_write_error(&mut stream);
                        let _ = command.completion.send(Err(error));
                        match write_error {
                            Some(WriteError::Stopped(code)) if context.flow_kind == FlowKind::Data => {
                                emit_flow_closed(
                                    &events,
                                    context,
                                    FlowCloseReason::SendStopped(code.into_inner()),
                                )
                                .await;
                            }
                            Some(WriteError::ConnectionLost(_)) => {
                                emit_connection_closed(&events, ConnectionCloseReason::TransportLost).await;
                            }
                            Some(WriteError::Stopped(_)) | Some(WriteError::ClosedStream)
                                if context.flow_kind == FlowKind::Control =>
                            {
                                emit_connection_closed(&events, ConnectionCloseReason::ControlFlowClosed).await;
                            }
                            Some(WriteError::ZeroRttRejected) => {
                                emit_connection_closed(&events, ConnectionCloseReason::ProtocolViolation).await;
                            }
                            _ if context.flow_kind == FlowKind::Data => {
                                emit_flow_closed(&events, context, FlowCloseReason::SendFailed).await;
                            }
                            _ => {
                                emit_connection_closed(&events, ConnectionCloseReason::ControlFlowClosed).await;
                            }
                        }
                        return;
                    }
                }
                let _ = command.completion.send(Ok(()));
            }
            packet = next_packet(&mut stream) => {
                match packet {
                    Ok(Some((packet, buffered_bytes))) => {
                        idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                        if context.flow_kind == FlowKind::Data {
                            match classify_data_packet(&packet) {
                                DataPacketAction::Emit => {
                                    if !buffer_budget.try_reserve(buffered_bytes) {
                                        emit_flow_closed(&events, context, FlowCloseReason::ResourceLimit).await;
                                        let _ = abort_stream(&mut stream, QUIC_APP_ERROR_PROTOCOL);
                                        return;
                                    }
                                    if events
                                        .send(QueuedLinkEvent::packet(
                                            packet,
                                            context.reply_path(),
                                            buffered_bytes,
                                        ))
                                        .await
                                        .is_err()
                                    {
                                        buffer_budget.release(buffered_bytes);
                                        return;
                                    }
                                }
                                DataPacketAction::ResetFlow => {
                                    emit_flow_closed(&events, context, FlowCloseReason::ProtocolViolation).await;
                                    let _ = abort_stream(&mut stream, QUIC_APP_ERROR_PROTOCOL);
                                    return;
                                }
                                DataPacketAction::CloseConnection => {
                                    let _ = events
                                        .send(QueuedLinkEvent::unbuffered(LinkEvent::ConnectionClosed {
                                            reason: ConnectionCloseReason::ProtocolViolation,
                                        }))
                                        .await;
                                    return;
                                }
                            }
                        } else {
                            if !buffer_budget.try_reserve(buffered_bytes) {
                                let _ = events
                                    .send(QueuedLinkEvent::unbuffered(LinkEvent::ConnectionClosed {
                                        reason: ConnectionCloseReason::ResourceLimit,
                                    }))
                                    .await;
                                return;
                            }
                            if events
                                .send(QueuedLinkEvent::packet(
                                    packet,
                                    context.reply_path(),
                                    buffered_bytes,
                                ))
                                .await
                                .is_err()
                            {
                                buffer_budget.release(buffered_bytes);
                                return;
                            }
                        }
                    }
                    Ok(None) => {
                        let reason = if context.flow_kind == FlowKind::Control {
                            FlowCloseReason::ConnectionLost
                        } else {
                            FlowCloseReason::RecvFinished
                        };
                        emit_flow_closed(&events, context, reason).await;
                        return;
                    }
                    Err(_) => {
                        match take_stream_read_error(&mut stream) {
                            Some(ReadError::Reset(code)) if context.flow_kind == FlowKind::Data => {
                                emit_flow_closed(
                                    &events,
                                    context,
                                    FlowCloseReason::RecvReset(code.into_inner()),
                                )
                                .await;
                            }
                            Some(ReadError::ClosedStream) if context.flow_kind == FlowKind::Data => {
                                emit_flow_closed(&events, context, FlowCloseReason::RecvFinished).await;
                            }
                            Some(ReadError::ConnectionLost(_)) => {
                                emit_connection_closed(&events, ConnectionCloseReason::TransportLost).await;
                            }
                            Some(ReadError::Reset(_)) | Some(ReadError::ClosedStream)
                                if context.flow_kind == FlowKind::Control =>
                            {
                                emit_connection_closed(&events, ConnectionCloseReason::ControlFlowClosed).await;
                            }
                            _ => {
                                emit_connection_closed(&events, ConnectionCloseReason::ProtocolViolation).await;
                            }
                        }
                        return;
                    }
                }
            }
            _ = &mut idle, if !idle_timeout.is_zero() => {
                emit_flow_closed(&events, context, FlowCloseReason::IdleTimeout).await;
                let _ = close_stream(&mut stream).await;
                return;
            }
        }
    }
}

enum FlowCommandResult {
    Continue,
    Closed(FlowCloseReason),
}

async fn handle_flow_command(
    stream: &mut MqttStream<QuinnBiStream>,
    command: FlowCommandKind,
) -> Result<FlowCommandResult> {
    match command {
        FlowCommandKind::Send(packet) => {
            send_packet(stream, packet).await?;
            Ok(FlowCommandResult::Continue)
        }
        FlowCommandKind::Flush => {
            flush_stream(stream).await?;
            Ok(FlowCommandResult::Continue)
        }
        FlowCommandKind::Close(reason) => {
            if matches!(reason, FlowCloseReason::ProtocolViolation | FlowCloseReason::CodecMalformed) {
                let _ = abort_stream(stream, QUIC_APP_ERROR_PROTOCOL);
            } else {
                let _ = close_stream(stream).await;
            }
            Ok(FlowCommandResult::Closed(reason))
        }
    }
}

async fn next_packet(stream: &mut MqttStream<QuinnBiStream>) -> Result<Option<(MqttPacket, usize)>> {
    match stream {
        MqttStream::V3(stream) => match stream.io.next().await {
            Some(Ok((MqttPacket::V3(packet), bytes))) => Ok(Some((MqttPacket::V3(packet), bytes as usize))),
            Some(Ok(_)) => Err(anyhow!("MQTT packet version does not match QUIC stream version")),
            Some(Err(error)) => Err(error.into()),
            None => Ok(None),
        },
        MqttStream::V5(stream) => match stream.io.next().await {
            Some(Ok((MqttPacket::V5(packet), bytes))) => Ok(Some((MqttPacket::V5(packet), bytes as usize))),
            Some(Ok(_)) => Err(anyhow!("MQTT packet version does not match QUIC stream version")),
            Some(Err(error)) => Err(error.into()),
            None => Ok(None),
        },
    }
}

async fn send_packet(stream: &mut MqttStream<QuinnBiStream>, packet: MqttPacket) -> Result<()> {
    match (stream, packet) {
        (MqttStream::V3(stream), MqttPacket::V3(packet)) => stream.send(packet).await,
        (MqttStream::V5(stream), MqttPacket::V5(packet)) => stream.send(packet).await,
        _ => Err(anyhow!("MQTT packet version does not match QUIC stream version")),
    }
}

async fn flush_stream(stream: &mut MqttStream<QuinnBiStream>) -> Result<()> {
    match stream {
        MqttStream::V3(stream) => stream.flush().await,
        MqttStream::V5(stream) => stream.flush().await,
    }
}

async fn close_stream(stream: &mut MqttStream<QuinnBiStream>) -> Result<()> {
    match stream {
        MqttStream::V3(stream) => stream.close().await,
        MqttStream::V5(stream) => stream.close().await,
    }
}

fn abort_stream(stream: &mut MqttStream<QuinnBiStream>, application_code: u32) -> Result<()> {
    match stream {
        MqttStream::V3(stream) => stream.io.get_mut().abort(application_code),
        MqttStream::V5(stream) => stream.io.get_mut().abort(application_code),
    }
}

fn take_stream_read_error(stream: &mut MqttStream<QuinnBiStream>) -> Option<ReadError> {
    match stream {
        MqttStream::V3(stream) => stream.io.get_mut().take_read_error(),
        MqttStream::V5(stream) => stream.io.get_mut().take_read_error(),
    }
}

fn take_stream_write_error(stream: &mut MqttStream<QuinnBiStream>) -> Option<WriteError> {
    match stream {
        MqttStream::V3(stream) => stream.io.get_mut().take_write_error(),
        MqttStream::V5(stream) => stream.io.get_mut().take_write_error(),
    }
}

async fn emit_connection_closed(events: &mpsc::Sender<QueuedLinkEvent>, reason: ConnectionCloseReason) {
    let _ = events.send(QueuedLinkEvent::unbuffered(LinkEvent::ConnectionClosed { reason })).await;
}

async fn emit_flow_closed(
    events: &mpsc::Sender<QueuedLinkEvent>,
    context: FlowContext,
    reason: FlowCloseReason,
) {
    if context.flow_kind == FlowKind::Control {
        let _ = events
            .send(QueuedLinkEvent::unbuffered(LinkEvent::ConnectionClosed {
                reason: ConnectionCloseReason::ControlFlowClosed,
            }))
            .await;
    } else {
        let _ = events
            .send(QueuedLinkEvent::unbuffered(LinkEvent::FlowClosed { flow_id: context.flow_id, reason }))
            .await;
    }
}

#[inline]
fn classify_data_packet(packet: &MqttPacket) -> DataPacketAction {
    match packet {
        MqttPacket::V3(packet) => classify_v3_data_packet(packet),
        MqttPacket::V5(packet) => classify_v5_data_packet(packet),
        MqttPacket::Version(_) => DataPacketAction::CloseConnection,
    }
}

#[inline]
fn classify_v3_data_packet(packet: &rmqtt_codec::v3::Packet) -> DataPacketAction {
    use rmqtt_codec::v3::Packet;

    match packet {
        Packet::Publish(_)
        | Packet::PublishAck { .. }
        | Packet::PublishReceived { .. }
        | Packet::PublishRelease { .. }
        | Packet::PublishComplete { .. }
        | Packet::Subscribe { .. }
        | Packet::Unsubscribe { .. } => DataPacketAction::Emit,
        Packet::PingRequest | Packet::PingResponse => DataPacketAction::ResetFlow,
        Packet::Connect(_)
        | Packet::ConnectAck(_)
        | Packet::Disconnect
        | Packet::SubscribeAck { .. }
        | Packet::UnsubscribeAck { .. } => DataPacketAction::CloseConnection,
    }
}

#[inline]
fn classify_v5_data_packet(packet: &rmqtt_codec::v5::Packet) -> DataPacketAction {
    use rmqtt_codec::v5::Packet;

    match packet {
        Packet::Publish(_)
        | Packet::PublishAck(_)
        | Packet::PublishReceived(_)
        | Packet::PublishRelease(_)
        | Packet::PublishComplete(_)
        | Packet::Subscribe(_)
        | Packet::Unsubscribe(_) => DataPacketAction::Emit,
        Packet::PingRequest | Packet::PingResponse => DataPacketAction::ResetFlow,
        Packet::Connect(_)
        | Packet::ConnectAck(_)
        | Packet::SubscribeAck(_)
        | Packet::UnsubscribeAck(_)
        | Packet::Disconnect(_)
        | Packet::Auth(_) => DataPacketAction::CloseConnection,
    }
}

#[derive(Clone, Copy)]
enum StreamVersion {
    V3,
    V5,
}

fn mqtt_stream_cfg(stream: &MqttStream<QuinnBiStream>) -> Arc<Builder> {
    match stream {
        MqttStream::V3(stream) => stream.cfg.clone(),
        MqttStream::V5(stream) => stream.cfg.clone(),
    }
}

fn mqtt_stream_remote_addr(stream: &MqttStream<QuinnBiStream>) -> std::net::SocketAddr {
    match stream {
        MqttStream::V3(stream) => stream.remote_addr,
        MqttStream::V5(stream) => stream.remote_addr,
    }
}

fn stream_version(stream: &MqttStream<QuinnBiStream>) -> StreamVersion {
    match stream {
        MqttStream::V3(_) => StreamVersion::V3,
        MqttStream::V5(_) => StreamVersion::V5,
    }
}

fn stream_for_version(
    version: StreamVersion,
    socket: QuinnBiStream,
    cfg: &Arc<Builder>,
    remote_addr: std::net::SocketAddr,
) -> MqttStream<QuinnBiStream> {
    match version {
        StreamVersion::V3 => MqttStream::V3(crate::v3::MqttStream {
            io: Framed::new(socket, MqttCodec::V3(rmqtt_codec::v3::Codec::new(cfg.max_packet_size))),
            remote_addr,
            cfg: cfg.clone(),
            #[cfg(feature = "tls")]
            cert_info: None,
        }),
        StreamVersion::V5 => MqttStream::V5(crate::v5::MqttStream {
            io: Framed::new(
                socket,
                MqttCodec::V5(rmqtt_codec::v5::Codec::new(cfg.max_packet_size, cfg.max_packet_size)),
            ),
            remote_addr,
            cfg: cfg.clone(),
            #[cfg(feature = "tls")]
            cert_info: None,
        }),
    }
}

fn reason_label(reason: &ConnectionCloseReason) -> &'static str {
    match reason {
        ConnectionCloseReason::ControlFlowClosed => "control-flow-closed",
        ConnectionCloseReason::ProtocolViolation => "protocol-violation",
        ConnectionCloseReason::StatefulFlowFailure => "stateful-flow-failure",
        ConnectionCloseReason::KeepAliveTimeout => "keep-alive-timeout",
        ConnectionCloseReason::ResourceLimit => "resource-limit",
        ConnectionCloseReason::LocalShutdown => "local-shutdown",
        ConnectionCloseReason::TransportLost => "transport-lost",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmqtt_codec::{v3, v5};

    #[test]
    fn data_allowlist_accepts_publish_qos_and_subscription_requests() {
        assert_eq!(
            classify_data_packet(&MqttPacket::V3(v3::Packet::PublishAck {
                packet_id: std::num::NonZeroU16::new(1).unwrap(),
            })),
            DataPacketAction::Emit
        );
        assert_eq!(
            classify_data_packet(&MqttPacket::V5(v5::Packet::PublishComplete(v5::PublishAck2 {
                packet_id: std::num::NonZeroU16::new(2).unwrap(),
                reason_code: v5::PublishAck2Reason::Success,
                properties: Vec::new(),
                reason_string: None,
            }))),
            DataPacketAction::Emit
        );
    }

    #[test]
    fn data_ping_resets_flow_without_emitting_packet() {
        assert_eq!(
            classify_data_packet(&MqttPacket::V3(v3::Packet::PingRequest)),
            DataPacketAction::ResetFlow
        );
        assert_eq!(
            classify_data_packet(&MqttPacket::V5(v5::Packet::PingResponse)),
            DataPacketAction::ResetFlow
        );
    }

    #[test]
    fn data_forbidden_packets_close_connection() {
        assert_eq!(
            classify_data_packet(&MqttPacket::V3(v3::Packet::Disconnect)),
            DataPacketAction::CloseConnection
        );
        assert_eq!(
            classify_data_packet(&MqttPacket::V5(v5::Packet::Auth(v5::Auth::default()))),
            DataPacketAction::CloseConnection
        );
    }

    #[test]
    fn target_resolution_rejects_stale_reply_generation() {
        let generation = 9;
        let stale = ReplyPath::new(FlowId::new(1), FlowKind::Data, generation - 1);
        assert!(
            resolve_send_target_for_test(generation, &[FlowId::new(1)], SendTarget::Reply(stale)).is_err()
        );
    }

    #[test]
    fn target_resolution_accepts_active_bound_flow() {
        let path =
            resolve_send_target_for_test(42, &[FlowId::new(7)], SendTarget::Bound(FlowId::new(7))).unwrap();
        assert_eq!(path.flow_id(), FlowId::new(7));
        assert_eq!(path.flow_kind(), FlowKind::Data);
        assert_eq!(path.generation(), 42);
    }

    fn resolve_send_target_for_test(
        generation: u64,
        flows: &[FlowId],
        target: SendTarget,
    ) -> Result<ReplyPath> {
        match target {
            SendTarget::Control => Ok(ReplyPath::new(FlowId::CONTROL, FlowKind::Control, generation)),
            SendTarget::Bound(flow_id) if flow_id == FlowId::CONTROL => {
                Ok(ReplyPath::new(FlowId::CONTROL, FlowKind::Control, generation))
            }
            SendTarget::Bound(flow_id) if flows.contains(&flow_id) => {
                Ok(ReplyPath::new(flow_id, FlowKind::Data, generation))
            }
            SendTarget::Bound(flow_id) => Err(anyhow!("QUIC data flow {} is not active", flow_id.get())),
            SendTarget::Reply(path) if path.generation() != generation => {
                Err(anyhow!("stale QUIC reply path generation"))
            }
            SendTarget::Reply(path)
                if path.flow_kind() == FlowKind::Control && path.flow_id() == FlowId::CONTROL =>
            {
                Ok(path)
            }
            SendTarget::Reply(path)
                if path.flow_kind() == FlowKind::Data && flows.contains(&path.flow_id()) =>
            {
                Ok(path)
            }
            SendTarget::Reply(path) => Err(anyhow!("QUIC data flow {} is not active", path.flow_id().get())),
        }
    }
}
