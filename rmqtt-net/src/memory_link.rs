#![deny(missing_docs)]

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use rmqtt_codec::MqttPacket;

use super::{
    ConnectionCloseReason, FlowCloseReason, FlowId, FlowKind, LinkEvent, MqttLink, ReplyPath, Result,
    SendReceipt, SendTarget,
};

#[derive(Debug)]
/// In-memory [`MqttLink`] implementation for deterministic protocol tests.
pub struct MemoryMqttLink {
    shared: Arc<Mutex<MemoryLinkState>>,
}

#[derive(Clone, Debug)]
/// Cloneable control handle for injecting events and inspecting a [`MemoryMqttLink`].
pub struct MemoryMqttLinkHandle {
    shared: Arc<Mutex<MemoryLinkState>>,
}

#[derive(Debug)]
/// Packet recorded by an in-memory link send operation.
pub struct SentPacket {
    /// Destination selected by the caller.
    pub target: SendTarget,
    /// MQTT packet passed to the link.
    pub packet: MqttPacket,
    /// Reply path resolved for the send operation.
    pub receipt: SendReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Close operation recorded by an in-memory link.
pub enum ClosedEvent {
    /// A single MQTT flow was reset.
    Flow {
        /// Identifier of the reset flow.
        flow_id: FlowId,
        /// Reason supplied for the flow reset.
        reason: FlowCloseReason,
    },
    /// The whole MQTT connection was closed.
    Connection {
        /// Reason supplied for the connection close.
        reason: ConnectionCloseReason,
    },
}

#[derive(Debug)]
struct MemoryLinkState {
    events: VecDeque<LinkEvent>,
    sent: Vec<SentPacket>,
    closed: Vec<ClosedEvent>,
    next_flow_id: u64,
    generation: u64,
    paths: HashMap<FlowId, ReplyPath>,
    next_send_failure: Option<String>,
    next_flush_failure: Option<String>,
}

impl MemoryMqttLink {
    /// Creates a link together with a handle that controls the same in-memory state.
    pub fn new() -> (Self, MemoryMqttLinkHandle) {
        let shared = Arc::new(Mutex::new(MemoryLinkState::new()));
        (Self { shared: Arc::clone(&shared) }, MemoryMqttLinkHandle { shared })
    }

    /// Returns another handle to the link's shared test state.
    pub fn handle(&self) -> MemoryMqttLinkHandle {
        MemoryMqttLinkHandle { shared: Arc::clone(&self.shared) }
    }
}

impl MemoryMqttLinkHandle {
    /// Queues a link event for the next receive operation.
    pub fn inject_event(&self, event: LinkEvent) {
        self.lock().events.push_back(event);
    }

    /// Queues an MQTT packet with its originating reply path.
    pub fn inject_packet(&self, packet: MqttPacket, reply_path: ReplyPath) {
        self.inject_event(LinkEvent::Packet { packet, reply_path });
    }

    /// Allocates the next reply path for the requested flow kind.
    pub fn next_reply_path(&self, flow_kind: FlowKind) -> ReplyPath {
        let mut state = self.lock();
        state.next_reply_path(flow_kind)
    }

    /// Returns the stable reply path for a particular flow identifier and kind.
    pub fn reply_path_for(&self, flow_id: FlowId, flow_kind: FlowKind) -> ReplyPath {
        let mut state = self.lock();
        state.reply_path_for(flow_id, flow_kind)
    }

    /// Makes the next send operation fail with the supplied message.
    pub fn fail_next_send(&self, message: impl Into<String>) {
        self.lock().next_send_failure = Some(message.into());
    }

    /// Makes the next flush operation fail with the supplied message.
    pub fn fail_next_flush(&self, message: impl Into<String>) {
        self.lock().next_flush_failure = Some(message.into());
    }

    /// Returns the number of recorded send operations.
    pub fn sent_len(&self) -> usize {
        self.lock().sent.len()
    }

    /// Returns the number of events waiting to be received.
    pub fn queued_len(&self) -> usize {
        self.lock().events.len()
    }

    /// Returns the number of recorded close operations.
    pub fn closed_len(&self) -> usize {
        self.lock().closed.len()
    }

    /// Drains and returns all recorded send operations.
    pub fn take_sent(&self) -> Vec<SentPacket> {
        std::mem::take(&mut self.lock().sent)
    }

    /// Drains and returns all recorded close operations.
    pub fn take_closed(&self) -> Vec<ClosedEvent> {
        std::mem::take(&mut self.lock().closed)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemoryLinkState> {
        match self.shared.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl MqttLink for MemoryMqttLink {
    async fn recv(&mut self) -> Result<Option<LinkEvent>> {
        Ok(self.lock().events.pop_front())
    }

    async fn send(&mut self, target: SendTarget, packet: MqttPacket) -> Result<SendReceipt> {
        let mut state = self.lock();
        if let Some(message) = state.next_send_failure.take() {
            return Err(anyhow!(message));
        }

        let path = state.resolve_target(target);
        let receipt = SendReceipt::new(path);
        state.sent.push(SentPacket { target, packet, receipt });
        Ok(receipt)
    }

    async fn flush(&mut self) -> Result<()> {
        if let Some(message) = self.lock().next_flush_failure.take() {
            return Err(anyhow!(message));
        }
        Ok(())
    }

    async fn reset_flow(&mut self, flow_id: FlowId, reason: FlowCloseReason) -> Result<()> {
        let mut state = self.lock();
        state.closed.push(ClosedEvent::Flow { flow_id, reason: reason.clone() });
        state.events.push_back(LinkEvent::FlowClosed { flow_id, reason });
        Ok(())
    }

    async fn close_connection(&mut self, reason: ConnectionCloseReason) -> Result<()> {
        let mut state = self.lock();
        state.closed.push(ClosedEvent::Connection { reason: reason.clone() });
        state.events.push_back(LinkEvent::ConnectionClosed { reason });
        Ok(())
    }
}

impl MemoryMqttLink {
    fn lock(&self) -> std::sync::MutexGuard<'_, MemoryLinkState> {
        match self.shared.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl MemoryLinkState {
    fn new() -> Self {
        Self {
            events: VecDeque::new(),
            sent: Vec::new(),
            closed: Vec::new(),
            next_flow_id: 1,
            generation: 1,
            paths: HashMap::new(),
            next_send_failure: None,
            next_flush_failure: None,
        }
    }

    fn resolve_target(&mut self, target: SendTarget) -> ReplyPath {
        match target {
            SendTarget::Control => ReplyPath::control(),
            SendTarget::Reply(reply_path) => reply_path,
            SendTarget::Bound(flow_id) => self.reply_path_for(flow_id, flow_kind_for(flow_id)),
        }
    }

    fn next_reply_path(&mut self, flow_kind: FlowKind) -> ReplyPath {
        if flow_kind == FlowKind::Control {
            return ReplyPath::control();
        }

        let flow_id = FlowId::new(self.next_flow_id);
        self.next_flow_id += 1;
        self.reply_path_for(flow_id, flow_kind)
    }

    fn reply_path_for(&mut self, flow_id: FlowId, flow_kind: FlowKind) -> ReplyPath {
        if flow_id == FlowId::CONTROL || flow_kind == FlowKind::Control {
            return ReplyPath::control();
        }

        *self.paths.entry(flow_id).or_insert_with(|| ReplyPath::new(flow_id, flow_kind, self.generation))
    }
}

fn flow_kind_for(flow_id: FlowId) -> FlowKind {
    if flow_id == FlowId::CONTROL {
        FlowKind::Control
    } else {
        FlowKind::Data
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn poisoned_test_state_remains_observable() {
        let (link, handle) = MemoryMqttLink::new();
        let poison_handle = handle.clone();

        let result = thread::spawn(move || {
            let _state = match poison_handle.shared.lock() {
                Ok(state) => state,
                Err(_) => panic!("test must acquire unpoisoned state lock"),
            };
            panic!("poison test state");
        })
        .join();

        assert!(result.is_err());
        handle.inject_event(LinkEvent::ConnectionClosed { reason: ConnectionCloseReason::LocalShutdown });
        assert_eq!(handle.queued_len(), 1);
        assert_eq!(link.handle().queued_len(), 1);
    }
}
