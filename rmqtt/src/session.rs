//! MQTT Session Management Core
//!
//! Provides robust session handling for MQTT brokers with full protocol version support (v3.1.1 & v5.0).
//! Implements advanced session state management with online/offline mode switching and QoS guarantee mechanisms.
//!
//! ## Core Features
//! 1. **Stateful Session Management**:
//!    - Automatic failover between online/offline modes
//!    - QoS 0/1/2 message handling with retry mechanisms
//!    - Session expiration and cleanup policies
//!
//! 2. **Message Processing**:
//!    - Hierarchical topic matching with wildcard support
//!    - Message expiry and retention policies
//!    - Flow control through configurable queue limits
//!
//! 3. **Protocol Implementation**:
//!    - MQTT 5.0 features:
//!      - Session expiry intervals
//!      - Topic aliasing
//!      - Enhanced authentication flows
//!    - Backward compatible with MQTT 3.1.1
//!
//! ## Architectural Components
//! ```text
//! SessionState
//! ├── Online Mode
//! │   ├── Real-time message delivery
//! │   ├── Keep-alive management
//! │   └── QoS handshake handling
//! └── Offline Mode
//!     ├── Message persistence
//!     ├── Delayed will messages
//!     └── Session state preservation
//! ```
//!
//! ## Key Mechanisms
//! - **Inflight Window Management**:
//!   - Tracks unacknowledged messages with configurable retry intervals
//!   - Implements sliding window protocol for QoS 1/2
//!
//! - **Hook System**:
//!   ```rust,ignore
//!   hook.message_publish()  // Message interception
//!   hook.client_keepalive() // Connection monitoring
//!   ```
//!   Allows custom processing through 10+ extension points
//!
//! - **Distributed Session Handling**:
//!   - Atomic session state transfers between nodes
//!   - Shared subscription support with load balancing
//!
//! ## Performance Characteristics
//! | Operation | Guarantee | Mechanism |
//! |-----------|-----------|-----------|
//! | Message Delivery | At-least-once | QoS 1 retransmit |
//! | Session Recovery | Exactly-once | State snapshotting |
//! | Connection Handling | 50K+ CPS | Async I/O with Tokio |
//!
//! Implements MQTT 5.0 best practices from OASIS specifications while maintaining
//! backward compatibility through protocol negotiation and feature detection.

use std::collections::vec_deque::VecDeque;
use std::convert::From as _f;
use std::fmt;
use std::num::NonZeroU16;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
#[allow(unused_imports)]
use bitflags::Flags;
use bytestring::ByteString;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::json;

use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};

use crate::acl::AuthInfo;
#[cfg(any(feature = "retain", feature = "msgstore"))]
use crate::codec::v5::RetainHandling;
use crate::codec::{
    v3,
    v5::{self, Auth, SubscribeAckReason, ToReasonCode},
};
use crate::context::ServerContext;
use crate::hook::Hook;
use crate::inflight::{InInflight, MomentStatus, OutInflight, OutInflightMessage};
use crate::net::{ConnectionCloseReason, FlowCloseReason, MqttError, MqttLink, ReplyPath, SendTarget};
use crate::queue::{self, Limiter, Policy};
use crate::route::{
    PacketIssuer, PacketRouteKey, PacketRouteLedger, RouteError, TransactionFamily, TransactionStage,
};
use crate::session_link::{SessionLink, SessionLinkEvent};
#[cfg(feature = "msgstore")]
use crate::shared::MessageLoadCallback;
#[cfg(feature = "retain")]
use crate::shared::RetainLoadCallback;
use crate::subscription_binding::SubscriptionBindingStore;
use crate::types::*;
use crate::utils::timestamp_millis;
use crate::Result;

/// Runtime state for an active MQTT session.
///
/// Wraps a [`Session`] with its associated send/receive channels,
/// hook system, topic aliases, and inbound inflight message tracker.
/// Created when an MQTT CONNECT is processed and represents the
/// full execution context for a connected client.
pub struct SessionState {
    inner: Session,
    tx: Tx,
    rx: Rx,
    pub hook: Arc<dyn Hook>,
    pub server_topic_aliases: Option<Arc<ServerTopicAliases>>,
    pub client_topic_aliases: Option<Arc<ClientTopicAliases>>,
    topic_alias_forbidden: bool,
    in_inflight: InInflightType,
    routes: PacketRouteLedger,
    subscription_bindings: SubscriptionBindingStore,
}

struct SubscribeOutcome {
    reply: SubscribeReturn,
    topic_filter: Option<TopicFilter>,
}

type OutboundTransaction = (PacketRouteKey, TransactionFamily, TransactionStage, MomentStatus);

fn resolve_existing_outbound_route(
    routes: &PacketRouteLedger,
    transaction: Option<OutboundTransaction>,
    duplicate: bool,
) -> Result<Option<ReplyPath>> {
    let Some((key, family, stage, _)) = transaction else {
        return Ok(None);
    };
    let Some(entry) = routes.get(key) else {
        return Ok(None);
    };
    if !duplicate {
        return Err(anyhow::anyhow!("outbound MQTT packet identifier already has an active route: {key:?}"));
    }
    routes.validate(key, family, stage, entry.path()).map_err(|error| anyhow::anyhow!(error))?;
    Ok(Some(entry.path()))
}

fn accept_client_qos2_publish_route(
    routes: &mut PacketRouteLedger,
    route_key: PacketRouteKey,
    reply_path: ReplyPath,
    duplicate: bool,
    resumed_await_pubrel: bool,
) -> std::result::Result<bool, Reason> {
    if resumed_await_pubrel && !duplicate {
        return Err(MqttError::PacketIdInUse(route_key.packet_id()).into());
    }

    if resumed_await_pubrel {
        routes
            .insert_or_validate_duplicate(
                route_key,
                TransactionFamily::PublishQos2,
                TransactionStage::PublishQos2AwaitPubrel,
                reply_path,
                true,
            )
            .map_err(SessionState::route_reason)?;
        Ok(false)
    } else {
        routes
            .insert_or_validate_duplicate(
                route_key,
                TransactionFamily::PublishQos2,
                TransactionStage::PublishQos2AwaitPubrel,
                reply_path,
                duplicate,
            )
            .map_err(SessionState::route_reason)
    }
}

fn restore_client_pubrel_route(
    routes: &mut PacketRouteLedger,
    route_key: PacketRouteKey,
    reply_path: ReplyPath,
    resumed_await_pubrel: bool,
) -> std::result::Result<(), Reason> {
    match routes.transition(
        route_key,
        TransactionFamily::PublishQos2,
        TransactionStage::PublishQos2AwaitPubrel,
        TransactionStage::PublishQos2AwaitPubrel,
        reply_path,
    ) {
        Ok(_) => Ok(()),
        Err(RouteError::NotFound { .. }) if resumed_await_pubrel => {
            routes
                .insert(
                    route_key,
                    TransactionFamily::PublishQos2,
                    TransactionStage::PublishQos2AwaitPubrel,
                    reply_path,
                )
                .map_err(SessionState::route_reason)?;
            routes
                .transition(
                    route_key,
                    TransactionFamily::PublishQos2,
                    TransactionStage::PublishQos2AwaitPubrel,
                    TransactionStage::PublishQos2AwaitPubrel,
                    reply_path,
                )
                .map_err(SessionState::route_reason)?;
            Ok(())
        }
        Err(error) => Err(SessionState::route_reason(error)),
    }
}

#[cfg(test)]
mod outbound_route_tests {
    use super::*;
    use crate::net::{FlowId, FlowKind};

    #[test]
    fn non_duplicate_packet_id_reuse_is_rejected_before_route_selection() {
        let mut routes = PacketRouteLedger::new();
        let packet_id = NonZeroU16::new(42).unwrap();
        let key = PacketRouteKey::new(PacketIssuer::Server, packet_id);
        let path = ReplyPath::new(FlowId::new(3), FlowKind::Data, 9);
        routes
            .insert(key, TransactionFamily::PublishQos1, TransactionStage::PublishQos1AwaitPuback, path)
            .unwrap();
        let transaction = Some((
            key,
            TransactionFamily::PublishQos1,
            TransactionStage::PublishQos1AwaitPuback,
            MomentStatus::UnAck,
        ));

        assert!(resolve_existing_outbound_route(&routes, transaction, false).is_err());
        assert_eq!(resolve_existing_outbound_route(&routes, transaction, true).unwrap(), Some(path));
    }

    #[test]
    fn restored_dup_qos2_publish_rebuilds_route_without_republishing() {
        let mut routes = PacketRouteLedger::new();
        let packet_id = NonZeroU16::new(42).unwrap();
        let key = PacketRouteKey::new(PacketIssuer::Client, packet_id);
        let path = ReplyPath::new(FlowId::new(3), FlowKind::Data, 9);

        let should_publish = accept_client_qos2_publish_route(&mut routes, key, path, true, true).unwrap();

        assert!(!should_publish);
        let entry = routes.get(key).unwrap();
        assert_eq!(entry.family(), TransactionFamily::PublishQos2);
        assert_eq!(entry.stage(), TransactionStage::PublishQos2AwaitPubrel);
        assert_eq!(entry.path(), path);
    }

    #[test]
    fn restored_pubrel_without_route_rebuilds_current_path_for_completion() {
        let mut routes = PacketRouteLedger::new();
        let packet_id = NonZeroU16::new(7).unwrap();
        let key = PacketRouteKey::new(PacketIssuer::Client, packet_id);
        let path = ReplyPath::new(FlowId::new(5), FlowKind::Data, 11);

        restore_client_pubrel_route(&mut routes, key, path, true).unwrap();
        routes
            .complete(key, TransactionFamily::PublishQos2, TransactionStage::PublishQos2AwaitPubrel, path)
            .unwrap();

        assert!(routes.get(key).is_none());
    }
}

impl fmt::Debug for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionState {{ {:?}, {:?} }}", self.id, self.inner,)
    }
}

impl Deref for SessionState {
    type Target = Session;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl SessionState {
    #[inline]
    pub(crate) fn new(
        session: Session,
        hook: Arc<dyn Hook>,
        server_topic_alias_max: u16,
        client_topic_alias_max: u16,
        topic_alias_forbidden: bool,
    ) -> Self {
        let server_topic_aliases = if server_topic_alias_max > 0 {
            Some(Arc::new(ServerTopicAliases::new(server_topic_alias_max as usize)))
        } else {
            None
        };
        let client_topic_aliases = if client_topic_alias_max > 0 {
            Some(Arc::new(ClientTopicAliases::new(client_topic_alias_max as usize)))
        } else {
            None
        };
        log::debug!("server_topic_aliases: {server_topic_aliases:?}");
        log::debug!("client_topic_aliases: {client_topic_aliases:?}");

        let mailbox_capacity = SessionTx::mailbox_capacity(session.listen_cfg().max_mqueue_len);
        let (tx, rx) = tokio::sync::mpsc::channel(mailbox_capacity);
        let tx = SessionTx::new(
            tx,
            #[cfg(feature = "debug")]
            session.scx.clone(),
        );
        let in_inflight = session.in_inflight.clone();
        Self {
            inner: session,
            tx,
            rx,
            hook,
            // deliver_queue_tx: None,
            server_topic_aliases,
            client_topic_aliases,
            topic_alias_forbidden,
            in_inflight,
            routes: PacketRouteLedger::new(),
            subscription_bindings: SubscriptionBindingStore::new(),
        }
    }

    #[inline]
    pub fn session(&self) -> &Session {
        &self.inner
    }

    #[inline]
    pub fn tx(&self) -> &Tx {
        &self.tx
    }

    #[inline]
    pub(crate) async fn run<L>(mut self, mut sink: SessionLink<L>, keep_alive: u16)
    where
        L: MqttLink,
    {
        let limiter = {
            let (burst, replenish_n_per) = self.fitter.mqueue_rate_limit();
            Limiter::new(burst, replenish_n_per)
        };

        let (deliver_queue_tx, mut deliver_queue_rx) = self.deliver_queue_channel(&limiter);
        let mut flags = StateFlags::empty();

        self.scx.connections.inc();
        match self.run_loop(&mut sink, keep_alive, &mut flags, &deliver_queue_tx, &mut deliver_queue_rx).await
        {
            Ok(()) => {
                log::debug!("{} exit ...", self.id);
            }
            Err(reason) => {
                log::debug!("{} Reason: {}", self.id, reason);
                let _ = self.disconnected_reason_add(reason).await;
            }
        }
        self.scx.connections.dec();

        if let Err(e) = sink.close().await {
            log::info!("{} close io error, {e}", self.id);
        }

        let disconnect = self.disconnect().await.unwrap_or(None);
        let clean_session = self.clean_session(disconnect.as_ref()).await;

        log::debug!(
            "{:?} exit online worker, flags: {:?}, clean_session: {:?} {}",
            self.id,
            flags,
            self.connect_info().await.map(|c| c.clean_start()),
            flags.contains(StateFlags::CleanStart)
        );

        //Setting the disconnected state
        if let Err(e) = self.disconnected_set(None, None).await {
            log::info!("{:?} disconnected set error, {:?}", self.id, e);
        }

        log::debug!(
            "{} disconnected_reason({}): {:?}",
            self.id,
            self.disconnected_reasons().await.map(|rs| rs.len()).unwrap_or_default(),
            self.disconnected_reason().await
        );

        //Last will message
        let will_delay_interval = if self.last_will_enable(flags, clean_session) {
            let will_delay_interval = self.will_delay_interval().await;
            if clean_session || will_delay_interval.is_none() {
                if let Err(e) = self.process_last_will().await {
                    log::warn!("{:?} process last will error, {:?}", self.id, e);
                }
                None
            } else {
                will_delay_interval
            }
        } else {
            None
        };

        //hook, client_disconnected
        let reason = if self.disconnected_reason_has().await {
            self.disconnected_reason().await.unwrap_or_default()
        } else {
            if let Err(e) = self.disconnected_reason_add(Reason::ConnectRemoteClose).await {
                log::warn!("{:?} disconnected reason add error: {:?}", self.id, e);
            }
            Reason::ConnectRemoteClose
        };

        if sink.protocol() == rmqtt_codec::version::ProtocolVersion::MQTT5 {
            let d = if let Reason::ConnectDisconnect(Some(Disconnect::V5(d))) = &reason {
                d.clone()
            } else {
                v5::Disconnect {
                    reason_code: reason.to_reason_code(),
                    reason_string: Some(reason.to_string().into()),
                    ..Default::default()
                }
            };
            let _ = sink.send_disconnect(SendTarget::Control, d).await;
        }

        self.hook.client_disconnected(reason).await;

        if flags.contains(StateFlags::Kicked) {
            if flags.contains(StateFlags::ByAdminKick) {
                self.clean(&deliver_queue_tx, self.disconnected_reason_take().await.unwrap_or_default())
                    .await;
            }
        } else if clean_session {
            self.clean(&deliver_queue_tx, self.disconnected_reason_take().await.unwrap_or_default()).await;
        } else {
            let session_expiry_interval = self.fitter.session_expiry_interval(disconnect.as_ref());
            //hook, offline_inflight_messages
            let inflight_messages = self.out_inflight().write().await.clone_inflight_messages();
            let has_inbound_qos2 = !self.inbound_qos2_await_pubrel_snapshot().await.is_empty();
            if !inflight_messages.is_empty() || has_inbound_qos2 {
                self.hook.offline_inflight_messages(inflight_messages).await;
            }

            //Start offline event loop
            self.offline_run_loop(
                &deliver_queue_tx,
                &mut flags,
                will_delay_interval,
                session_expiry_interval,
            )
            .await;
            log::debug!("{:?} offline flags: {:?}", self.id, flags);
            if !flags.contains(StateFlags::Kicked) {
                self.clean(&deliver_queue_tx, Reason::SessionExpiration).await;
            }
        }
    }

    #[inline]
    async fn run_loop<L>(
        &mut self,
        sink: &mut SessionLink<L>,
        keep_alive: u16,
        flags: &mut StateFlags,
        deliver_queue_tx: &queue::Sender<(From, Publish)>,
        deliver_queue_rx: &mut queue::Receiver<'_, (From, Publish)>,
    ) -> std::result::Result<(), Reason>
    where
        L: MqttLink,
    {
        log::debug!("{:?} start online event loop", self.id);
        let state = self;

        let keep_alive_interval = if keep_alive == 0 {
            Duration::from_secs(u32::MAX as u64)
        } else {
            Duration::from_secs(keep_alive as u64)
        };
        log::debug!("{:?} keep_alive_interval is {:?}", state.id, keep_alive_interval);
        let keep_alive_delay = tokio::time::sleep(keep_alive_interval);

        let deliver_timeout_delay = tokio::time::sleep(Duration::from_secs(60));

        log::debug!("{:?} there are {} offline messages ...", state.id, state.deliver_queue().len());

        tokio::pin!(keep_alive_delay);

        tokio::pin!(deliver_timeout_delay);

        loop {
            log::debug!("{:?} tokio::select! loop", state.id);
            deliver_timeout_delay.as_mut().reset(
                Instant::now()
                    + state
                        .out_inflight()
                        .read()
                        .await
                        .get_timeout()
                        .unwrap_or_else(|| Duration::from_secs(120)),
            );

            tokio::select! {
                 _ = &mut keep_alive_delay => {
                    return Err(Reason::ConnectKeepaliveTimeout)
                },

                _ = &mut deliver_timeout_delay => {
                    loop {
                        let iflt_msg = { state.out_inflight().write().await.pop_front_timeout() };
                        let Some(iflt_msg) = iflt_msg else {
                            break;
                        };
                        log::debug!("{:?} has timeout message in inflight: {:?}", state.id, iflt_msg);
                        state.reforward(sink, iflt_msg).await?;
                    }
                },

                deliver_packet = deliver_queue_rx.next(), if state.out_inflight().read().await.has_credit() => {
                    log::debug!("{:?} deliver_packet: {:?}", state.id, deliver_packet);
                    match deliver_packet {
                        Some(Some((from, p))) => {
                            state.deliver(sink, from, p).await?;
                        },
                        Some(None) => {
                            log::warn!("{:?} No messages received from the delivery queue", state.id);
                        },
                        None => {
                            return Err("Message delivery queue is closed".into())
                        }
                    }
                }

                msg = state.rx.recv() => {
                    log::debug!("{:?} msg: {:?}", state.id, msg);
                    if let Some(msg) = msg {
                        #[cfg(feature = "debug")]
                        state.scx.stats.debug_session_channels.dec();
                        state.process_message(sink, msg, deliver_queue_tx, flags).await?;
                    }else{
                        return Err("No message received from the Rx".into());
                    }
                }

                event = sink.recv() => {
                    log::debug!("{:?} link event: {:?}", state.id, event);
                    match event? {
                        Some(SessionLinkEvent::Packet { packet, reply_path }) => {
                            state.process_mqtt_message(sink, packet, reply_path, flags).await?;
                            keep_alive_delay.as_mut().reset(Instant::now() + keep_alive_interval);
                        },
                        Some(SessionLinkEvent::FlowClosed { flow_id, reason }) => {
                            log::debug!("{:?} data flow {:?} closed: {:?}", state.id, flow_id, reason);
                            if state.routes.has_flow_entries(flow_id) {
                                let _ = sink
                                    .close_connection(ConnectionCloseReason::StatefulFlowFailure)
                                    .await;
                                return Err(Reason::ProtocolError(
                                    format!("stateful MQTT transaction lost with data flow {flow_id:?}").into(),
                                ));
                            }
                            state.subscription_bindings.remove_flow(flow_id);
                        },
                        Some(SessionLinkEvent::ConnectionClosed { reason }) => {
                            log::debug!("{:?} MQTT link closed: {:?}", state.id, reason);
                            return Err(Reason::ConnectRemoteClose);
                        },
                        None => return Err(Reason::ConnectRemoteClose),
                    }
                }
            }
        }
    }

    #[inline]
    async fn offline_run_loop(
        &mut self,
        deliver_queue_tx: &MessageSender,
        flags: &mut StateFlags,
        mut will_delay_interval: Option<Duration>,
        session_expiry_interval: Duration,
    ) {
        log::debug!(
            "{:?} start offline event loop, session_expiry_interval: {:?}, will_delay_interval: {:?}",
            self.id,
            session_expiry_interval,
            will_delay_interval
        );

        //state.disconnect
        let session_expiry_delay = tokio::time::sleep(session_expiry_interval);
        tokio::pin!(session_expiry_delay);

        let will_delay_interval_delay = tokio::time::sleep(will_delay_interval.unwrap_or(Duration::MAX));
        tokio::pin!(will_delay_interval_delay);

        loop {
            tokio::select! {
                msg = self.rx.recv() => {
                    log::debug!("{:?} recv offline msg: {:?}", self.id, msg);
                    if let Some(msg) = msg {
                        match msg {
                            Message::Forward(from, p) => {

                                //hook, offline_message
                                self.hook.offline_message(from.clone(), &p).await;

                                if let Err((from, p)) = deliver_queue_tx.send((from, p)).await {
                                    log::debug!("{:?} offline deliver_dropped, from: {:?}, {:?}", self.id, from, p);
                                    //hook, message_dropped
                                   self.scx.extends.hook_mgr().message_dropped(Some(self.id.clone()), from, p, Reason::MessageQueueFull).await;
                                }
                            },
                            Message::Kick(sender, by_id, clean_start, is_admin) => {
                                log::debug!("{:?} offline Kicked, send kick result, to: {:?}, clean_start: {}, is_admin: {}", self.id, by_id, clean_start, is_admin);
                                if !sender.is_closed() {
                                    if let Err(e) = sender.send(()) {
                                        log::warn!("{:?} offline Kick send response error, to: {:?}, clean_start: {}, is_admin: {}, {:?}", self.id, by_id, clean_start, is_admin, e);
                                    }
                                    flags.insert(StateFlags::Kicked);
                                    if is_admin {
                                        flags.insert(StateFlags::ByAdminKick);
                                    }
                                    if clean_start {
                                        flags.insert(StateFlags::CleanStart);
                                    }
                                    break
                                }else{
                                    log::warn!("{:?} offline Kick sender is closed, to {:?}, clean_start: {}, is_admin: {}", self.id, by_id, clean_start, is_admin);
                                }
                            },
                            _ => {
                                log::debug!("{:?} offline receive message is {:?}", self.id, msg);
                            }
                        }
                    }else{
                        log::warn!("{:?} offline None is received from the Rx", self.id);
                        break;
                    }
                },
               _ = &mut session_expiry_delay => { //, if !session_expiry_delay.is_elapsed() => {
                  log::debug!("{:?} session expired, will_delay_interval: {:?}", self.id, will_delay_interval);
                  if will_delay_interval.is_some() {
                      if let Err(e) = self.process_last_will().await {
                          log::error!("{:?} process last will error, {:?}", self.id, e);
                      }
                  }
                  break
               },
               _ = &mut will_delay_interval_delay => { //, if !will_delay_interval_delay.is_elapsed() => {
                  log::debug!("{:?} will delay interval, will_delay_interval: {:?}", self.id, will_delay_interval);
                  if will_delay_interval.is_some() {
                      if let Err(e) = self.process_last_will().await {
                          log::error!("{:?} process last will error, {:?}", self.id, e);
                      }
                      will_delay_interval = None;
                  }
                  will_delay_interval_delay.as_mut().reset(
                    Instant::now() + session_expiry_interval,
                  );
               },
            }
        }
        log::debug!("{:?} exit offline worker", self.id);
    }

    /// Restart an offline MQTT session asynchronously.
    ///
    /// This function:
    /// - Sets up internal session state, including rate limiter and queues.
    /// - Handles Last Will message logic if applicable.
    /// - Spawns a background task to manage the session's offline lifecycle.
    ///
    /// Returns a handle to the message transmission channel (`Tx`) that can be used
    /// to send messages to this offline session.
    ///
    /// # Arguments
    ///
    /// * `session` - The session object representing the MQTT client.
    /// * `session_expiry_interval` - How long the session should persist before expiration.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `Tx` (message transmission handle), or an error.
    ///
    #[inline]
    pub async fn offline_restart(session: Session, session_expiry_interval: Duration) -> Result<Tx> {
        let hook = session.scx.extends.hook_mgr().hook(session.clone());

        let mut state = SessionState::new(session, hook, 0, 0, false);
        let msg_tx = state.tx.clone();
        let limiter = {
            let (burst, replenish_n_per) = state.fitter.mqueue_rate_limit();
            Limiter::new(burst, replenish_n_per)
        };

        tokio::spawn(async move {
            let (deliver_queue_tx, _deliver_queue_rx) = state.deliver_queue_channel(&limiter);
            let mut flags = StateFlags::empty();

            let disconnect = state.disconnect().await.unwrap_or(None);
            let clean_session = state.clean_session(disconnect.as_ref()).await;

            //Last will message
            let will_delay_interval = if state.last_will_enable(flags, clean_session) {
                let will_delay_interval = state.will_delay_interval().await;
                if clean_session || will_delay_interval.is_none() {
                    if let Err(e) = state.process_last_will().await {
                        log::error!("{:?} process last will error, {:?}", state.id, e);
                    }
                    None
                } else {
                    will_delay_interval
                }
            } else {
                None
            };

            state
                .offline_run_loop(&deliver_queue_tx, &mut flags, will_delay_interval, session_expiry_interval)
                .await;

            if !flags.contains(StateFlags::Kicked) {
                state.clean(&deliver_queue_tx, Reason::SessionExpiration).await;
            }
        });

        Ok(msg_tx)
    }

    #[inline]
    async fn process_message<L>(
        &mut self,
        sink: &mut SessionLink<L>,
        msg: Message,
        deliver_queue_tx: &queue::Sender<(From, Publish)>,
        flags: &mut StateFlags,
    ) -> std::result::Result<(), Reason>
    where
        L: MqttLink,
    {
        match msg {
            Message::Forward(from, p) => {
                if let Err((from, p)) = deliver_queue_tx.send((from, p)).await {
                    log::debug!("{:?} deliver_dropped, from: {:?}, {:?}", self.id, from, p);
                    //hook, message_dropped
                    self.scx
                        .extends
                        .hook_mgr()
                        .message_dropped(Some(self.id.clone()), from, p, Reason::MessageQueueFull)
                        .await;
                }
            }
            Message::Kick(sender, by_id, clean_start, is_admin) => {
                log::debug!(
                    "{:?} Message::Kick, send kick result, to {:?}, clean_start: {}, is_admin: {}",
                    self.id,
                    by_id,
                    clean_start,
                    is_admin
                );
                if !sender.is_closed() {
                    if sender.send(()).is_err() {
                        log::warn!("{:?} Message::Kick, send response error, sender is closed", self.id);
                    }
                    flags.insert(StateFlags::Kicked);
                    if is_admin {
                        flags.insert(StateFlags::ByAdminKick);
                    }
                    if clean_start {
                        flags.insert(StateFlags::CleanStart);
                    }
                    return Err(Reason::ConnectKicked(is_admin));
                } else {
                    log::warn!(
                        "{:?} Message::Kick, kick sender is closed, to {:?}, is_admin: {}",
                        self.id,
                        by_id,
                        is_admin
                    );
                }
            }
            Message::Subscribe(sub, reply_tx) => {
                log::debug!("{:?} Message::Subscribe, sub {:?}", self.id, sub,);
                let sub_reply = self.subscribe(sub).await;
                if !reply_tx.is_closed() {
                    if let Err(e) = reply_tx.send(sub_reply) {
                        log::warn!("{:?} Message::Subscribe, send response error, {:?}", self.id, e);
                    }
                } else {
                    log::warn!("{:?} Message::Subscribe, reply sender is closed", self.id);
                }
            }
            Message::Subscribes(subs, replies_tx) => {
                log::debug!("{:?} Message::Subscribes, subs {:?}", self.id, subs,);

                let mut replies = Vec::new();
                for sub in subs {
                    let reply = self.subscribe(sub).await;
                    match &reply {
                        Err(e) => {
                            log::warn!("{:?} Message::Subscribes, subscribe error, {:?}", self.id, e);
                        }
                        Ok(ret) => {
                            if ret.failure() {
                                log::warn!(
                                    "{:?} Message::Subscribes, subscribe failed, {:?}",
                                    self.id,
                                    ret.ack_reason
                                );
                            }
                        }
                    }
                    replies.push(reply);
                }
                if let Some(replies_tx) = replies_tx {
                    if !replies_tx.is_closed() {
                        if let Err(e) = replies_tx.send(replies) {
                            log::warn!("{:?} Message::Subscribes, send response error, {:?}", self.id, e);
                        }
                    } else {
                        log::warn!("{:?} Message::Subscribes, reply sender is closed", self.id);
                    }
                }
            }
            Message::Unsubscribe(unsub, reply_tx) => {
                log::debug!("{:?} Message::Unsubscribe, unsub {:?}", self.id, unsub,);
                let unsub_reply = self.unsubscribe(unsub).await;
                if !reply_tx.is_closed() {
                    if let Err(e) = reply_tx.send(unsub_reply) {
                        log::warn!("{:?} Message::Unsubscribe, send response error, {:?}", self.id, e);
                    }
                } else {
                    log::warn!("{:?} Message::Unsubscribe, reply sender is closed", self.id);
                }
            }
            Message::SessionStateTransfer(offline_info, clean_start) => {
                self.transfer_session_state(sink, clean_start, offline_info).await?;
            }
            Message::Closed(r) => {
                return Err(r);
            }
        }
        Ok(())
    }

    async fn accept_client_pubrel(
        &mut self,
        packet_id: NonZeroU16,
        reply_path: ReplyPath,
    ) -> std::result::Result<(), Reason> {
        let key = PacketRouteKey::new(PacketIssuer::Client, packet_id);
        let resumed_await_pubrel = self.in_inflight.read().await.contains(&packet_id);
        restore_client_pubrel_route(&mut self.routes, key, reply_path, resumed_await_pubrel)
    }

    #[inline]
    async fn process_mqtt_message<L>(
        &mut self,
        sink: &mut SessionLink<L>,
        pkt: Packet,
        reply_path: ReplyPath,
        flags: &mut StateFlags,
    ) -> std::result::Result<(), Reason>
    where
        L: MqttLink,
    {
        match pkt {
            Packet::V3(v3::Packet::Publish(publish)) => {
                log::debug!("{} publish: {:?}", self.id, publish);
                let p: Publish = publish.into();
                self.process_publish(sink, p.create_time(timestamp_millis()), reply_path).await?;
            }
            Packet::V5(v5::Packet::Publish(publish)) => {
                log::debug!("{} publish: {:?}", self.id, publish);
                let p: Publish = publish.into();
                self.process_publish(sink, p.create_time(timestamp_millis()), reply_path).await?;
            }

            Packet::V3(v3::Packet::PublishRelease { packet_id }) => {
                log::debug!("{} PublishRelease: {:?}", self.id, packet_id);
                let key = PacketRouteKey::new(PacketIssuer::Client, packet_id);
                self.accept_client_pubrel(packet_id, reply_path).await?;
                sink.send_publish_complete(SendTarget::Reply(reply_path), packet_id, None).await?;
                self.routes
                    .complete(
                        key,
                        TransactionFamily::PublishQos2,
                        TransactionStage::PublishQos2AwaitPubrel,
                        reply_path,
                    )
                    .map_err(Self::route_reason)?;
                self.in_inflight.write().await.remove(&packet_id);
            }
            Packet::V5(v5::Packet::PublishRelease(ack2)) => {
                log::debug!("{} PublishRelease: {:?}", self.id, ack2);
                let key = PacketRouteKey::new(PacketIssuer::Client, ack2.packet_id);
                self.accept_client_pubrel(ack2.packet_id, reply_path).await?;
                sink.send_publish_complete(SendTarget::Reply(reply_path), ack2.packet_id, None).await?;
                self.routes
                    .complete(
                        key,
                        TransactionFamily::PublishQos2,
                        TransactionStage::PublishQos2AwaitPubrel,
                        reply_path,
                    )
                    .map_err(Self::route_reason)?;
                self.in_inflight.write().await.remove(&ack2.packet_id);
            }

            Packet::V3(v3::Packet::PublishAck { packet_id }) => {
                self.routes
                    .complete(
                        PacketRouteKey::new(PacketIssuer::Server, packet_id),
                        TransactionFamily::PublishQos1,
                        TransactionStage::PublishQos1AwaitPuback,
                        reply_path,
                    )
                    .map_err(Self::route_reason)?;
                if let Some(iflt_msg) = self.out_inflight().write().await.remove(&packet_id.get()) {
                    //hook, message_ack
                    self.hook.message_acked(iflt_msg.from, &iflt_msg.publish).await;
                }
            }
            Packet::V5(v5::Packet::PublishAck(ack)) => {
                self.routes
                    .complete(
                        PacketRouteKey::new(PacketIssuer::Server, ack.packet_id),
                        TransactionFamily::PublishQos1,
                        TransactionStage::PublishQos1AwaitPuback,
                        reply_path,
                    )
                    .map_err(Self::route_reason)?;
                if let Some(iflt_msg) = self.out_inflight().write().await.remove(&ack.packet_id.get()) {
                    //hook, message_ack
                    self.hook.message_acked(iflt_msg.from, &iflt_msg.publish).await;
                }
            }

            Packet::V3(v3::Packet::PublishReceived { packet_id }) => {
                self.accept_server_pubrec(packet_id, reply_path)?;
                self.out_inflight().write().await.update_status(&packet_id.get(), MomentStatus::UnComplete);
                sink.send_publish_release(SendTarget::Reply(reply_path), packet_id, None).await?;
            }
            Packet::V5(v5::Packet::PublishReceived(ack)) => {
                self.accept_server_pubrec(ack.packet_id, reply_path)?;
                self.out_inflight()
                    .write()
                    .await
                    .update_status(&ack.packet_id.get(), MomentStatus::UnComplete);

                sink.send_publish_release(SendTarget::Reply(reply_path), ack.packet_id, None).await?;
            }

            Packet::V3(v3::Packet::PublishComplete { packet_id }) => {
                self.routes
                    .complete(
                        PacketRouteKey::new(PacketIssuer::Server, packet_id),
                        TransactionFamily::PublishQos2,
                        TransactionStage::PublishQos2AwaitPubcomp,
                        reply_path,
                    )
                    .map_err(Self::route_reason)?;
                if let Some(iflt_msg) = self.out_inflight().write().await.remove(&packet_id.get()) {
                    //hook, message_ack
                    self.hook.message_acked(iflt_msg.from, &iflt_msg.publish).await;
                }
            }
            Packet::V5(v5::Packet::PublishComplete(ack2)) => {
                self.routes
                    .complete(
                        PacketRouteKey::new(PacketIssuer::Server, ack2.packet_id),
                        TransactionFamily::PublishQos2,
                        TransactionStage::PublishQos2AwaitPubcomp,
                        reply_path,
                    )
                    .map_err(Self::route_reason)?;
                if let Some(iflt_msg) = self.out_inflight().write().await.remove(&ack2.packet_id.get()) {
                    //hook, message_ack
                    self.hook.message_acked(iflt_msg.from, &iflt_msg.publish).await;
                }
            }

            Packet::V3(v3::Packet::Subscribe { packet_id, topic_filters }) => {
                let key = PacketRouteKey::new(PacketIssuer::Client, packet_id);
                self.routes
                    .insert(
                        key,
                        TransactionFamily::Subscribe,
                        TransactionStage::SubscribeAwaitSuback,
                        reply_path,
                    )
                    .map_err(Self::route_reason)?;
                let (status, bound_filters) = match self.subscribes_v3(topic_filters).await {
                    Ok(outcome) => outcome,
                    Err(e) => {
                        log::warn!("{} Subscribe Refused, reason: {e}", self.id);
                        return Err(Reason::SubscribeFailed(Some(e.to_string().into())));
                    }
                };
                for topic_filter in &bound_filters {
                    self.subscription_bindings.begin(topic_filter.clone(), reply_path);
                }
                sink.send_subscribe_ack_v3(SendTarget::Reply(reply_path), packet_id, status).await?;
                for topic_filter in &bound_filters {
                    let _ = self.subscription_bindings.activate(topic_filter);
                }
                self.routes
                    .complete(
                        key,
                        TransactionFamily::Subscribe,
                        TransactionStage::SubscribeAwaitSuback,
                        reply_path,
                    )
                    .map_err(Self::route_reason)?;
            }
            Packet::V5(v5::Packet::Subscribe(subs)) => {
                let key = PacketRouteKey::new(PacketIssuer::Client, subs.packet_id);
                self.routes
                    .insert(
                        key,
                        TransactionFamily::Subscribe,
                        TransactionStage::SubscribeAwaitSuback,
                        reply_path,
                    )
                    .map_err(Self::route_reason)?;
                let (ack, bound_filters) = match self.subscribes_v5(subs).await {
                    Err(e) => {
                        log::warn!("{} Subscribe Refused, reason: {e}", self.id);
                        return Err(Reason::SubscribeFailed(Some(e.to_string().into())));
                    }
                    Ok(outcome) => outcome,
                };
                for topic_filter in &bound_filters {
                    self.subscription_bindings.begin(topic_filter.clone(), reply_path);
                }
                sink.send_subscribe_ack_v5(SendTarget::Reply(reply_path), ack).await?;
                for topic_filter in &bound_filters {
                    let _ = self.subscription_bindings.activate(topic_filter);
                }
                self.routes
                    .complete(
                        key,
                        TransactionFamily::Subscribe,
                        TransactionStage::SubscribeAwaitSuback,
                        reply_path,
                    )
                    .map_err(Self::route_reason)?;
            }

            Packet::V3(v3::Packet::Unsubscribe { packet_id, topic_filters }) => {
                let key = PacketRouteKey::new(PacketIssuer::Client, packet_id);
                self.routes
                    .insert(
                        key,
                        TransactionFamily::Unsubscribe,
                        TransactionStage::UnsubscribeAwaitUnsuback,
                        reply_path,
                    )
                    .map_err(Self::route_reason)?;
                let unbound_filters = self
                    .unsubscribes_v3(topic_filters)
                    .await
                    .map_err(|e| Reason::UnsubscribeFailed(Some(e.to_string().into())))?;
                sink.send_unsubscribe_ack_v3(SendTarget::Reply(reply_path), packet_id).await?;
                for topic_filter in &unbound_filters {
                    self.subscription_bindings.unsubscribe(topic_filter);
                }
                self.routes
                    .complete(
                        key,
                        TransactionFamily::Unsubscribe,
                        TransactionStage::UnsubscribeAwaitUnsuback,
                        reply_path,
                    )
                    .map_err(Self::route_reason)?;
            }

            Packet::V5(v5::Packet::Unsubscribe(unsubs)) => {
                let key = PacketRouteKey::new(PacketIssuer::Client, unsubs.packet_id);
                self.routes
                    .insert(
                        key,
                        TransactionFamily::Unsubscribe,
                        TransactionStage::UnsubscribeAwaitUnsuback,
                        reply_path,
                    )
                    .map_err(Self::route_reason)?;
                let (ack, unbound_filters) = match self.unsubscribes_v5(unsubs).await {
                    Err(e) => {
                        return Err(Reason::UnsubscribeFailed(Some(e.to_string().into())));
                    }
                    Ok(outcome) => outcome,
                };
                sink.send_unsubscribe_ack_v5(SendTarget::Reply(reply_path), ack).await?;
                for topic_filter in &unbound_filters {
                    self.subscription_bindings.unsubscribe(topic_filter);
                }
                self.routes
                    .complete(
                        key,
                        TransactionFamily::Unsubscribe,
                        TransactionStage::UnsubscribeAwaitUnsuback,
                        reply_path,
                    )
                    .map_err(Self::route_reason)?;
            }

            Packet::V3(v3::Packet::PingRequest) => {
                sink.send_ping_response(SendTarget::Reply(reply_path)).await?;
                flags.insert(StateFlags::Ping);
            }
            Packet::V5(v5::Packet::PingRequest) => {
                sink.send_ping_response(SendTarget::Reply(reply_path)).await?;
                flags.insert(StateFlags::Ping);
            }

            Packet::V3(v3::Packet::Disconnect) => {
                flags.insert(StateFlags::DisconnectReceived);
                self.disconnected_set(Some(Disconnect::V3), None).await?;
                // return Err(Reason::ConnectDisconnect(Some(Disconnect::V3)));
                return Ok(());
            }
            Packet::V5(v5::Packet::Disconnect(d)) => {
                flags.insert(StateFlags::DisconnectReceived);
                self.disconnected_set(Some(Disconnect::V5(d)), None).await?;
                // return Err(Reason::ConnectDisconnect(Some(Disconnect::V5(d))));
                return Ok(());
            }
            Packet::V5(v5::Packet::Auth(_)) => {
                sink.send_auth(SendTarget::Reply(reply_path), Auth::default()).await?;
                //@TODO Consider implementing Auth through hooks
            }
            _ => {
                return Err(format!("Received an unimplemented message, {pkt:?}").into());
            }
        }

        let is_ping = flags.contains(StateFlags::Ping);
        //hook, keepalive
        self.hook.client_keepalive(is_ping).await;
        self.keepalive(is_ping).await;
        if is_ping {
            flags.remove(StateFlags::Ping);
        }
        Ok(())
    }

    #[inline]
    fn last_will_enable(&self, flags: StateFlags, clean_session: bool) -> bool {
        let session_present =
            flags.contains(StateFlags::Kicked) && !flags.contains(StateFlags::CleanStart) && !clean_session;
        !(flags.contains(StateFlags::DisconnectReceived) || session_present)
    }

    #[inline]
    async fn will_delay_interval(&self) -> Option<Duration> {
        self.connect_info().await.ok()?.last_will().and_then(|lw| lw.will_delay_interval())
    }

    #[inline]
    async fn process_last_will(&self) -> Result<()> {
        if let Ok(conn_info) = self.connect_info().await {
            if let Some(lw) = conn_info.last_will() {
                let p = Publish::try_from(lw)?;
                let from = From::from_lastwill(self.id.clone());
                //hook, message_publish
                let p = self.hook.message_publish(from.clone(), &p).await.unwrap_or(p);
                log::debug!("process_last_will, publish: {p:?}");

                let message_storage_available = {
                    #[cfg(feature = "msgstore")]
                    {
                        self.scx.extends.message_mgr().await.enable()
                    }
                    #[cfg(not(feature = "msgstore"))]
                    {
                        false
                    }
                };

                #[cfg(feature = "retain")]
                let message_expiry_interval =
                    if message_storage_available || (p.retain && self.scx.extends.retain().await.enable()) {
                        Some(self.fitter.message_expiry_interval(&p))
                    } else {
                        None
                    };
                #[cfg(not(feature = "retain"))]
                let message_expiry_interval = if message_storage_available {
                    Some(self.fitter.message_expiry_interval(&p))
                } else {
                    None
                };

                Self::forwards(&self.scx, from, p, message_storage_available, message_expiry_interval)
                    .await?;
            }
        }

        Ok(())
    }

    #[inline]
    async fn clean_session(&self, d: Option<&Disconnect>) -> bool {
        self.connect_info()
            .await
            .map(|c| {
                if let ConnectInfo::V3(_, c) = c.as_ref() {
                    c.clean_session
                } else {
                    self.fitter.session_expiry_interval(d).is_zero()
                }
            })
            .unwrap_or(true)
    }

    #[inline]
    fn packet_id(packet_id: Option<NonZeroU16>) -> std::result::Result<NonZeroU16, Reason> {
        packet_id.ok_or_else(|| Reason::ProtocolError(ByteString::from_static("packet_id is None")))
    }

    #[inline]
    fn route_reason(error: impl std::fmt::Display) -> Reason {
        Reason::ProtocolError(error.to_string().into())
    }

    fn accept_server_pubrec(
        &mut self,
        packet_id: NonZeroU16,
        reply_path: ReplyPath,
    ) -> std::result::Result<(), Reason> {
        let key = PacketRouteKey::new(PacketIssuer::Server, packet_id);
        if self.routes.get(key).is_some_and(|entry| {
            entry.family() == TransactionFamily::PublishQos2
                && entry.stage() == TransactionStage::PublishQos2AwaitPubcomp
        }) {
            self.routes
                .validate(
                    key,
                    TransactionFamily::PublishQos2,
                    TransactionStage::PublishQos2AwaitPubcomp,
                    reply_path,
                )
                .map_err(Self::route_reason)?;
        } else {
            self.routes
                .transition(
                    key,
                    TransactionFamily::PublishQos2,
                    TransactionStage::PublishQos2AwaitPubrec,
                    TransactionStage::PublishQos2AwaitPubcomp,
                    reply_path,
                )
                .map_err(Self::route_reason)?;
        }
        Ok(())
    }

    #[inline]
    async fn process_publish<L>(
        &mut self,
        sink: &mut SessionLink<L>,
        publish: Publish,
        reply_path: ReplyPath,
    ) -> std::result::Result<(), Reason>
    where
        L: MqttLink,
    {
        let packet_id = publish.packet_id;
        let qos = publish.qos;

        match qos {
            QoS::AtLeastOnce => {
                let packet_id = Self::packet_id(packet_id)?;
                let route_key = PacketRouteKey::new(PacketIssuer::Client, packet_id);
                self.routes
                    .insert(
                        route_key,
                        TransactionFamily::PublishQos1,
                        TransactionStage::PublishQos1AwaitPuback,
                        reply_path,
                    )
                    .map_err(Self::route_reason)?;
                let inflight_result = {
                    let mut in_inflight = self.in_inflight.write().await;
                    in_inflight.add(packet_id, qos)
                };
                let inflight_res = match inflight_result {
                    Err(e) => {
                        self.routes.remove(route_key);
                        //hook, Message dropped
                        self.scx
                            .extends
                            .hook_mgr()
                            .message_dropped(None, From::from_custom(self.id.clone()), publish, e.clone())
                            .await;
                        return Err(e);
                    }
                    Ok(res) => res,
                };

                let pubres = match self.publish(publish).await {
                    Ok(pubres) => pubres,
                    Err(error) => {
                        self.routes.remove(route_key);
                        if inflight_res {
                            self.in_inflight.write().await.remove(&packet_id);
                        }
                        return Err(error.into());
                    }
                };

                let ack_res = sink.send_publish_ack(SendTarget::Reply(reply_path), packet_id, pubres).await;
                if inflight_res {
                    self.in_inflight.write().await.remove(&packet_id);
                }
                ack_res?;
                self.routes
                    .complete(
                        route_key,
                        TransactionFamily::PublishQos1,
                        TransactionStage::PublishQos1AwaitPuback,
                        reply_path,
                    )
                    .map_err(Self::route_reason)?;
            }
            QoS::ExactlyOnce => {
                let packet_id = Self::packet_id(packet_id)?;
                let route_key = PacketRouteKey::new(PacketIssuer::Client, packet_id);
                let resumed_await_pubrel = self.in_inflight.read().await.contains(&packet_id);
                let new_route = accept_client_qos2_publish_route(
                    &mut self.routes,
                    route_key,
                    reply_path,
                    publish.dup,
                    resumed_await_pubrel,
                )?;
                if !new_route {
                    sink.send_publish_received(
                        SendTarget::Reply(reply_path),
                        packet_id,
                        PublishResult::success(),
                    )
                    .await?;
                    return Ok(());
                }

                // Reserve Receive Maximum capacity before any business side effect. Once the
                // publish is accepted, this packet id must remain durable even if writing PUBREC
                // fails, so a persistent-session retry cannot publish the message a second time.
                let inflight_result = {
                    let mut in_inflight = self.in_inflight.write().await;
                    in_inflight.add(packet_id, qos)
                };
                let inflight_res = match inflight_result {
                    Ok(inflight) => inflight,
                    Err(error) => {
                        self.routes.remove(route_key);
                        self.scx
                            .extends
                            .hook_mgr()
                            .message_dropped(None, From::from_custom(self.id.clone()), publish, error.clone())
                            .await;
                        return Err(error);
                    }
                };
                let pub_res = match self.publish(publish).await {
                    Ok(pubres) => pubres,
                    Err(error) => {
                        self.routes.remove(route_key);
                        if inflight_res {
                            self.in_inflight.write().await.remove(&packet_id);
                        }
                        return Err(error.into());
                    }
                };
                let publish_accepted = pub_res.is_success();
                if !publish_accepted {
                    self.routes.remove(route_key);
                    if inflight_res {
                        self.in_inflight.write().await.remove(&packet_id);
                    }
                }
                sink.send_publish_received(SendTarget::Reply(reply_path), packet_id, pub_res).await?;
            }
            QoS::AtMostOnce => {
                self.publish(publish).await?;
            }
        }
        Ok(())
    }

    #[inline]
    async fn publish(&self, publish: Publish) -> Result<PublishResult> {
        match self._publish(publish).await {
            Err(e) => {
                #[cfg(feature = "metrics")]
                self.scx.metrics.client_publish_error_inc();
                Err(e)
            }
            Ok(pub_res) => {
                if pub_res.is_success() {
                    Ok(pub_res)
                } else {
                    #[cfg(feature = "metrics")]
                    self.scx.metrics.client_publish_error_inc();
                    match pub_res.disconnect {
                        true => Err(MqttError::PublishAckReason(
                            pub_res.reason_code,
                            pub_res.reason_string.unwrap_or_default(),
                        )
                        .into()),
                        false => Ok(pub_res),
                    }
                }
            }
        }
    }

    #[inline]
    async fn _publish(&self, mut publish: Publish) -> Result<PublishResult> {
        if self.topic_alias_forbidden
            && publish.properties.as_ref().and_then(|properties| properties.topic_alias).is_some()
        {
            return Err(MqttError::PublishAckReason(
                v5::PublishAckReason::ImplementationSpecificError,
                "Topic Alias is disabled for MQTT over QUIC simple-v1 multistream".into(),
            )
            .into());
        }
        if let Some(client_topic_aliases) = &self.client_topic_aliases {
            publish.deref_mut().topic = client_topic_aliases
                .set_and_get(publish.properties.as_ref().and_then(|p| p.topic_alias), publish.topic.clone())
                .await?;
        }

        let from = From::from_custom(self.id.clone());

        #[cfg(feature = "delayed")]
        if self.listen_cfg().delayed_publish {
            publish = self.scx.extends.delayed_sender().await.parse(publish)?;
        }

        //hook, message_publish
        let publish = self.hook.message_publish(from.clone(), &publish).await.unwrap_or(publish);

        //hook, message_publish_check_acl
        let acl_result = self.hook.message_publish_check_acl(&publish).await;
        log::debug!("{:?} acl_result: {:?}", self.id, acl_result);
        if !acl_result.is_allow() {
            #[cfg(feature = "metrics")]
            self.scx.metrics.client_publish_auth_error_inc();

            let pub_res = acl_result.pub_res();
            let reason = Reason::PublishResult(pub_res.clone());

            //hook, Message dropped
            self.scx.extends.hook_mgr().message_dropped(None, from, publish, reason).await;

            return if pub_res.disconnect {
                Err(MqttError::PublishAckReason(
                    pub_res.reason_code,
                    pub_res.reason_string.unwrap_or_default(),
                )
                .into())
            } else {
                Ok(pub_res)
            };
        }

        let message_storage_available = {
            #[cfg(feature = "msgstore")]
            {
                self.scx.extends.message_mgr().await.enable()
            }
            #[cfg(not(feature = "msgstore"))]
            {
                false
            }
        };

        let message_expiry_interval = if message_storage_available
            || (publish.retain && {
                #[cfg(feature = "retain")]
                {
                    self.scx.extends.retain().await.enable()
                }
                #[cfg(not(feature = "retain"))]
                {
                    false
                }
            }) {
            Some(self.fitter.message_expiry_interval(&publish))
        } else {
            None
        };

        Self::forwards(&self.scx, from, publish, message_storage_available, message_expiry_interval).await?;

        Ok(PublishResult::success())
    }

    #[inline]
    async fn subscribes_v3(
        &mut self,
        topic_filters: Vec<(ByteString, QoS)>,
    ) -> Result<(Vec<v3::SubscribeReturnCode>, Vec<crate::topic::Topic>)> {
        #[allow(unused_variables)]
        let listen_cfg = self.listen_cfg();
        let shared_subscription = {
            #[cfg(feature = "shared-subscription")]
            {
                self.scx.extends.shared_subscription().await.is_supported(listen_cfg)
            }
            #[cfg(not(feature = "shared-subscription"))]
            {
                false
            }
        };

        let limit_subscription = {
            #[cfg(feature = "limit-subscription")]
            {
                listen_cfg.limit_subscription
            }
            #[cfg(not(feature = "limit-subscription"))]
            {
                false
            }
        };

        let mut acks = Vec::new();
        let mut bound_filters = Vec::new();
        for (topic_filter, qos) in topic_filters {
            let s = Subscribe::from_v3(&topic_filter, qos, shared_subscription, limit_subscription)?;
            match self.subscribe_outcome(s).await {
                Ok(outcome) => {
                    if let Some(qos) = outcome.reply.success() {
                        acks.push(v3::SubscribeReturnCode::Success(qos))
                    } else {
                        acks.push(v3::SubscribeReturnCode::Failure)
                    }
                    if let Some(topic_filter) = outcome.topic_filter {
                        bound_filters
                            .push(crate::topic::Topic::from_str(AsRef::<str>::as_ref(&topic_filter))?);
                    }
                }
                Err(e) => {
                    log::warn!("{:?} Subscribe failed, {:?}", self.id, e);
                    acks.push(v3::SubscribeReturnCode::Failure)
                }
            }
        }
        Ok((acks, bound_filters))
    }

    #[inline]
    async fn subscribes_v5(
        &mut self,
        subs: v5::Subscribe,
    ) -> Result<(v5::SubscribeAck, Vec<crate::topic::Topic>)> {
        #[allow(unused_variables)]
        let listen_cfg = self.listen_cfg();
        let shared_subscription = {
            #[cfg(feature = "shared-subscription")]
            {
                self.scx.extends.shared_subscription().await.is_supported(listen_cfg)
            }
            #[cfg(not(feature = "shared-subscription"))]
            {
                false
            }
        };

        let limit_subscription = {
            #[cfg(feature = "limit-subscription")]
            {
                listen_cfg.limit_subscription
            }
            #[cfg(not(feature = "limit-subscription"))]
            {
                false
            }
        };

        let sub_id = subs.id;

        let mut status: Vec<SubscribeAckReason> = Vec::new();
        let mut bound_filters = Vec::new();

        for (topic_filter, opts) in &subs.topic_filters {
            let s = Subscribe::from_v5(topic_filter, opts, shared_subscription, limit_subscription, sub_id)?;
            match self.subscribe_outcome(s).await {
                Ok(outcome) => {
                    if let Some(topic_filter) = outcome.topic_filter {
                        bound_filters
                            .push(crate::topic::Topic::from_str(AsRef::<str>::as_ref(&topic_filter))?);
                    }
                    status.push(outcome.reply.into_inner());
                }
                Err(e) => {
                    log::warn!("{:?} Subscribe failed, {:?}", self.id, e);
                    status.push(SubscribeAckReason::UnspecifiedError);
                }
            }
        }
        Ok((
            v5::SubscribeAck {
                status,
                packet_id: subs.packet_id,
                properties: v5::UserProperties::default(),
                reason_string: None,
            },
            bound_filters,
        ))
    }

    #[inline]
    async fn unsubscribes_v3(&mut self, topic_filters: Vec<ByteString>) -> Result<Vec<crate::topic::Topic>> {
        let listen_cfg = self.listen_cfg();
        let shared_subscription = {
            #[cfg(feature = "shared-subscription")]
            {
                self.scx.extends.shared_subscription().await.is_supported(listen_cfg)
            }
            #[cfg(not(feature = "shared-subscription"))]
            {
                false
            }
        };
        let limit_subscription = listen_cfg.limit_subscription;
        let mut unbound_filters = Vec::new();
        for topic_filter in &topic_filters {
            let unsub = Unsubscribe::from(topic_filter, shared_subscription, limit_subscription)?;
            let topic_filter = self.unsubscribe_outcome(unsub).await?;
            unbound_filters.push(crate::topic::Topic::from_str(AsRef::<str>::as_ref(&topic_filter))?);
        }
        Ok(unbound_filters)
    }

    async fn unsubscribes_v5(
        &mut self,
        unsubs: v5::Unsubscribe,
    ) -> Result<(v5::UnsubscribeAck, Vec<crate::topic::Topic>)> {
        let listen_cfg = self.listen_cfg();
        let shared_subscription = {
            #[cfg(feature = "shared-subscription")]
            {
                self.scx.extends.shared_subscription().await.is_supported(listen_cfg)
            }
            #[cfg(not(feature = "shared-subscription"))]
            {
                false
            }
        };
        let limit_subscription = listen_cfg.limit_subscription;
        let mut unbound_filters = Vec::new();
        for topic_filter in &unsubs.topic_filters {
            let unsub = Unsubscribe::from(topic_filter, shared_subscription, limit_subscription)?;
            let topic_filter = self.unsubscribe_outcome(unsub).await?;
            unbound_filters.push(crate::topic::Topic::from_str(AsRef::<str>::as_ref(&topic_filter))?);
        }

        let mut status = Vec::with_capacity(unsubs.topic_filters.len());
        (0..unsubs.topic_filters.len()).for_each(|_| status.push(v5::UnsubscribeAckReason::Success));

        let ack = v5::UnsubscribeAck {
            status,
            packet_id: unsubs.packet_id,
            properties: v5::UserProperties::default(),
            reason_string: None,
        };
        Ok((ack, unbound_filters))
    }

    #[inline]
    async fn unsubscribe(&self, unsub: Unsubscribe) -> Result<()> {
        self.unsubscribe_outcome(unsub).await.map(|_| ())
    }

    #[inline]
    async fn unsubscribe_outcome(&self, mut unsub: Unsubscribe) -> Result<TopicFilter> {
        log::debug!("{:?} unsubscribe: {:?}", self.id, unsub);
        //hook, client_unsubscribe
        let topic_filter = self.hook.client_unsubscribe(&unsub).await;
        if let Some(topic_filter) = topic_filter {
            unsub.topic_filter = topic_filter;
            log::debug!("{:?} adjust topic_filter: {:?}", self.id, unsub.topic_filter);
        }
        let ok = self.scx.extends.shared().await.entry(self.id.clone()).unsubscribe(&unsub).await?;
        if ok {
            //hook, session_unsubscribed
            self.hook.session_unsubscribed(unsub.clone()).await;
        }
        Ok(unsub.topic_filter)
    }

    #[inline]
    #[allow(clippy::type_complexity)]
    fn deliver_queue_channel<'a>(
        &mut self,
        limiter: &'a Limiter,
    ) -> (queue::Sender<(From, Publish)>, queue::Receiver<'a, (From, Publish)>) {
        let (deliver_queue_tx, deliver_queue_rx) = limiter.channel(self.deliver_queue().clone());
        //When the message queue is full, the message dropping policy is implemented
        let deliver_queue_tx = deliver_queue_tx.policy(|(_, p): &(From, Publish)| -> Policy {
            if let QoS::AtMostOnce = p.qos {
                Policy::Current
            } else {
                Policy::Early
            }
        });
        (deliver_queue_tx, deliver_queue_rx)
    }

    #[inline]
    pub(crate) async fn subscribe(&self, sub: Subscribe) -> Result<SubscribeReturn> {
        self.subscribe_outcome(sub).await.map(|outcome| outcome.reply)
    }

    #[inline]
    async fn subscribe_outcome(&self, sub: Subscribe) -> Result<SubscribeOutcome> {
        let outcome = self._subscribe(sub).await;
        if let Ok(outcome) = &outcome {
            match outcome.reply.ack_reason {
                SubscribeAckReason::NotAuthorized => {
                    #[cfg(feature = "metrics")]
                    self.scx.metrics.client_subscribe_auth_error_inc();
                }
                SubscribeAckReason::GrantedQos0
                | SubscribeAckReason::GrantedQos1
                | SubscribeAckReason::GrantedQos2 => {}
                _ => {
                    #[cfg(feature = "metrics")]
                    self.scx.metrics.client_subscribe_error_inc();
                }
            }
        } else {
            #[cfg(feature = "metrics")]
            self.scx.metrics.client_subscribe_error_inc();
        }
        outcome
    }

    #[inline]
    async fn _subscribe(&self, mut sub: Subscribe) -> Result<SubscribeOutcome> {
        let listen_cfg = self.listen_cfg();

        if listen_cfg.max_subscriptions > 0
            && (self.subscriptions().await?.len().await >= listen_cfg.max_subscriptions)
        {
            return Err(MqttError::TooManySubscriptions.into());
        }

        if listen_cfg.max_topic_levels > 0
            && Topic::from_str(&sub.topic_filter)?.len() > listen_cfg.max_topic_levels
        {
            return Err(MqttError::TooManyTopicLevels.into());
        }

        #[cfg(feature = "limit-subscription")]
        if let Some(limit) = sub.opts.limit_subs() {
            let (allow, count) = self
                .scx
                .extends
                .router()
                .await
                .relations()
                .get(&sub.topic_filter)
                .map(|rels| {
                    if rels.value().contains_key(&self.id.client_id) {
                        (true, rels.value().len() - 1)
                    } else {
                        let c = rels.value().len();
                        (c < limit, c)
                    }
                })
                .unwrap_or((true, 0));
            if !allow {
                return Err(MqttError::SubscribeLimited(format!(
                    "limited: {}, current count: {}, topic_filter: {}",
                    limit, count, sub.topic_filter
                ))
                .into());
            }
        }

        sub.opts.set_qos(sub.opts.qos().less_value(listen_cfg.max_qos_allowed));

        //hook, client_subscribe
        let topic_filter = self.hook.client_subscribe(&sub).await;
        log::debug!("{:?} topic_filter: {:?}", self.id, topic_filter);

        //adjust topic filter
        if let Some(topic_filter) = topic_filter {
            sub.topic_filter = topic_filter;
        }

        //hook, client_subscribe_check_acl
        let acl_result = self.hook.client_subscribe_check_acl(&sub).await;
        if let Some(acl_result) = acl_result {
            if let Some(qos) = acl_result.success() {
                sub.opts.set_qos(sub.opts.qos().less_value(qos))
            } else {
                return Ok(SubscribeOutcome { reply: acl_result, topic_filter: None });
            }
        }

        //subscribe
        let sub_ret = self.scx.extends.shared().await.entry(self.id.clone()).subscribe(&sub).await?;

        let bound_topic_filter = sub_ret.success().map(|_| sub.topic_filter.clone());
        #[allow(unused_variables)]
        if let Some(qos) = sub_ret.success() {
            #[cfg(any(feature = "retain", feature = "msgstore"))]
            {
                //send retain messages + sent storaged messages (fire-and-forget)
                let scx = self.scx.clone();
                let id = self.id.clone();
                let sub_topic_filter = sub.topic_filter.clone();
                let sub_shared_group = sub.opts.shared_group().cloned();
                let retain_handling = sub.opts.retain_handling();
                let prev_opts_is_none = sub_ret.prev_opts.is_none();
                tokio::spawn(async move {
                    _send_subscribe_messages(
                        scx,
                        id,
                        sub_topic_filter,
                        sub_shared_group,
                        retain_handling,
                        prev_opts_is_none,
                        qos,
                    )
                    .await;
                });
            }
            //hook, session_subscribed
            self.hook.session_subscribed(sub).await;
        }

        Ok(SubscribeOutcome { reply: sub_ret, topic_filter: bound_topic_filter })
    }

    #[inline]
    async fn transfer_session_state<L>(
        &mut self,
        sink: &mut SessionLink<L>,
        clear_subscriptions: bool,
        mut offline_info: OfflineInfo,
    ) -> Result<()>
    where
        L: MqttLink,
    {
        log::debug!(
                "{:?} transfer session state, form: {:?}, subscriptions: {}, inflight_messages: {}, offline_messages: {}, clear_subscriptions: {}",
                self.id,
                offline_info.id,
                offline_info.subscriptions.len(),
                offline_info.inflight_messages.len(),
                offline_info.offline_messages.len(),
                clear_subscriptions
            );
        if !clear_subscriptions && !offline_info.subscriptions.is_empty() {
            for (tf, opts) in offline_info.subscriptions.iter() {
                let id = self.id.clone();
                log::debug!(
                    "{id:?} transfer_session_state, router.add ... topic_filter: {tf:?}, opts: {opts:?}"
                );
                if let Err(e) = self.scx.extends.router().await.add(tf, id, opts.clone()).await {
                    log::warn!("transfer_session_state, router.add, {e}");
                }

                //Send messages before they expire
                #[cfg(feature = "msgstore")]
                if let Err(e) =
                    self.send_storaged_messages(tf.clone(), opts.qos(), opts.shared_group(), None).await
                {
                    log::warn!("transfer_session_state, router.add, {e}");
                }
            }
        }

        //Subscription transfer from previous session
        if !clear_subscriptions {
            self.subscriptions_extend(offline_info.subscriptions).await?;
        }

        //Send previous session unacked messages
        while let Some(msg) = offline_info.inflight_messages.pop() {
            if let Err(e) = self.reforward(sink, msg).await {
                log::warn!("transfer_session_state, reforward error, {e}");
            }
        }

        //Send offline messages
        while let Some((from, p)) = offline_info.offline_messages.pop_front() {
            self.forward(from, p).await;
        }
        Ok(())
    }

    #[inline]
    #[cfg(feature = "msgstore")]
    async fn send_storaged_messages(
        &self,
        topic_filter: TopicFilter,
        qos: QoS,
        group: Option<&SharedGroup>,
        excludeds: Option<Vec<(NodeId, MsgID)>>,
    ) -> Result<()> {
        let scx = self.scx.clone();
        let group = group.cloned();
        let id = self.id.clone();
        tokio::spawn(async move {
            let now = std::time::Instant::now();
            let handler = SendStoragedMessagesHandler {
                scx: scx.clone(),
                id: id.clone(),
                qos,
                excludeds,
                topic_filter: topic_filter.clone(),
                group: group.clone(),
            };
            if let Err(e) = scx
                .extends
                .shared()
                .await
                .message_load_with(&id.client_id, &topic_filter, group.as_ref(), Arc::new(handler))
                .await
            {
                log::warn!("message_load_with failed, {e}");
            }
            let elaps = now.elapsed();
            if elaps.as_secs() > 3 {
                log::warn!("message_load_with cost time: {:?}", elaps);
            }
        });
        Ok(())
    }

    #[inline]
    async fn deliver<L>(&mut self, sink: &mut SessionLink<L>, from: From, mut publish: Publish) -> Result<()>
    where
        L: MqttLink,
    {
        //hook, message_expiry_check
        let expiry_check_res = self.hook.message_expiry_check(from.clone(), &publish).await;
        if expiry_check_res.is_expiry() {
            if publish.dup {
                if let Some(packet_id) = publish.packet_id {
                    self.routes.remove(PacketRouteKey::new(PacketIssuer::Server, packet_id));
                }
            }
            self.scx
                .extends
                .hook_mgr()
                .message_dropped(Some(self.id.clone()), from, publish, Reason::MessageExpiration)
                .await;
            return Ok(());
        }

        //generate packet_id
        if matches!(publish.qos, QoS::AtLeastOnce | QoS::ExactlyOnce)
            && (!publish.dup || publish.packet_id.is_none())
        {
            publish.packet_id = NonZeroU16::new(self.out_inflight().read().await.next_id()?)
        }
        let retry_identity = publish.dup.then_some((publish.qos, publish.packet_id));

        //hook, message_delivered
        let publish = self.hook.message_delivered(from.clone(), &publish).await.unwrap_or(publish);
        if let Some((qos, packet_id)) = retry_identity {
            if !publish.dup || publish.qos != qos || publish.packet_id != packet_id {
                return Err(anyhow::anyhow!(
                    "message_delivered hook changed MQTT transaction identity during retry"
                ));
            }
        }

        let transaction = match publish.qos {
            QoS::AtLeastOnce => Some((
                PacketRouteKey::new(
                    PacketIssuer::Server,
                    publish.packet_id.ok_or_else(|| anyhow::anyhow!("packet_id is None"))?,
                ),
                TransactionFamily::PublishQos1,
                TransactionStage::PublishQos1AwaitPuback,
                MomentStatus::UnAck,
            )),
            QoS::ExactlyOnce => Some((
                PacketRouteKey::new(
                    PacketIssuer::Server,
                    publish.packet_id.ok_or_else(|| anyhow::anyhow!("packet_id is None"))?,
                ),
                TransactionFamily::PublishQos2,
                TransactionStage::PublishQos2AwaitPubrec,
                MomentStatus::UnReceived,
            )),
            QoS::AtMostOnce => None,
        };
        let existing_route = resolve_existing_outbound_route(&self.routes, transaction, publish.dup)?;

        //send message
        let target = existing_route
            .map(SendTarget::Reply)
            .or_else(|| {
                self.subscription_bindings.route(AsRef::<str>::as_ref(&publish.topic)).map(SendTarget::Reply)
            })
            .unwrap_or(SendTarget::Control);
        let send_result = sink
            .publish(
                target,
                publish.clone(),
                expiry_check_res.message_expiry_interval(),
                self.server_topic_aliases.as_ref(),
            )
            .await;
        let receipt = match send_result {
            Ok(receipt) => receipt,
            Err(error)
                if publish.qos == QoS::AtMostOnce
                    && matches!(target, SendTarget::Reply(path) if path.flow_id() != crate::net::FlowId::CONTROL) =>
            {
                if let SendTarget::Reply(path) = target {
                    self.subscription_bindings.remove_flow(path.flow_id());
                    let _ = sink.reset_flow(path.flow_id(), FlowCloseReason::SendFailed).await;
                }
                self.scx
                    .extends
                    .hook_mgr()
                    .message_dropped(Some(self.id.clone()), from, publish, Reason::ConnectReadWriteError)
                    .await;
                log::debug!("isolated QoS 0 data-flow send failure: {error}");
                return Ok(());
            }
            Err(error) => return Err(error),
        }; //@TODO ... at exception, send hook and or store message

        //cache messages to inflight window
        if let Some((key, family, stage, moment_status)) = transaction {
            self.routes
                .insert_or_validate_duplicate(key, family, stage, receipt.path(), publish.dup)
                .map_err(|error| anyhow::anyhow!(error))?;
            self.out_inflight().write().await.push_back(OutInflightMessage::new(
                moment_status,
                from,
                publish,
            ));
        }

        Ok(())
    }

    #[inline]
    async fn reforward<L>(
        &mut self,
        sink: &mut SessionLink<L>,
        mut iflt_msg: OutInflightMessage,
    ) -> std::result::Result<(), Reason>
    where
        L: MqttLink,
    {
        match iflt_msg.status {
            MomentStatus::UnAck => {
                iflt_msg.publish.dup = true;
                self.deliver(sink, iflt_msg.from, iflt_msg.publish).await?;
            }
            MomentStatus::UnReceived => {
                iflt_msg.publish.dup = true;
                self.deliver(sink, iflt_msg.from, iflt_msg.publish).await?;
            }
            MomentStatus::UnComplete => {
                let expiry_check_res =
                    self.hook.message_expiry_check(iflt_msg.from.clone(), &iflt_msg.publish).await;

                if expiry_check_res.is_expiry() {
                    if let Some(packet_id) = iflt_msg.publish.packet_id {
                        self.routes.remove(PacketRouteKey::new(PacketIssuer::Server, packet_id));
                    }
                    log::warn!(
                        "{:?} MQTT::PublishComplete is not received, from: {:?}, message: {:?}",
                        self.id,
                        iflt_msg.from,
                        iflt_msg.publish
                    );
                    return Ok(());
                }

                self.send_rerelease(sink, iflt_msg).await?;
            }
        }
        Ok(())
    }

    #[inline]
    async fn send_rerelease<L>(
        &mut self,
        sink: &mut SessionLink<L>,
        iflt_msg: OutInflightMessage,
    ) -> std::result::Result<(), Reason>
    where
        L: MqttLink,
    {
        let packet_id = Self::packet_id(iflt_msg.publish.packet_id)?;
        self.out_inflight().write().await.push_back(OutInflightMessage::new(
            MomentStatus::UnComplete,
            iflt_msg.from,
            iflt_msg.publish,
        ));

        let route_key = PacketRouteKey::new(PacketIssuer::Server, packet_id);
        let target = if let Some(route) = self.routes.get(route_key) {
            self.routes
                .transition(
                    route_key,
                    TransactionFamily::PublishQos2,
                    TransactionStage::PublishQos2AwaitPubcomp,
                    TransactionStage::PublishQos2AwaitPubcomp,
                    route.path(),
                )
                .map_err(Self::route_reason)?;
            SendTarget::Reply(route.path())
        } else {
            SendTarget::Control
        };
        let receipt = sink.send_publish_release(target, packet_id, None).await?;
        if self.routes.get(route_key).is_none() {
            self.routes
                .insert(
                    route_key,
                    TransactionFamily::PublishQos2,
                    TransactionStage::PublishQos2AwaitPubcomp,
                    receipt.path(),
                )
                .map_err(Self::route_reason)?;
        }
        Ok(())
    }

    #[inline]
    pub(crate) async fn forward(&self, from: From, p: Publish) {
        let res = if let Err(e) = self.tx.try_send(Message::Forward(from, p)) {
            let reason = if e.is_full() {
                Reason::MessageQueueFull
            } else {
                Reason::from("Send Publish message error, Tx is closed")
            };
            if let Message::Forward(from, p) = e.into_inner() {
                Err((from, p, reason))
            } else {
                Ok(())
            }
        } else {
            Ok(())
        };

        if let Err((from, p, reason)) = res {
            //hook, message_dropped
            self.scx.extends.hook_mgr().message_dropped(Some(self.id.clone()), from, p, reason).await;
        }
    }

    #[inline]
    pub(crate) async fn clean(&self, deliver_queue_tx: &MessageSender, reason: Reason) {
        log::debug!("{:?} clean, reason: {:?}", self.id, reason);

        //Session expired, discarding messages in deliver queue
        while let Some((from, publish)) = deliver_queue_tx.pop() {
            log::debug!("{:?} clean.dropped, from: {:?}, publish: {:?}", self.id, from, publish);
            //hook, message dropped
            self.scx
                .extends
                .hook_mgr()
                .message_dropped(Some(self.id.clone()), from, publish, reason.clone())
                .await;
        }

        //Session expired, discarding messages in the flight window
        while let Some(iflt_msg) = self.out_inflight().write().await.pop_front() {
            log::debug!(
                "{:?} clean.dropped, from: {:?}, publish: {:?}",
                self.id,
                iflt_msg.from,
                iflt_msg.publish
            );

            //hook, message dropped
            self.scx
                .extends
                .hook_mgr()
                .message_dropped(Some(self.id.clone()), iflt_msg.from, iflt_msg.publish, reason.clone())
                .await;
        }

        //hook, session terminated
        self.hook.session_terminated(reason).await;

        //clear session, and unsubscribe
        let mut entry = self.scx.extends.shared().await.entry(self.id.clone());
        if let Some(true) = entry.id_same() {
            if let Err(e) = entry.remove_with(&self.id).await {
                log::warn!("{:?} Failed to remove the session from the broker, {:?}", self.id, e);
            }
        }
    }

    /// Forwards a `PUBLISH` message from a client to all subscribed clients.
    ///
    /// Handles:
    /// - Retain logic (if `retain` feature is enabled)
    /// - Message ID assignment and storage (if `msgstore` feature is enabled)
    /// - Delivery to shared and individual subscribers
    /// - Hook callbacks for dropped or unsubscribed messages
    ///
    /// # Arguments
    ///
    /// * `scx` - The server context containing shared resources.
    /// * `from` - Represents the sender client information.
    /// * `publish` - The message to forward.
    /// * `message_storage_available` - Indicates whether message storage is available (conditional).
    /// * `message_expiry_interval` - Optional expiration interval for the message.
    ///
    /// # Returns
    ///
    /// A `Result<()>` indicating success or failure.
    ///
    #[inline]
    pub async fn forwards(
        scx: &ServerContext,
        from: From,
        publish: Publish,
        #[allow(unused_variables)] message_storage_available: bool,
        #[allow(unused_variables)] message_expiry_interval: Option<Duration>,
    ) -> Result<()> {
        //delayed publish
        #[cfg(feature = "delayed")]
        if publish.delay_interval.is_some() {
            if let Some((f, p)) = scx
                .extends
                .delayed_sender()
                .await
                .delay_publish(from, publish, message_storage_available, message_expiry_interval)
                .await?
            {
                if scx.mqtt_delayed_publish_immediate {
                    Self::inner_forwards(scx, f, p, message_storage_available, message_expiry_interval)
                        .await?;
                } else {
                    //hook, Message dropped
                    scx.extends.hook_mgr().message_dropped(None, f, p, Reason::DelayedPublishRefused).await;
                    return Ok(());
                }
            }
            return Ok(());
        }

        Self::inner_forwards(scx, from, publish, message_storage_available, message_expiry_interval).await
    }

    #[inline]
    pub(crate) async fn inner_forwards(
        scx: &ServerContext,
        from: From,
        publish: Publish,
        #[allow(unused_variables)] message_storage_available: bool,
        #[allow(unused_variables)] message_expiry_interval: Option<Duration>,
    ) -> Result<()> {
        log::debug!("{from:?}");
        log::debug!("{publish:?}");
        //make message id
        #[cfg(feature = "msgstore")]
        let msg_id = if message_storage_available {
            Some(scx.extends.message_mgr().await.next_msg_id())
        } else {
            None
        };
        #[allow(unused_variables)]
        #[cfg(not(feature = "msgstore"))]
        let msg_id: Option<MsgID> = None;

        #[cfg(feature = "retain")]
        {
            let retain = scx.extends.retain().await;
            if retain.enable() && publish.retain {
                let retain_msg = Retain { msg_id, from: from.clone(), publish: publish.clone() };
                retain.set(&publish.topic, retain_msg.clone(), message_expiry_interval).await?;
                let _ = scx
                    .extends
                    .shared()
                    .await
                    .retain_set_broadcast(&publish.topic, &retain_msg, message_expiry_interval)
                    .await;
            }
            drop(retain);
        }
        // Store FIRST (subscriber IDs will be recorded inside forwards()
        // via mark_forwarded), ensuring subscriber tracking is tied
        // to the forwarding result rather than deferred to a later store().
        #[cfg(feature = "msgstore")]
        if let (Some(msg_id), Some(message_expiry_interval)) = (msg_id, message_expiry_interval) {
            if let Err(e) = scx
                .extends
                .message_mgr()
                .await
                .store(msg_id, from.clone(), publish.clone(), message_expiry_interval, None)
                .await
            {
                log::warn!("Failed to storage messages, {e}");
            }
        }

        match scx.extends.shared().await.forwards(msg_id, from.clone(), publish).await {
            Ok(0) => {
                //hook, message_nonsubscribed
                scx.extends.hook_mgr().message_nonsubscribed(from).await;
            }
            Ok(_count) => {}
            Err((_subscriber_count, errs)) => {
                for (to, from, p, reason) in errs {
                    //hook, Message dropped
                    scx.extends.hook_mgr().message_dropped(Some(to), from, p, reason).await;
                }
            }
        };

        Ok(())
    }
}

/// Thread-safe handle to an MQTT session.
///
/// Wraps an `Arc<_Session>` for efficient cloning and shared access.
/// Derefs to `_Session` for field and method access.
#[derive(Clone)]
pub struct Session(Arc<_Session>);

impl Deref for Session {
    type Target = _Session;
    #[inline]
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

/// Internal session data shared across all [`Session`] clones.
///
/// Holds the client identifier, connection metadata, hook references,
/// authentication info, topic alias tables, and the underlying
/// [`SessionLike`] trait object that implements session behavior.
pub struct _Session {
    inner: Arc<dyn SessionLike>,
    pub id: Id,
    pub fitter: FitterType,
    pub auth_info: Option<AuthInfo>,
    in_inflight: InInflightType,
    pub extra_attrs: Arc<RwLock<ExtraAttrs>>,
    pub scx: ServerContext,
}

impl Deref for _Session {
    type Target = dyn SessionLike;
    #[inline]
    fn deref(&self) -> &Self::Target {
        self.inner.as_ref()
    }
}

impl Drop for _Session {
    fn drop(&mut self) {
        // #[cfg(feature = "stats")]
        self.scx.sessions.dec();
        let id = self.id.clone();
        let s = self.inner.clone();
        tokio::spawn(async move {
            if let Err(e) = s.on_drop().await {
                log::error!("{id:?} session clear error, {e}");
            }
        });
    }
}

impl fmt::Debug for Session {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Session {:?}", self.id)
    }
}

#[inline]
#[cfg(feature = "msgstore")]
async fn _send_storaged_messages(
    scx: &ServerContext,
    id: Id,
    storaged_messages: Vec<(MsgID, From, Publish)>,
    qos: QoS,
    excludeds: Option<Vec<(NodeId, MsgID)>>,
    topic_filter: &str,
    group: Option<&SharedGroup>,
) {
    for (msg_id, from, mut publish) in storaged_messages {
        log::debug!(
            "{:?} msg_id: {}, from:{:?}, publish:{:?}, excluded: {}",
            id,
            msg_id,
            from,
            publish,
            excludeds
                .as_ref()
                .map(|excludeds| excludeds.contains(&(from.node_id, msg_id)))
                .unwrap_or_default()
        );
        if excludeds.as_ref().map(|excludeds| excludeds.contains(&(from.node_id, msg_id))).unwrap_or_default()
        {
            continue;
        }

        let from_node_id = from.node_id;

        publish.dup = false;
        publish.retain = false;
        publish.qos = publish.qos.less_value(qos);
        publish.packet_id = None;

        log::debug!("{:?} persistent.publish: {:?}", id, publish);

        if let Err((from, p, reason)) =
            scx.extends.shared().await.entry(id.clone()).publish(from, publish).await
        {
            scx.extends.hook_mgr().message_dropped(Some(id.clone()), from, p, reason).await;
        } else {
            // Record successful delivery so the message is not
            // redelivered on next reconnect. The node_id check is
            // handled inside the shared implementation.
            let opts = group.map(|g| (TopicFilter::from(topic_filter), g.clone()));
            if let Err(e) = scx
                .extends
                .shared()
                .await
                .message_mark_forwarded(from_node_id, msg_id, vec![(id.client_id.clone(), opts)])
                .await
            {
                log::warn!("{:?} mark_forwarded error: {e}", id);
            }
        }
    }
}

/// Handler for [`MessageLoadCallback`] used by [`send_storaged_messages`].
#[cfg(feature = "msgstore")]
struct SendStoragedMessagesHandler {
    scx: ServerContext,
    id: Id,
    qos: QoS,
    excludeds: Option<Vec<(NodeId, MsgID)>>,
    topic_filter: TopicFilter,
    group: Option<SharedGroup>,
}

#[cfg(feature = "msgstore")]
#[async_trait]
impl MessageLoadCallback for SendStoragedMessagesHandler {
    async fn on_messages(&self, msgs: Vec<(MsgID, From, Publish)>) -> Result<()> {
        _send_storaged_messages(
            &self.scx,
            self.id.clone(),
            msgs,
            self.qos,
            self.excludeds.clone(),
            &self.topic_filter,
            self.group.as_ref(),
        )
        .await;
        Ok(())
    }
}

/// Sends retain messages to a subscriber, adjusting fields as needed.
///
/// # Arguments
/// * `scx` - The server context.
/// * `id` - The subscriber's session ID.
/// * `retains` - The retain messages to send.
/// * `qos` - The maximum QoS to use.
#[cfg(feature = "retain")]
#[inline]
async fn _send_retain_messages(
    scx: &ServerContext,
    id: &Id,
    retains: Vec<(TopicName, Retain)>,
    qos: QoS,
) -> Result<()> {
    for (topic, mut retain) in retains {
        log::debug!("{:?} topic:{:?}, retain:{:?}", id, topic, retain);

        retain.publish.dup = false;
        retain.publish.retain = true;
        retain.publish.qos = retain.publish.qos.less_value(qos);
        retain.publish.topic = topic;
        retain.publish.packet_id = None;
        retain.publish.create_time = Some(timestamp_millis());

        log::debug!("{:?} retain.publish: {:?}", id, retain.publish);

        if let Err((from, p, reason)) =
            scx.extends.shared().await.entry(id.clone()).publish(retain.from, retain.publish).await
        {
            scx.extends.hook_mgr().message_dropped(Some(id.clone()), from, p, reason).await;
        }
    }
    Ok(())
}

/// Standalone retain excludeds loader — does not require `SessionState` reference.
#[cfg(feature = "retain")]
#[inline]
async fn _send_retain_excludeds(
    scx: &ServerContext,
    id: &Id,
    topic_filter: &TopicFilter,
    retain_handling: Option<RetainHandling>,
    prev_opts_is_none: bool,
    qos: QoS,
) -> Result<Option<Vec<(NodeId, MsgID)>>> {
    if !scx.extends.retain().await.enable() {
        return Ok(None);
    }

    //MQTT V5: Retain Handling
    let send_retain_enable = match retain_handling {
        Some(RetainHandling::AtSubscribe) => true,
        Some(RetainHandling::AtSubscribeNew) => prev_opts_is_none,
        Some(RetainHandling::NoAtSubscribe) => false,
        None => true, //MQTT V3
    };
    log::debug!("send_retain_enable: {}, prev_opts.is_none: {}", send_retain_enable, prev_opts_is_none,);

    let excludeds = if send_retain_enable {
        let handler = SendRetainMessagesHandler { scx: scx.clone(), id: id.clone(), qos };
        scx.extends.shared().await.retain_load_with(topic_filter, Arc::new(handler)).await?
    } else {
        Vec::new()
    };

    log::debug!("{:?} excludeds: {:?}", id, excludeds);
    Ok(Some(excludeds))
}

/// Handler for [`RetainLoadCallback`] used to load and send retain messages on subscribe.
#[cfg(feature = "retain")]
struct SendRetainMessagesHandler {
    scx: ServerContext,
    id: Id,
    qos: QoS,
}

#[cfg(feature = "retain")]
#[async_trait]
impl RetainLoadCallback for SendRetainMessagesHandler {
    async fn on_retains(&self, retains: Vec<(TopicName, Retain)>) -> Result<Vec<(NodeId, MsgID)>> {
        let excludeds = retains
            .iter()
            .filter_map(|(_, r)| r.msg_id.map(|msg_id| (r.from.node_id, msg_id)))
            .collect::<Vec<_>>();

        _send_retain_messages(&self.scx, &self.id, retains, self.qos).await?;

        Ok(excludeds)
    }
}

/// Fire-and-forget handler for sending retain + storaged messages on subscribe.
///
/// Runs inside a `tokio::spawn` so the subscribe response is not blocked.
/// Logs errors internally — no error propagation to the caller.
#[inline]
#[allow(unused_variables)]
#[cfg(any(feature = "retain", feature = "msgstore"))]
async fn _send_subscribe_messages(
    scx: ServerContext,
    id: Id,
    topic_filter: TopicFilter,
    shared_group: Option<SharedGroup>,
    retain_handling: Option<RetainHandling>,
    prev_opts_is_none: bool,
    qos: QoS,
) {
    #[cfg(feature = "retain")]
    let excludeds =
        match _send_retain_excludeds(&scx, &id, &topic_filter, retain_handling, prev_opts_is_none, qos).await
        {
            Ok(r) => r,
            Err(e) => {
                log::warn!("{:?} retain excludeds error: {:?}", id, e);
                None
            }
        };

    #[cfg(not(feature = "retain"))]
    let excludeds: Option<Vec<(NodeId, MsgID)>> = None;

    #[cfg(feature = "msgstore")]
    if scx.extends.message_mgr().await.enable() {
        let now = std::time::Instant::now();
        let handler = SendStoragedMessagesHandler {
            scx: scx.clone(),
            id: id.clone(),
            qos,
            excludeds,
            topic_filter: topic_filter.clone(),
            group: shared_group.clone(),
        };
        if let Err(e) = scx
            .extends
            .shared()
            .await
            .message_load_with(&id.client_id, &topic_filter, shared_group.as_ref(), Arc::new(handler))
            .await
        {
            log::warn!("message_load_with failed, {e}");
        }
        let elaps = now.elapsed();
        if elaps.as_secs() > 3 {
            log::warn!("message_load_with cost time: {:?}", elaps);
        }
    }
}

impl Session {
    /// Returns client-issued QoS 2 packet identifiers whose accepted PUBLISH is awaiting PUBREL.
    ///
    /// The snapshot contains only MQTT deduplication state. Per-connection reply paths and route
    /// ledger entries are intentionally excluded and must be reconstructed from retransmitted
    /// packets after the session resumes.
    #[inline]
    pub async fn inbound_qos2_await_pubrel_snapshot(&self) -> Vec<NonZeroU16> {
        self.in_inflight.read().await.snapshot()
    }

    /// Replaces the client-issued QoS 2 packet identifiers that are awaiting PUBREL.
    ///
    /// Session storage implementations should call this before exposing or running a rebuilt
    /// session. This restores only MQTT deduplication state; reply paths and route ledger entries
    /// remain connection-local and are reconstructed when the client retransmits.
    #[inline]
    pub async fn restore_inbound_qos2_await_pubrel(&self, packet_ids: Vec<NonZeroU16>) {
        self.in_inflight.write().await.restore(packet_ids);
    }

    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        id: Id,
        scx: ServerContext,
        max_mqueue_len: usize,
        listen_cfg: ListenerConfig,
        fitter: FitterType,
        auth_info: Option<AuthInfo>,
        max_inflight: NonZeroU16,
        created_at: TimestampMillis,

        conn_info: ConnectInfoType,
        session_present: bool,
        superuser: bool,
        connected: bool,
        connected_at: TimestampMillis,

        subscriptions: SessionSubs,
        disconnect_info: Option<DisconnectInfo>,

        last_id: Option<Id>,
    ) -> Result<Self> {
        Self::new_with_inbound_inflight(
            id,
            scx,
            max_mqueue_len,
            listen_cfg,
            fitter,
            auth_info,
            max_inflight,
            created_at,
            conn_info,
            session_present,
            superuser,
            connected,
            connected_at,
            subscriptions,
            disconnect_info,
            last_id,
            Vec::new(),
        )
        .await
    }

    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn new_with_inbound_inflight(
        id: Id,
        scx: ServerContext,
        max_mqueue_len: usize,
        listen_cfg: ListenerConfig,
        fitter: FitterType,
        auth_info: Option<AuthInfo>,
        max_inflight: NonZeroU16,
        created_at: TimestampMillis,

        conn_info: ConnectInfoType,
        session_present: bool,
        superuser: bool,
        connected: bool,
        connected_at: TimestampMillis,

        subscriptions: SessionSubs,
        disconnect_info: Option<DisconnectInfo>,

        last_id: Option<Id>,
        inbound_inflight_packet_ids: Vec<NonZeroU16>,
    ) -> Result<Self> {
        let max_inflight = max_inflight.get() as usize;
        let message_retry_interval = listen_cfg.message_retry_interval.as_millis() as TimestampMillis;
        let message_expiry_interval = listen_cfg.message_expiry_interval.as_millis() as TimestampMillis;
        #[allow(unused_mut)]
        let mut deliver_queue = MessageQueue::new(max_mqueue_len);

        #[cfg(feature = "stats")]
        {
            let scx1 = scx.clone();
            deliver_queue.on_push(move || {
                scx1.stats.message_queues.inc();
            });
        }

        #[cfg(feature = "stats")]
        {
            let scx1 = scx.clone();
            deliver_queue.on_pop(move || {
                scx1.stats.message_queues.dec();
            });
        }

        let out_inflight = OutInflight::new(max_inflight, message_retry_interval, message_expiry_interval);
        #[cfg(feature = "stats")]
        let out_inflight = {
            let scx1 = scx.clone();
            let scx2 = scx.clone();
            out_inflight
                .on_push(move || {
                    scx1.stats.out_inflights.inc();
                })
                .on_pop(move || {
                    scx2.stats.out_inflights.dec();
                })
        };

        scx.sessions.inc();

        #[cfg(feature = "stats")]
        {
            scx.stats.subscriptions.incs(subscriptions.len().await as isize);
            scx.stats.subscriptions_shared.incs(subscriptions.shared_len().await as isize);
        }

        let mut initial_in_inflight = InInflight::new(scx.clone(), max_inflight as u16);
        initial_in_inflight.restore(inbound_inflight_packet_ids);
        let in_inflight = Arc::new(RwLock::new(initial_in_inflight));
        let session_like = scx
            .extends
            .session_mgr()
            .await
            .create(
                id.clone(),
                scx.clone(),
                listen_cfg,
                fitter.clone(),
                subscriptions,
                Arc::new(deliver_queue),
                Arc::new(RwLock::new(out_inflight)),
                conn_info,
                created_at,
                connected_at,
                session_present,
                superuser,
                connected,
                disconnect_info,
                last_id,
            )
            .await?;
        let extra_attrs = Arc::new(RwLock::new(ExtraAttrs::new()));
        Ok(Self(Arc::new(_Session {
            inner: session_like,
            id,
            fitter,
            auth_info,
            in_inflight,
            extra_attrs,
            scx,
        })))
    }

    #[inline]
    pub(crate) async fn to_offline_info(&self) -> Result<OfflineInfo> {
        let id = self.id.clone();
        let created_at = self.created_at().await?;
        let subscriptions = self.subscriptions_drain().await?;

        let mut offline_messages = VecDeque::new();
        while let Some(item) = self.deliver_queue().pop() {
            //@TODO ..., check message expired
            offline_messages.push_back(item);
        }
        let inflight_messages = self.out_inflight().write().await.to_inflight_messages();
        let inbound_inflight_packet_ids = self.in_inflight.read().await.snapshot();

        Ok(OfflineInfo {
            id,
            subscriptions,
            offline_messages,
            inflight_messages,
            inbound_inflight_packet_ids,
            created_at,
        })
    }

    #[inline]
    pub async fn to_json(&self) -> serde_json::Value {
        let (count, subs) = if let Ok(subs) = self.subscriptions().await {
            let count = subs.len().await;
            let subs = subs
                .read()
                .await
                .iter()
                .enumerate()
                .filter_map(|(i, (tf, opts))| {
                    if i < 100 {
                        Some(json!({
                            "topic_filter": tf.to_string(),
                            "opts": opts.to_json(),
                        }))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            (count, subs)
        } else {
            (0, Vec::new())
        };

        let data = json!({
            "subscriptions": {
                "count": count,
                "topic_filters": subs,
            },
            "queues": self.deliver_queue().len(),
            "inflights": self.out_inflight().read().await.len(),
            "created_at": self.created_at().await.unwrap_or_default(),
        });
        data
    }
}

#[async_trait]
/// Manages the lifecycle of MQTT sessions in the broker.
///
/// Defines operations for creating, resuming, and removing sessions,
/// as well as checking session existence and retrieving session status.
/// Implementations handle persistent session storage across reconnects.
pub trait SessionManager: Sync + Send {
    #[allow(clippy::too_many_arguments)]
    async fn create(
        &self,
        id: Id,
        scx: ServerContext,
        listen_cfg: ListenerConfig,
        fitter: FitterType,
        subscriptions: SessionSubs,
        deliver_queue: MessageQueueType,
        outinflight: OutInflightType,
        conn_info: ConnectInfoType,
        created_at: TimestampMillis,
        connected_at: TimestampMillis,
        session_present: bool,
        superuser: bool,
        connected: bool,
        disconnect_info: Option<DisconnectInfo>,

        last_id: Option<Id>,
    ) -> Result<Arc<dyn SessionLike>>;
}

/// Core session behavior trait implemented by MQTT protocol versions.
///
/// Defines the interface for session state management: subscription
/// operations, connection metadata access, inflight message tracking,
/// and disconnect handling. Implementations differ between MQTT v3.1.1
/// and v5.0 to accommodate protocol-specific features.
#[async_trait]
pub trait SessionLike: Sync + Send + 'static {
    fn id(&self) -> &Id;
    fn context(&self) -> &ServerContext;
    fn listen_cfg(&self) -> &ListenerConfig;
    fn deliver_queue(&self) -> &MessageQueueType;
    fn out_inflight(&self) -> &OutInflightType;

    async fn subscriptions(&self) -> Result<SessionSubs>;
    async fn subscriptions_add(
        &self,
        topic_filter: TopicFilter,
        opts: SubscriptionOptions,
    ) -> Result<Option<SubscriptionOptions>>;
    async fn subscriptions_remove(
        &self,
        topic_filter: &str,
    ) -> Result<Option<(TopicFilter, SubscriptionOptions)>>;
    async fn subscriptions_drain(&self) -> Result<Subscriptions>;
    async fn subscriptions_extend(&self, other: Subscriptions) -> Result<()>;

    async fn created_at(&self) -> Result<TimestampMillis>;
    async fn session_present(&self) -> Result<bool>;
    async fn connect_info(&self) -> Result<Arc<ConnectInfo>>;
    fn username(&self) -> Option<&UserName>;
    fn password(&self) -> Option<&Password>;
    async fn protocol(&self) -> Result<u8>;
    async fn superuser(&self) -> Result<bool>;
    async fn connected(&self) -> Result<bool>;
    async fn connected_at(&self) -> Result<TimestampMillis>;

    async fn disconnected_at(&self) -> Result<TimestampMillis>;
    async fn disconnected_reasons(&self) -> Result<Vec<Reason>>;
    async fn disconnected_reason(&self) -> Result<Reason>;
    async fn disconnected_reason_has(&self) -> bool;
    async fn disconnected_reason_add(&self, r: Reason) -> Result<()>;
    async fn disconnected_reason_take(&self) -> Result<Reason>;
    async fn disconnect(&self) -> Result<Option<Disconnect>>;
    async fn disconnected_set(&self, d: Option<Disconnect>, reason: Option<Reason>) -> Result<()>;

    #[inline]
    async fn on_drop(&self) -> Result<()> {
        Ok(())
    }

    #[inline]
    async fn keepalive(&self, _ping: IsPing) {}
}

/// Information about an offline session, preserved for session resumption.
///
/// Captures the client's subscriptions, queued offline messages, in-flight
/// QoS 1/2 messages, and session creation timestamp. Used by persistent
/// session storage to restore state when a client reconnects.
#[derive(Serialize, Deserialize, Clone)]
pub struct OfflineInfo {
    /// Identity of the session that produced this snapshot.
    pub id: Id,
    /// Subscriptions retained by the persistent session.
    pub subscriptions: Subscriptions,
    /// Messages queued while the session was offline.
    pub offline_messages: VecDeque<(From, Publish)>,
    /// Broker-to-client QoS messages awaiting acknowledgement.
    pub inflight_messages: Vec<OutInflightMessage>,
    /// Client-issued QoS2 packet identifiers that are awaiting PUBREL.
    #[serde(default)]
    pub inbound_inflight_packet_ids: Vec<NonZeroU16>,
    /// Original session creation timestamp.
    pub created_at: TimestampMillis,
}

impl std::fmt::Debug for OfflineInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "subscriptions: {}, offline_messages: {}, inflight_messages: {}, inbound_inflight_packet_ids: {}, created_at: {}",
            self.subscriptions.len(),
            self.offline_messages.len(),
            self.inflight_messages.len(),
            self.inbound_inflight_packet_ids.len(),
            self.created_at
        )
    }
}

#[cfg(test)]
mod offline_info_tests {
    use super::*;

    fn offline_info_with_inbound(ids: Vec<NonZeroU16>) -> OfflineInfo {
        OfflineInfo {
            id: Id::from(1, ClientId::from_static("offline-info-test")),
            subscriptions: Vec::new(),
            offline_messages: VecDeque::new(),
            inflight_messages: Vec::new(),
            inbound_inflight_packet_ids: ids,
            created_at: 123,
        }
    }

    #[test]
    fn offline_info_roundtrips_inbound_qos2_packet_ids() {
        let packet_id = NonZeroU16::new(77).unwrap();
        let info = offline_info_with_inbound(vec![packet_id]);

        let encoded = postcard::to_stdvec(&info).unwrap();
        let decoded: OfflineInfo = postcard::from_bytes(&encoded).unwrap();

        assert_eq!(decoded.inbound_inflight_packet_ids, vec![packet_id]);
    }

    #[test]
    fn offline_info_defaults_missing_inbound_qos2_packet_ids() {
        let info = offline_info_with_inbound(vec![NonZeroU16::new(88).unwrap()]);
        let mut value = serde_json::to_value(info).unwrap();
        value
            .as_object_mut()
            .expect("OfflineInfo should serialize to an object")
            .remove("inbound_inflight_packet_ids");

        let decoded: OfflineInfo = serde_json::from_value(value).unwrap();

        assert!(decoded.inbound_inflight_packet_ids.is_empty());
    }
}

/// Default implementation of [`SessionManager`] for production use.
///
/// Relies on the broker's [`Shared`] state for session storage and
/// retrieval. Session creation and resumption are delegated to the
/// cluster-wide shared session infrastructure.
pub struct DefaultSessionManager;

#[async_trait]
impl SessionManager for DefaultSessionManager {
    #[allow(clippy::too_many_arguments)]
    async fn create(
        &self,
        id: Id,
        scx: ServerContext,
        listen_cfg: ListenerConfig,
        _fitter: FitterType,
        subscriptions: SessionSubs,
        deliver_queue: MessageQueueType,
        out_inflight: OutInflightType,
        conn_info: ConnectInfoType,

        created_at: TimestampMillis,
        connected_at: TimestampMillis,
        session_present: bool,
        superuser: bool,
        connected: bool,
        disconnect_info: Option<DisconnectInfo>,

        _last_id: Option<Id>,
    ) -> Result<Arc<dyn SessionLike>> {
        let s = DefaultSession::new(
            id,
            scx,
            listen_cfg,
            subscriptions,
            deliver_queue,
            out_inflight,
            conn_info,
            created_at,
            connected_at,
            session_present,
            superuser,
            connected,
            disconnect_info,
        );
        Ok(Arc::new(s))
    }
}

/// Default implementation of [`SessionLike`] for MQTT sessions.
///
/// Manages session subscriptions, delivery queue, inflight message tracking,
/// and connection lifecycle. Supports both MQTT v3.1.1 and v5.0 protocol
/// versions through the session-like interface.
pub struct DefaultSession {
    id: Id,
    scx: ServerContext,
    listen_cfg: ListenerConfig,
    pub subscriptions: SessionSubs,
    deliver_queue: MessageQueueType,
    outinflight: OutInflightType,
    conn_info: ConnectInfoType,

    created_at: TimestampMillis,
    state_flags: SessionStateFlags,
    connected_at: TimestampMillis,

    pub disconnect_info: RwLock<DisconnectInfo>,
}

impl DefaultSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Id,
        scx: ServerContext,
        listen_cfg: ListenerConfig,
        subscriptions: SessionSubs,
        deliver_queue: MessageQueueType,
        outinflight: OutInflightType,
        conn_info: ConnectInfoType,

        created_at: TimestampMillis,
        connected_at: TimestampMillis,
        session_present: bool,
        superuser: bool,
        connected: bool,
        disconnect_info: Option<DisconnectInfo>,
    ) -> Self {
        let mut state_flags = SessionStateFlags::empty();
        if session_present {
            state_flags.insert(SessionStateFlags::SessionPresent);
        }
        if superuser {
            state_flags.insert(SessionStateFlags::Superuser);
        }
        if connected {
            state_flags.insert(SessionStateFlags::Connected);
        }
        let disconnect_info = disconnect_info.unwrap_or_default();

        Self {
            id,
            scx,
            listen_cfg,
            subscriptions,
            deliver_queue,
            outinflight,
            conn_info,

            created_at,
            state_flags,
            connected_at,

            disconnect_info: RwLock::new(disconnect_info),
        }
    }
}

#[async_trait]
impl SessionLike for DefaultSession {
    fn id(&self) -> &Id {
        &self.id
    }

    #[inline]
    fn context(&self) -> &ServerContext {
        &self.scx
    }

    #[inline]
    fn listen_cfg(&self) -> &ListenerConfig {
        &self.listen_cfg
    }

    #[inline]
    fn deliver_queue(&self) -> &MessageQueueType {
        &self.deliver_queue
    }

    #[inline]
    fn out_inflight(&self) -> &OutInflightType {
        &self.outinflight
    }

    #[inline]
    async fn subscriptions(&self) -> Result<SessionSubs> {
        Ok(self.subscriptions.clone())
    }

    #[inline]
    async fn subscriptions_add(
        &self,
        topic_filter: TopicFilter,
        opts: SubscriptionOptions,
    ) -> Result<Option<SubscriptionOptions>> {
        Ok(self.subscriptions._add(&self.scx, topic_filter, opts).await)
    }

    #[inline]
    async fn subscriptions_remove(
        &self,
        topic_filter: &str,
    ) -> Result<Option<(TopicFilter, SubscriptionOptions)>> {
        Ok(self.subscriptions._remove(&self.scx, topic_filter).await)
    }

    #[inline]
    async fn subscriptions_drain(&self) -> Result<Subscriptions> {
        Ok(self.subscriptions._drain(&self.scx).await)
    }

    #[inline]
    async fn subscriptions_extend(&self, other: Subscriptions) -> Result<()> {
        self.subscriptions._extend(&self.scx, other).await;
        Ok(())
    }

    #[inline]
    async fn created_at(&self) -> Result<TimestampMillis> {
        Ok(self.created_at)
    }

    #[inline]
    async fn session_present(&self) -> Result<bool> {
        Ok(self.state_flags.contains(SessionStateFlags::SessionPresent))
    }

    async fn connect_info(&self) -> Result<Arc<ConnectInfo>> {
        Ok(self.conn_info.clone())
    }
    fn username(&self) -> Option<&UserName> {
        self.id.username.as_ref()
    }
    fn password(&self) -> Option<&Password> {
        self.conn_info.password()
    }
    async fn protocol(&self) -> Result<u8> {
        Ok(self.conn_info.proto_ver())
    }
    async fn superuser(&self) -> Result<bool> {
        Ok(self.state_flags.contains(SessionStateFlags::Superuser))
    }
    async fn connected(&self) -> Result<bool> {
        Ok(self.state_flags.contains(SessionStateFlags::Connected)
            && !self.disconnect_info.read().await.is_disconnected())
    }
    async fn connected_at(&self) -> Result<TimestampMillis> {
        Ok(self.connected_at)
    }
    async fn disconnected_at(&self) -> Result<TimestampMillis> {
        Ok(self.disconnect_info.read().await.disconnected_at)
    }
    async fn disconnected_reasons(&self) -> Result<Vec<Reason>> {
        Ok(self.disconnect_info.read().await.reasons.clone())
    }
    async fn disconnected_reason(&self) -> Result<Reason> {
        Ok(Reason::Reasons(self.disconnect_info.read().await.reasons.clone()))
    }
    async fn disconnected_reason_has(&self) -> bool {
        !self.disconnect_info.read().await.reasons.is_empty()
    }
    async fn disconnected_reason_add(&self, r: Reason) -> Result<()> {
        self.disconnect_info.write().await.reasons.push(r);
        Ok(())
    }
    async fn disconnected_reason_take(&self) -> Result<Reason> {
        Ok(Reason::Reasons(self.disconnect_info.write().await.reasons.drain(..).collect()))
    }
    async fn disconnect(&self) -> Result<Option<Disconnect>> {
        Ok(self.disconnect_info.read().await.mqtt_disconnect.clone())
    }
    async fn disconnected_set(&self, d: Option<Disconnect>, reason: Option<Reason>) -> Result<()> {
        let mut disconnect_info = self.disconnect_info.write().await;

        if !disconnect_info.is_disconnected() {
            disconnect_info.disconnected_at = timestamp_millis();
        }

        if let Some(d) = d {
            disconnect_info.reasons.push(Reason::ConnectDisconnect(Some(d.clone())));
            disconnect_info.mqtt_disconnect.replace(d);
        }

        if let Some(reason) = reason {
            disconnect_info.reasons.push(reason);
        }

        Ok(())
    }

    #[inline]
    async fn on_drop(&self) -> Result<()> {
        self.subscriptions.clear(&self.scx).await;
        Ok(())
    }
}
