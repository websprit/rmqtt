//! MQTT v5 Protocol Connection Handler Implementation
//!
//! Provides broker-side MQTT v5 protocol implementation with full CONNECT/CONNACK workflow,
//! session management, and QoS enforcement. Key features include:
//!
//! 1. **Protocol Compliance**
//!    - Full support for MQTT v5 specification features
//!    - Session expiration and persistence handling
//!    - Topic alias management (client/server-side)
//!    - Enhanced authentication flow with reason code mapping
//!
//! 2. **Connection Lifecycle**
//!    - Async TCP stream handling using Tokio runtime
//!    - Client ID generation with UUIDv4 fallback
//!    - Keep-alive negotiation and timeout detection
//!    - Configurable maximum packet size enforcement
//!
//! 3. **Session Management**
//!    - Clean session/dirty session persistence
//!    - Session takeover protection with atomic locking
//!    - Automatic offline message queuing
//!    - Resource limits enforcement (max sessions/client)
//!
//! 4. **Security & Extensibility**
//!    - Pluggable authentication hooks
//!    - Anonymous connection support with config toggle
//!    - QoS level validation (0-2)
//!    - Retained message control via feature flags
//!
//! Core components:
//! - `process()`: Main entry point handling TCP stream lifecycle
//! - `handshake()`: Negotiates protocol version and client capabilities
//! - SessionState: Manages client-specific subscriptions and message queues
//! - ConnectAck builder: Generates compliant CONNACK packets with server capabilities
//!
//! Implements advanced MQTT v5 features:
//! - Shared subscription support (feature-gated)
//! - Server-side topic alias mapping
//! - Session expiry interval control
//! - Reason code propagation for diagnostic clarity
//!
//! Metrics integration tracks:
//! - Concurrent handshakes
//! - Session creation/termination
//! - Protocol violations
//! - Resource limit triggers

use std::sync::Arc;

use anyhow::anyhow;
use rmqtt_codec::MqttCodec;
use rust_box::task_exec_queue::SpawnExt;
use scopeguard::defer;
use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

use crate::codec::v5::{Connect as ConnectV5, ConnectAck, ConnectAckReason as ConnectAckReasonV5};
use crate::context::ServerContext;
use crate::net::{v5, MqttStream, SerialMqttLink};
#[cfg(feature = "quic")]
use crate::net::{QuicActivation, QuinnBiStream};
use crate::session::{Session, SessionState};
use crate::session_link::SessionLink;
use crate::types::{
    ClientId, ConnectAckReason, ConnectInfo, Id, ListenerConfig, ListenerId, Message, OfflineSession,
    SessionSubs,
};
use crate::utils::timestamp_millis;
use crate::{Error, Result};

const QUIC_MULTISTREAM_PROPERTY: &str = "rmqtt-quic-multistream";
const QUIC_MULTISTREAM_SIMPLE_V1: &str = "simple-v1";

/// Processes a new MQTT v5.0 connection through its full lifecycle.
///
/// Performs the protocol handshake with MQTT v5 features (session expiry,
/// topic aliases, reason codes), sets up session state, and enters
/// the main message processing loop. Handles connection refusal with
/// appropriate CONNACK codes on failure.
///
/// # Arguments
/// * `scx` - Server context for accessing shared state
/// * `sink` - MQTT v5.0 stream for I/O operations
/// * `lid` - Listener port identifier
pub(crate) async fn process<Io>(
    scx: ServerContext,
    mut sink: v5::MqttStream<Io>,
    lid: ListenerId,
) -> Result<()>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    let (state, ack, keep_alive, _) = {
        scx.handshakings.inc();
        defer! {
            scx.handshakings.dec();
        }

        let outcome = match handshake(&scx, &mut sink, lid, false).await {
            Ok(c) => c,
            Err((ack_code, e)) => {
                refused_ack(&scx, &mut sink, None, ack_code, e.to_string()).await?;
                if let Err(e) = sink.close().await {
                    log::info!("{lid} close io error, {e}");
                }
                return Err(e);
            }
        };
        outcome
    };

    sink.send_connect_ack(ack).await?;
    sink.flush().await?;

    state
        .run(
            SessionLink::new(
                rmqtt_codec::version::ProtocolVersion::MQTT5,
                SerialMqttLink::new(MqttStream::V5(sink)),
            ),
            keep_alive,
        )
        .await;

    Ok(())
}

#[cfg(feature = "quic")]
pub(crate) async fn process_quic(
    scx: ServerContext,
    mut sink: v5::MqttStream<QuinnBiStream>,
    activation: QuicActivation,
    is_0rtt: bool,
    lid: ListenerId,
) -> Result<()> {
    let (state, ack, keep_alive, multistream_accepted) = {
        scx.handshakings.inc();
        defer! {
            scx.handshakings.dec();
        }

        match handshake(&scx, &mut sink, lid, true).await {
            Ok(outcome) => outcome,
            Err((ack_code, e)) => {
                refused_ack(&scx, &mut sink, None, ack_code, e.to_string()).await?;
                if let Err(close_error) = sink.close().await {
                    log::info!("{lid} close io error, {close_error}");
                }
                return Err(e);
            }
        }
    };

    // Quinn only identifies an early-opened stream, not a byte-level 0-RTT boundary.
    // This catches CONNECT plus a pipelined packet already decoded into Framed's buffer;
    // Finished gating and single-use tickets remain the replay-security boundary.
    if is_0rtt && sink.has_buffered_input() {
        return Err(anyhow!("0-RTT control flow contains MQTT data after CONNECT"));
    }

    let max_data_streams = if multistream_accepted { sink.cfg.multistream_max_data_streams } else { 0 };
    let committed = activation.send_v5_connack_and_commit(&mut sink, ack).await?;
    let link = committed.activate_multistream(MqttStream::V5(sink), max_data_streams);
    state.run(SessionLink::new(rmqtt_codec::version::ProtocolVersion::MQTT5, link), keep_alive).await;
    Ok(())
}

#[inline]
async fn handshake<Io>(
    scx: &ServerContext,
    sink: &mut v5::MqttStream<Io>,
    lid: ListenerId,
    allow_multistream: bool,
) -> std::result::Result<(SessionState, ConnectAck, u16, bool), (ConnectAckReason, Error)>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    if scx.busy_check_enable && scx.node.sys_is_busy() {
        return Err((
            ConnectAckReason::V5(ConnectAckReasonV5::ServerUnavailable),
            anyhow!("the system is currently overloaded"),
        ));
    }

    let mut c = sink
        .recv_connect(sink.cfg.handshake_timeout)
        .await
        .map_err(|e| (ConnectAckReason::V5(ConnectAckReasonV5::ServerUnavailable), e))?;
    let multistream_requested = requests_quic_multistream(&c);
    let multistream_accepted =
        allow_multistream && sink.cfg.multistream_mode == "simple" && multistream_requested;

    log::debug!(
        "new Connection: local_addr: {:?}, remote_addr: {:?}, listen_cfg: {:?}",
        sink.cfg.laddr,
        sink.remote_addr,
        sink.cfg,
    );

    //The client specifies the maximum message length that the server can send to it in the CONNECT packet.
    if let Some(max_packet_size) = c.max_packet_size {
        if let MqttCodec::V5(codec) = sink.io.codec_mut() {
            codec.set_max_outbound_size(max_packet_size.get());
        }
    }

    let assigned_client_id = if c.client_id.is_empty() {
        c.client_id =
            ClientId::from(Uuid::new_v4().as_simple().encode_lower(&mut Uuid::encode_buffer()).to_owned());
        true
    } else {
        false
    };

    let id = Id::new(
        scx.node.id(),
        lid,
        Some(sink.cfg.laddr),
        Some(sink.remote_addr),
        c.client_id.clone(),
        c.username.clone(),
    );

    let now = std::time::Instant::now();
    let exec = scx.handshake_exec.get(sink.cfg.laddr.port(), &sink.cfg);
    match _handshake(
        scx.clone(),
        id.clone(),
        c,
        sink.cfg.clone(),
        assigned_client_id,
        multistream_accepted,
        now,
    )
    .spawn(&exec)
    .result()
    .await
    {
        Ok(Ok((state, ack, keep_alive))) => Ok((state, ack, keep_alive, multistream_accepted)),
        Ok(Err((ack_code, e))) => {
            log::info!("{id:?} Connection Refused, handshake error, reason: {ack_code:?}, {e}");
            Err((ack_code, e))
        }
        Err(e) => {
            #[cfg(feature = "metrics")]
            scx.metrics.client_handshaking_timeout_inc();
            let err = anyhow!("Connection Refused, execute handshake timeout");
            log::info!("{:?} {:?}, reason: {:?}", id, err, e.to_string(),);
            Err((ConnectAckReason::V5(ConnectAckReasonV5::ServerUnavailable), err))
        }
    }
}

#[inline]
async fn _handshake(
    scx: ServerContext,
    id: Id,
    connect: Box<ConnectV5>,
    listen_cfg: ListenerConfig,
    is_assigned_client_id: bool,
    multistream_accepted: bool,
    hdshk_start: std::time::Instant,
) -> std::result::Result<(SessionState, ConnectAck, u16), (ConnectAckReason, Error)> {
    let connect_info = ConnectInfo::V5(id.clone(), connect);

    //hook, client connect
    let _ = scx.extends.hook_mgr().client_connect(&connect_info).await;

    if hdshk_start.elapsed() > listen_cfg.handshake_timeout {
        return Err((
            ConnectAckReason::V5(ConnectAckReasonV5::ServerUnavailable),
            anyhow!("handshake timeout"),
        ));
    }

    //check clientid len
    if listen_cfg.max_clientid_len > 0 && id.client_id.len() > listen_cfg.max_clientid_len {
        return Err((
            ConnectAckReason::V5(ConnectAckReasonV5::ClientIdentifierNotValid),
            anyhow!("client_id is too long"),
        ));
    }

    //Extended Auth is not supported
    if connect_info.auth_method().is_some() {
        return Err((
            ConnectAckReason::V5(ConnectAckReasonV5::BadAuthenticationMethod),
            anyhow!("extended Auth is not supported"),
        ));
    }

    let entry = scx.extends.shared().await.entry(id.clone());
    let max_sessions = scx.mqtt_max_sessions;
    if max_sessions > 0 && scx.sessions.count() >= max_sessions && !entry.exist() {
        return Err((
            ConnectAckReason::V5(ConnectAckReasonV5::ServerUnavailable),
            anyhow!(format!("the number of sessions on the current node exceeds the limit, with a maximum of {} sessions allowed", max_sessions)),
        ));
    }

    //hook, client authenticate
    let (ack, superuser, auth_info) =
        scx.extends.hook_mgr().client_authenticate(&connect_info, listen_cfg.allow_anonymous).await;
    if !ack.success() {
        return Err((ack, anyhow!("Authentication failed")));
    }

    let mut entry = match { scx.extends.shared().await.entry(id.clone()) }.try_lock().await {
        Err(e) => {
            return Err((ConnectAckReason::V5(ConnectAckReasonV5::ServerUnavailable), e));
        }
        Ok(entry) => entry,
    };

    // Kick out the current session, if it exists
    let clean_session = connect_info.clean_start();
    let (session_present, _has_offline_session, offline_info) =
        match entry.kick(clean_session, clean_session, false).await {
            Err(e) => {
                return Err((ConnectAckReason::V5(ConnectAckReasonV5::ServerUnavailable), e));
            }
            Ok(OfflineSession::NotExist) => (false, false, None),
            Ok(OfflineSession::Exist(Some(offline_info))) => (!clean_session, true, Some(offline_info)),
            Ok(OfflineSession::Exist(None)) => (false, true, None),
        };

    let connected_at = timestamp_millis();

    let connect_info = Arc::new(connect_info);

    log::debug!("{id:?} offline_info: {offline_info:?}");
    let created_at =
        if let Some(ref offline_info) = offline_info { offline_info.created_at } else { connected_at };

    let fitter = scx.extends.fitter_mgr().await.create(connect_info.clone(), id.clone(), listen_cfg.clone());

    let max_inflight = fitter.max_inflight();
    let max_mqueue_len = fitter.max_mqueue_len();
    let inbound_inflight_packet_ids = offline_info
        .as_ref()
        .filter(|_| !clean_session)
        .map(|offline| offline.inbound_inflight_packet_ids.clone())
        .unwrap_or_default();

    let session = match Session::new_with_inbound_inflight(
        id,
        scx,
        max_mqueue_len,
        listen_cfg,
        fitter,
        auth_info,
        max_inflight,
        created_at,
        connect_info.clone(),
        session_present,
        superuser,
        true,
        connected_at,
        SessionSubs::new(),
        None,
        offline_info.as_ref().map(|o| o.id.clone()),
        inbound_inflight_packet_ids,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            return Err((ConnectAckReason::V5(ConnectAckReasonV5::ServerUnavailable), e));
        }
    };

    let mut server_keepalive_sec = connect_info.keep_alive();
    let keep_alive = match session.fitter.keep_alive(&mut server_keepalive_sec) {
        Ok(keep_alive) => keep_alive,
        Err(e) => {
            return Err((ConnectAckReason::V5(ConnectAckReasonV5::ServerUnavailable), e));
        }
    };

    let hook = session.scx.extends.hook_mgr().hook(session.clone());

    if offline_info.is_none() {
        //hook, session created
        hook.session_created().await;
    }

    let client_topic_alias_max =
        if multistream_accepted { 0 } else { session.fitter.max_client_topic_aliases() };
    let server_topic_alias_max =
        if multistream_accepted { 0 } else { session.fitter.max_server_topic_aliases() };
    let state = SessionState::new(
        session,
        hook,
        server_topic_alias_max,
        client_topic_alias_max,
        multistream_accepted,
    );

    if let Err(e) = entry.set(state.session().clone(), state.tx().clone()).await {
        return Err((ConnectAckReason::V5(ConnectAckReasonV5::ServerUnavailable), e));
    }

    //hook, client connack
    let _ = state
        .scx
        .extends
        .hook_mgr()
        .client_connack(connect_info.as_ref(), ConnectAckReason::V5(ConnectAckReasonV5::Success))
        .await;

    //hook, client connected
    state.hook.client_connected().await;

    //transfer session state
    if let Some(o) = offline_info {
        if let Err(e) = state.tx().try_send(Message::SessionStateTransfer(o, clean_session)) {
            return Err((ConnectAckReason::V5(ConnectAckReasonV5::ServerUnavailable), e.into()));
        }
    }

    //automatic subscription
    #[cfg(feature = "auto-subscription")]
    {
        let auto_subscription = state.scx.extends.auto_subscription().await;
        if auto_subscription.enable() {
            match auto_subscription.subscribes(state.id()).await {
                Err(e) => return Err((ConnectAckReason::V5(ConnectAckReasonV5::ServerUnavailable), e)),
                Ok(subs) => {
                    if let Err(e) = state.tx().try_send(Message::Subscribes(subs, None)) {
                        return Err((ConnectAckReason::V5(ConnectAckReasonV5::ServerUnavailable), e.into()));
                    }
                }
            }
        }
    }

    log::debug!(
        "{:?} keep_alive: {}, server_keepalive_sec: {}",
        state.id,
        keep_alive,
        connect_info.keep_alive()
    );

    let session_expiry_interval = state.fitter.session_expiry_interval(None).as_secs() as u32;
    let session_expiry_interval_secs =
        if session_expiry_interval > 0 { Some(session_expiry_interval) } else { None };
    let max_qos = state.listen_cfg().max_qos_allowed;
    let retain_available = {
        #[cfg(feature = "retain")]
        {
            state.scx.extends.retain().await.enable()
        }
        #[cfg(not(feature = "retain"))]
        {
            false
        }
    };
    let max_server_packet_size = state.listen_cfg().max_packet_size;
    let shared_subscription_available = {
        #[cfg(feature = "shared-subscription")]
        {
            state.scx.extends.shared_subscription().await.is_supported(state.listen_cfg())
        }
        #[cfg(not(feature = "shared-subscription"))]
        {
            false
        }
    };

    let assigned_client_id = if is_assigned_client_id { Some(state.id.client_id.clone()) } else { None };

    let mut ack = ConnectAck {
        session_present,
        server_keepalive_sec: Some(server_keepalive_sec),
        session_expiry_interval_secs,
        receive_max: max_inflight,
        max_qos,
        retain_available,
        max_packet_size: Some(max_server_packet_size),
        assigned_client_id,
        topic_alias_max: client_topic_alias_max,
        wildcard_subscription_available: true,
        subscription_identifiers_available: true,
        shared_subscription_available,
        ..Default::default()
    };
    if multistream_accepted {
        ack.user_properties.push((QUIC_MULTISTREAM_PROPERTY.into(), QUIC_MULTISTREAM_SIMPLE_V1.into()));
    }

    Ok((state, ack, keep_alive))
}

fn requests_quic_multistream(connect: &ConnectV5) -> bool {
    connect.user_properties.iter().any(|(key, value)| {
        AsRef::<str>::as_ref(key) == QUIC_MULTISTREAM_PROPERTY
            && AsRef::<str>::as_ref(value) == QUIC_MULTISTREAM_SIMPLE_V1
    })
}

async fn refused_ack<Io>(
    scx: &ServerContext,
    sink: &mut v5::MqttStream<Io>,
    connect_info: Option<&ConnectInfo>,
    ack_code: ConnectAckReason,
    reason: String,
) -> Result<()>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    let new_ack_code = if let Some(connect_info) = connect_info {
        scx.extends.hook_mgr().client_connack(connect_info, ack_code).await
    } else {
        ack_code
    };
    log::info!(
        "{:?} Connection Refused, handshake, ack_code: {:?}, new_ack_code: {:?}, reason: {}",
        connect_info.map(|c| c.id()),
        ack_code,
        new_ack_code,
        reason
    );
    let reason_code = if let ConnectAckReason::V5(ack_code) = new_ack_code {
        ack_code
    } else {
        ConnectAckReasonV5::ServerUnavailable
    };
    sink.send_connect_ack(ConnectAck { reason_code, ..Default::default() }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multistream_negotiation_requires_the_exact_connect_user_property() {
        let mut connect = ConnectV5::default();
        assert!(!requests_quic_multistream(&connect));

        connect.user_properties.push((QUIC_MULTISTREAM_PROPERTY.into(), "future-version".into()));
        assert!(!requests_quic_multistream(&connect));

        connect.user_properties.push((QUIC_MULTISTREAM_PROPERTY.into(), QUIC_MULTISTREAM_SIMPLE_V1.into()));
        assert!(requests_quic_multistream(&connect));
    }
}
