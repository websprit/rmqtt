//! # MQTT Server Implementation
//!
//! ## Overall Example
//!
//! ```rust,no_run
//! use std::net::{Ipv4Addr, SocketAddr};
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create server configuration
//!     let builder = rmqtt_net::Builder::new()
//!         .name("MyMQTTBroker")
//!         .laddr(SocketAddr::from((Ipv4Addr::LOCALHOST, 1883)))
//!         .max_connections(5000);
//!
//!     // Bind TCP listener
//!     let listener = builder.bind()?;
//!
//!     // Accept and handle connections
//!     loop {
//!         let acceptor = listener.accept().await?;
//!         tokio::spawn(async move {
//!             let dispatcher = acceptor.tcp().unwrap();
//!             // Handle MQTT protocol...
//!         });
//!     }
//!     Ok(())
//! }
//! ```

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::num::{NonZeroU16, NonZeroU32};
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "quic")]
use std::collections::HashMap;
#[cfg(feature = "quic")]
use std::net::{IpAddr, Ipv6Addr};
#[cfg(feature = "quic")]
use std::sync::Mutex;
#[cfg(feature = "quic")]
use std::time::Instant;

#[cfg(feature = "quic")]
use crate::quic::{QuicIncoming, QuinnBiStream};
#[cfg(feature = "quic")]
use crate::quic_session_store::{ReplaySafeServerSessionStore, ZeroRttProfileFingerprint};
use crate::stream::Dispatcher;
#[cfg(feature = "ws")]
use crate::ws::WsStream;
#[cfg(feature = "tls")]
use crate::TlsCertExtractor;
use crate::{Error, Result};
#[allow(unused_imports)]
use anyhow::{anyhow, Context};
use nonzero_ext::nonzero;
use proxy_protocol::parse;
use proxy_protocol::ProxyHeader;
use proxy_protocol::{version1 as v1, version2 as v2};
#[cfg(feature = "quic")]
use quinn::{crypto::rustls::QuicServerConfig, IdleTimeout, VarInt};
#[cfg(feature = "tls")]
use rmqtt_codec::cert::CertInfo;
use rmqtt_codec::types::QoS;
#[cfg(not(target_os = "windows"))]
#[cfg(feature = "tls")]
use rustls::crypto::aws_lc_rs as provider;
#[cfg(feature = "tls")]
#[cfg(target_os = "windows")]
use rustls::crypto::ring as provider;
#[cfg(feature = "tls")]
use rustls::pki_types::CertificateDer;
#[cfg(feature = "tls")]
use rustls::{pki_types::pem::PemObject, server::WebPkiClientVerifier, RootCertStore, ServerConfig};
use socket2::{Domain, SockAddr, Socket, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
#[cfg(feature = "quic")]
use tokio::sync::Semaphore;
#[cfg(feature = "tls")]
use tokio_rustls::{server::TlsStream, TlsAcceptor};
#[cfg(feature = "ws")]
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::handshake::server::{ErrorResponse, Request, Response},
};

/// QUIC 0-RTT operating mode for resumed connections.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ZeroRttMode {
    /// Disable QUIC 0-RTT and require all MQTT data to wait for a full handshake.
    #[default]
    Disabled,
    /// Accept early data only through the resumed-handshake completion gate.
    HandshakeGated,
}

impl ZeroRttMode {
    /// Returns the configuration string for this 0-RTT mode.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::HandshakeGated => "handshake_gated",
        }
    }
}

impl From<&str> for ZeroRttMode {
    fn from(value: &str) -> Self {
        match value {
            "handshake_gated" => Self::HandshakeGated,
            _ => Self::Disabled,
        }
    }
}

/// Credential policy required before QUIC 0-RTT can be enabled.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ZeroRttCredentialProfile {
    /// Reject QUIC 0-RTT until a concrete credential profile is configured.
    #[default]
    Deny,
    /// Allow 0-RTT for listeners that explicitly allow anonymous MQTT clients.
    Anonymous,
    /// Allow 0-RTT for listeners that require short-lived client credentials.
    ShortLivedToken,
}

impl ZeroRttCredentialProfile {
    /// Returns the configuration string for this credential profile.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Anonymous => "anonymous",
            Self::ShortLivedToken => "short_lived_token",
        }
    }
}

impl From<&str> for ZeroRttCredentialProfile {
    fn from(value: &str) -> Self {
        match value {
            "anonymous" => Self::Anonymous,
            "short_lived_token" => Self::ShortLivedToken,
            _ => Self::Deny,
        }
    }
}

/// Configuration builder for MQTT server instances
#[derive(Clone, Debug)]
pub struct Builder {
    /// Server identifier for logging and monitoring
    pub name: String,
    /// Network address to listen on
    pub laddr: SocketAddr,
    /// Maximum number of pending connections in the accept queue
    pub backlog: i32,
    /// Enable TCP_NODELAY option for lower latency
    pub nodelay: bool,
    /// Set SO_REUSEADDR socket option
    pub reuseaddr: Option<bool>,
    /// Set SO_REUSEPORT socket option
    pub reuseport: Option<bool>,
    /// Maximum concurrent active connections
    pub max_connections: usize,
    /// Maximum simultaneous handshakes during connection setup
    pub max_handshaking_limit: usize,
    /// Maximum allowed MQTT packet size in bytes (0 = unlimited)
    pub max_packet_size: u32,

    /// Allow unauthenticated client connections
    pub allow_anonymous: bool,
    /// Minimum acceptable keepalive value in seconds
    pub min_keepalive: u16,
    /// Maximum acceptable keepalive value in seconds
    pub max_keepalive: u16,
    /// Allow clients to disable keepalive mechanism
    pub allow_zero_keepalive: bool,
    /// Multiplier for calculating actual keepalive timeout
    pub keepalive_backoff: f32,
    /// Window size for unacknowledged QoS 1/2 messages
    pub max_inflight: NonZeroU16,
    /// Timeout for completing connection handshake
    pub handshake_timeout: Duration,
    /// Network I/O timeout for sending operations
    pub send_timeout: Duration,
    /// Maximum messages queued per client
    pub max_mqueue_len: usize,
    /// Rate limiting for message delivery (messages per duration)
    pub mqueue_rate_limit: (NonZeroU32, Duration),
    /// Maximum length of client identifiers
    pub max_clientid_len: usize,
    /// Highest QoS level permitted for publishing
    pub max_qos_allowed: QoS,
    /// Maximum depth for topic hierarchy (0 = unlimited)
    pub max_topic_levels: usize,
    /// Duration before inactive sessions expire
    pub session_expiry_interval: Duration,
    /// The upper limit for how long a session can remain valid before it must expire,
    /// regardless of the client's requested session expiry interval. (0 = unlimited)
    pub max_session_expiry_interval: Duration,
    /// Retry interval for unacknowledged messages
    pub message_retry_interval: Duration,
    /// Time-to-live for undelivered messages
    pub message_expiry_interval: Duration,
    /// Maximum subscriptions per client (0 = unlimited)
    pub max_subscriptions: usize,
    /// Maximum topic aliases (MQTTv5 feature)
    pub max_topic_aliases: u16,
    /// Enable subscription count limiting
    pub limit_subscription: bool,
    /// Enable future-dated message publishing
    pub delayed_publish: bool,

    /// Enable mutual TLS authentication
    pub tls_cross_certificate: bool,
    /// Path to TLS certificate chain
    pub tls_cert: Option<String>,
    /// Path to TLS private key
    pub tls_key: Option<String>,
    /// Path to TLS client ca certs
    pub tls_client_ca_certs: Option<String>,
    /// Enable Proxy Protocol
    pub proxy_protocol: bool,
    /// Proxy Protocol timeout
    pub proxy_protocol_timeout: Duration,

    /// Use TLS Certificate CN as Username
    pub cert_cn_as_username: bool,

    /// Use the full Subject DN of the TLS Certificate as Username.
    /// Overrides `cert_cn_as_username` when both are set. Useful when
    /// multiple CAs are trusted on the same listener and CNs may
    /// collide — the full DN includes O / OU / CN and naturally
    /// namespaces identities (e.g. `OU=ANS,CN=alice` vs
    /// `OU=EnduranceUser,CN=alice`).
    pub cert_subject_dn_as_username: bool,

    /// Collect TLS Certificate information
    pub collect_cert_info: bool,

    /// QUIC(max_idle_timeout)
    pub idle_timeout: Duration,
    /// Accept MQTT application data during a resumed QUIC handshake.
    ///
    /// Enabling this also selects `ZeroRttMode::HandshakeGated` unless an
    /// explicit mode was already configured.
    pub enable_quic_0rtt: bool,
    /// QUIC 0-RTT operating mode used for resumed connections.
    pub quic_0rtt_mode: ZeroRttMode,
    /// Credential profile that must match listener authentication policy before 0-RTT is allowed.
    pub quic_0rtt_credential_profile: ZeroRttCredentialProfile,
    /// Authentication policy epoch included in ticket fingerprints to invalidate old tickets.
    pub quic_0rtt_auth_policy_epoch: u64,
    /// Capacity of the stateful, single-use QUIC 0-RTT ticket cache.
    pub quic_0rtt_ticket_capacity: usize,
    /// Time-to-live for cached QUIC 0-RTT tickets.
    pub quic_0rtt_ticket_ttl: Duration,
    /// Bytes accepted before the resumed QUIC handshake finishes.
    pub quic_0rtt_pre_finished_read_budget: u32,
    /// QUIC multistream mode string, currently `disabled` or `simple`.
    pub multistream_mode: String,
    /// Maximum concurrent MQTT data streams allowed after QUIC multistream activation.
    pub multistream_max_data_streams: u32,
    /// Maximum MQTT data-stream open rate allowed after QUIC multistream activation.
    pub multistream_stream_open_rate: u32,
    /// MQTT data-stream idle timeout after QUIC multistream activation.
    pub multistream_stream_idle_timeout: Duration,
    /// Packets queued per QUIC multistream connection.
    pub multistream_connection_mailbox_packets: usize,
    /// Buffered bytes allowed per QUIC multistream connection.
    pub multistream_connection_buffer_bytes: usize,
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

/// # Examples
/// ```
/// use std::net::SocketAddr;
/// use rmqtt_net::Builder;
///
/// let builder = Builder::new()
///     .name("EdgeBroker")
///     .laddr("127.0.0.1:1883".parse().unwrap())
///     .max_connections(10_000);
/// ```
impl Builder {
    /// Creates a new builder with default configuration values
    pub fn new() -> Builder {
        Builder {
            name: Default::default(),
            laddr: SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 1883)),
            max_connections: 1_000_000,
            max_handshaking_limit: 1_000,
            max_packet_size: 1024 * 1024,
            backlog: 512,
            nodelay: false,
            reuseaddr: None,
            reuseport: None,

            allow_anonymous: true,
            min_keepalive: 0,
            max_keepalive: 65535,
            allow_zero_keepalive: true,
            keepalive_backoff: 0.75,
            max_inflight: nonzero!(16u16),
            handshake_timeout: Duration::from_secs(30),
            send_timeout: Duration::from_secs(10),
            max_mqueue_len: 1000,

            mqueue_rate_limit: (nonzero!(u32::MAX), Duration::from_secs(1)),
            max_clientid_len: 65535,
            max_qos_allowed: QoS::ExactlyOnce,
            max_topic_levels: 0,
            session_expiry_interval: Duration::from_secs(2 * 60 * 60),
            max_session_expiry_interval: Duration::ZERO,
            message_retry_interval: Duration::from_secs(20),
            message_expiry_interval: Duration::from_secs(5 * 60),
            max_subscriptions: 0,
            max_topic_aliases: 0,

            limit_subscription: false,
            delayed_publish: false,

            tls_cross_certificate: false,
            tls_cert: None,
            tls_key: None,
            tls_client_ca_certs: None,
            proxy_protocol: false,
            proxy_protocol_timeout: Duration::from_secs(5),

            cert_cn_as_username: false,
            cert_subject_dn_as_username: false,
            collect_cert_info: false,

            idle_timeout: Duration::from_secs(90),
            enable_quic_0rtt: false,
            quic_0rtt_mode: ZeroRttMode::Disabled,
            quic_0rtt_credential_profile: ZeroRttCredentialProfile::Deny,
            quic_0rtt_auth_policy_epoch: 0,
            quic_0rtt_ticket_capacity: 4096,
            quic_0rtt_ticket_ttl: Duration::from_secs(10 * 60),
            quic_0rtt_pre_finished_read_budget: 64 * 1024,
            multistream_mode: "disabled".into(),
            multistream_max_data_streams: 8,
            multistream_stream_open_rate: 32,
            multistream_stream_idle_timeout: Duration::from_secs(60),
            multistream_connection_mailbox_packets: 256,
            multistream_connection_buffer_bytes: 1024 * 1024,
        }
    }

    /// Sets the server name identifier
    pub fn name<N: Into<String>>(mut self, name: N) -> Self {
        self.name = name.into();
        self
    }

    /// Configures the network listen address
    pub fn laddr(mut self, laddr: SocketAddr) -> Self {
        self.laddr = laddr;
        self
    }

    /// Sets the TCP backlog size
    pub fn backlog(mut self, backlog: i32) -> Self {
        self.backlog = backlog;
        self
    }

    /// Enables/disables TCP_NODELAY option
    pub fn nodelay(mut self, nodelay: bool) -> Self {
        self.nodelay = nodelay;
        self
    }

    /// Configures SO_REUSEADDR socket option
    pub fn reuseaddr(mut self, reuseaddr: Option<bool>) -> Self {
        self.reuseaddr = reuseaddr;
        self
    }

    /// Configures SO_REUSEPORT socket option
    pub fn reuseport(mut self, reuseport: Option<bool>) -> Self {
        self.reuseport = reuseport;
        self
    }

    /// Sets maximum concurrent connections
    pub fn max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// Sets maximum concurrent handshakes
    pub fn max_handshaking_limit(mut self, max_handshaking_limit: usize) -> Self {
        self.max_handshaking_limit = max_handshaking_limit;
        self
    }

    /// Configures maximum MQTT packet size
    pub fn max_packet_size(mut self, max_packet_size: u32) -> Self {
        self.max_packet_size = max_packet_size;
        self
    }

    /// Enables anonymous client access
    pub fn allow_anonymous(mut self, allow_anonymous: bool) -> Self {
        self.allow_anonymous = allow_anonymous;
        self
    }

    /// Sets minimum acceptable keepalive value
    pub fn min_keepalive(mut self, min_keepalive: u16) -> Self {
        self.min_keepalive = min_keepalive;
        self
    }

    /// Sets maximum acceptable keepalive value
    pub fn max_keepalive(mut self, max_keepalive: u16) -> Self {
        self.max_keepalive = max_keepalive;
        self
    }

    /// Allows clients to disable keepalive
    pub fn allow_zero_keepalive(mut self, allow_zero_keepalive: bool) -> Self {
        self.allow_zero_keepalive = allow_zero_keepalive;
        self
    }

    /// Configures keepalive backoff multiplier
    pub fn keepalive_backoff(mut self, keepalive_backoff: f32) -> Self {
        self.keepalive_backoff = keepalive_backoff;
        self
    }

    /// Sets inflight message window size
    pub fn max_inflight(mut self, max_inflight: NonZeroU16) -> Self {
        self.max_inflight = max_inflight;
        self
    }

    /// Configures handshake timeout duration
    pub fn handshake_timeout(mut self, handshake_timeout: Duration) -> Self {
        self.handshake_timeout = handshake_timeout;
        self
    }

    /// Sets network send timeout duration
    pub fn send_timeout(mut self, send_timeout: Duration) -> Self {
        self.send_timeout = send_timeout;
        self
    }

    /// Configures maximum message queue length
    pub fn max_mqueue_len(mut self, max_mqueue_len: usize) -> Self {
        self.max_mqueue_len = max_mqueue_len;
        self
    }

    /// Sets message rate limiting parameters
    pub fn mqueue_rate_limit(mut self, rate_limit: NonZeroU32, duration: Duration) -> Self {
        self.mqueue_rate_limit = (rate_limit, duration);
        self
    }

    /// Sets maximum client ID length
    pub fn max_clientid_len(mut self, max_clientid_len: usize) -> Self {
        self.max_clientid_len = max_clientid_len;
        self
    }

    /// Configures maximum allowed QoS level
    pub fn max_qos_allowed(mut self, max_qos_allowed: QoS) -> Self {
        self.max_qos_allowed = max_qos_allowed;
        self
    }

    /// Sets maximum topic hierarchy depth
    pub fn max_topic_levels(mut self, max_topic_levels: usize) -> Self {
        self.max_topic_levels = max_topic_levels;
        self
    }

    /// Configures session expiration interval
    pub fn session_expiry_interval(mut self, session_expiry_interval: Duration) -> Self {
        self.session_expiry_interval = session_expiry_interval;
        self
    }

    /// Configures max session expiration interval
    pub fn max_session_expiry_interval(mut self, max_session_expiry_interval: Duration) -> Self {
        self.max_session_expiry_interval = max_session_expiry_interval;
        self
    }

    /// Sets message retry interval for QoS 1/2
    pub fn message_retry_interval(mut self, message_retry_interval: Duration) -> Self {
        self.message_retry_interval = message_retry_interval;
        self
    }

    /// Configures message expiration time
    pub fn message_expiry_interval(mut self, message_expiry_interval: Duration) -> Self {
        self.message_expiry_interval = message_expiry_interval;
        self
    }

    /// Sets maximum subscriptions per client
    pub fn max_subscriptions(mut self, max_subscriptions: usize) -> Self {
        self.max_subscriptions = max_subscriptions;
        self
    }

    /// Configures maximum topic aliases (MQTTv5)
    pub fn max_topic_aliases(mut self, max_topic_aliases: u16) -> Self {
        self.max_topic_aliases = max_topic_aliases;
        self
    }

    /// Enables subscription count limiting
    pub fn limit_subscription(mut self, limit_subscription: bool) -> Self {
        self.limit_subscription = limit_subscription;
        self
    }

    /// Enables delayed message publishing
    pub fn delayed_publish(mut self, delayed_publish: bool) -> Self {
        self.delayed_publish = delayed_publish;
        self
    }

    /// Enables mutual TLS authentication
    pub fn tls_cross_certificate(mut self, cross_certificate: bool) -> Self {
        self.tls_cross_certificate = cross_certificate;
        self
    }

    /// Sets path to TLS certificate chain
    pub fn tls_cert<N: Into<String>>(mut self, tls_cert: Option<N>) -> Self {
        self.tls_cert = tls_cert.map(|c| c.into());
        self
    }

    /// Sets path to TLS private key
    pub fn tls_key<N: Into<String>>(mut self, tls_key: Option<N>) -> Self {
        self.tls_key = tls_key.map(|c| c.into());
        self
    }

    /// Sets path to TLS private key
    pub fn tls_client_ca_certs<N: Into<String>>(mut self, tls_key: Option<N>) -> Self {
        self.tls_client_ca_certs = tls_key.map(|c| c.into());
        self
    }

    /// Configures using the TLS certificate CN field as the MQTT username
    pub fn cert_cn_as_username(mut self, cert_cn_as_username: bool) -> Self {
        self.cert_cn_as_username = cert_cn_as_username;
        self
    }

    /// Configures using the full TLS certificate Subject DN as the MQTT username.
    /// Takes precedence over `cert_cn_as_username` when both are enabled.
    pub fn cert_subject_dn_as_username(mut self, v: bool) -> Self {
        self.cert_subject_dn_as_username = v;
        self
    }

    /// Enables collection of TLS certificate metadata for connected clients
    pub fn collect_cert_info(mut self, collect_cert_info: bool) -> Self {
        self.collect_cert_info = collect_cert_info;
        self
    }

    /// Enable proxy protocol parse
    pub fn proxy_protocol(mut self, enable_protocol_proxy: bool) -> Self {
        self.proxy_protocol = enable_protocol_proxy;
        self
    }

    /// Sets proxy protocol timeout
    pub fn proxy_protocol_timeout(mut self, proxy_protocol_timeout: Duration) -> Self {
        self.proxy_protocol_timeout = proxy_protocol_timeout;
        self
    }

    /// Sets idle timeout (QUIC)
    pub fn idle_timeout(mut self, idle_timeout: Duration) -> Self {
        self.idle_timeout = idle_timeout;
        self
    }

    /// Enables TLS 1.3 early data and immediate stream acceptance for resumed QUIC connections.
    ///
    /// When enabled, `bind_quic` requires a non-deny credential profile and
    /// uses stateful, single-use tickets to guard replay-sensitive MQTT data.
    pub fn enable_quic_0rtt(mut self, enable_quic_0rtt: bool) -> Self {
        self.enable_quic_0rtt = enable_quic_0rtt;
        if enable_quic_0rtt && self.quic_0rtt_mode == ZeroRttMode::Disabled {
            self.quic_0rtt_mode = ZeroRttMode::HandshakeGated;
        } else if !enable_quic_0rtt {
            self.quic_0rtt_mode = ZeroRttMode::Disabled;
        }
        self
    }

    /// Configures QUIC 0-RTT mode from its configuration string.
    pub fn quic_0rtt_mode<N: AsRef<str>>(mut self, mode: N) -> Self {
        self.quic_0rtt_mode = ZeroRttMode::from(mode.as_ref());
        self.enable_quic_0rtt = self.quic_0rtt_mode == ZeroRttMode::HandshakeGated;
        self
    }

    /// Configures the QUIC 0-RTT credential policy from its configuration string.
    pub fn quic_0rtt_credential_profile<N: AsRef<str>>(mut self, profile: N) -> Self {
        self.quic_0rtt_credential_profile = ZeroRttCredentialProfile::from(profile.as_ref());
        self
    }

    /// Configures the QUIC 0-RTT auth-policy epoch used to invalidate old tickets.
    pub fn quic_0rtt_auth_policy_epoch(mut self, auth_policy_epoch: u64) -> Self {
        self.quic_0rtt_auth_policy_epoch = auth_policy_epoch;
        self
    }

    /// Configures the QUIC 0-RTT stateful, single-use ticket cache capacity.
    pub fn quic_0rtt_ticket_capacity(mut self, ticket_capacity: usize) -> Self {
        self.quic_0rtt_ticket_capacity = ticket_capacity;
        self
    }

    /// Configures the QUIC 0-RTT stateful ticket cache TTL.
    pub fn quic_0rtt_ticket_ttl(mut self, ticket_ttl: Duration) -> Self {
        self.quic_0rtt_ticket_ttl = ticket_ttl;
        self
    }

    /// Configures bytes accepted before the resumed QUIC handshake finishes.
    pub fn quic_0rtt_pre_finished_read_budget(mut self, pre_finished_read_budget: u32) -> Self {
        self.quic_0rtt_pre_finished_read_budget = pre_finished_read_budget;
        self
    }

    /// Configures QUIC multistream mode from its configuration string.
    pub fn multistream_mode<N: Into<String>>(mut self, mode: N) -> Self {
        self.multistream_mode = mode.into();
        self
    }

    /// Configures maximum MQTT data streams per QUIC connection.
    pub fn multistream_max_data_streams(mut self, max_data_streams: u32) -> Self {
        self.multistream_max_data_streams = max_data_streams.min(u32::MAX - 1);
        self
    }

    /// Configures the MQTT data-stream open rate per QUIC connection.
    pub fn multistream_stream_open_rate(mut self, stream_open_rate: u32) -> Self {
        self.multistream_stream_open_rate = stream_open_rate;
        self
    }

    /// Configures the MQTT data-stream idle timeout for QUIC multistream sessions.
    pub fn multistream_stream_idle_timeout(mut self, stream_idle_timeout: Duration) -> Self {
        self.multistream_stream_idle_timeout = stream_idle_timeout;
        self
    }

    /// Configures packets queued per QUIC multistream connection.
    pub fn multistream_connection_mailbox_packets(mut self, connection_mailbox_packets: usize) -> Self {
        self.multistream_connection_mailbox_packets = connection_mailbox_packets;
        self
    }

    /// Configures buffered bytes allowed per QUIC multistream connection.
    pub fn multistream_connection_buffer_bytes(mut self, connection_buffer_bytes: usize) -> Self {
        self.multistream_connection_buffer_bytes = connection_buffer_bytes;
        self
    }

    /// Binds the server to the configured address
    #[allow(unused_variables)]
    pub fn bind(self) -> Result<Listener> {
        let builder = match self.laddr {
            SocketAddr::V4(_) => Socket::new(Domain::IPV4, Type::STREAM, None)?,
            SocketAddr::V6(_) => Socket::new(Domain::IPV6, Type::STREAM, None)?,
        };

        builder.set_nonblocking(true)?;

        if let Some(reuseaddr) = self.reuseaddr {
            builder.set_reuse_address(reuseaddr)?;
        }

        #[cfg(not(windows))]
        if let Some(reuseport) = self.reuseport {
            builder.set_reuse_port(reuseport)?;
        }

        builder.bind(&SockAddr::from(self.laddr))?;
        builder.listen(self.backlog)?;
        let tcp_listener = TcpListener::from_std(std::net::TcpListener::from(builder))?;

        log::info!(
            "MQTT Broker Listening on {} {}",
            self.name,
            tcp_listener.local_addr().unwrap_or(self.laddr)
        );
        #[cfg(feature = "quic")]
        let quic_handshake_permits = Arc::new(Semaphore::new(self.max_handshaking_limit.max(1)));
        #[cfg(feature = "quic")]
        let quic_prefix_limiter = Arc::new(QuicPrefixLimiter::new(self.max_handshaking_limit.max(1)));
        Ok(Listener {
            typ: ListenerType::TCP,
            cfg: Arc::new(self),
            tcp_listener: Some(tcp_listener),
            #[cfg(feature = "tls")]
            tls_acceptor: None,
            #[cfg(feature = "quic")]
            quinn_endpoint: None,
            #[cfg(feature = "quic")]
            quic_handshake_permits,
            #[cfg(feature = "quic")]
            quic_prefix_limiter,
        })
    }

    #[allow(unused_variables)]
    #[cfg(feature = "quic")]
    /// Binds a QUIC listener using the configured TLS, 0-RTT, and multistream policy.
    ///
    /// 0-RTT requires a non-deny credential profile, stateful TLS tickets, and
    /// an authentication policy that is compatible with the configured listener.
    pub fn bind_quic(self) -> Result<Listener> {
        let quic_0rtt_enabled = self.enable_quic_0rtt || self.quic_0rtt_mode == ZeroRttMode::HandshakeGated;
        if quic_0rtt_enabled && self.quic_0rtt_credential_profile == ZeroRttCredentialProfile::Deny {
            return Err(anyhow!("QUIC 0-RTT requires an explicit credential profile"));
        }
        if quic_0rtt_enabled && self.tls_cross_certificate {
            return Err(anyhow!("QUIC 0-RTT cannot be combined with mutual TLS authentication"));
        }
        if quic_0rtt_enabled
            && self.quic_0rtt_credential_profile == ZeroRttCredentialProfile::Anonymous
            && !self.allow_anonymous
        {
            return Err(anyhow!("QUIC 0-RTT anonymous credential profile requires an anonymous listener"));
        }
        if quic_0rtt_enabled
            && self.quic_0rtt_credential_profile == ZeroRttCredentialProfile::ShortLivedToken
            && self.allow_anonymous
        {
            return Err(anyhow!(
                "QUIC 0-RTT short-lived token profile requires anonymous access to be disabled"
            ));
        }
        let mut tls_config = self.build_tls_config()?;
        tls_config.alpn_protocols = vec![b"mqtt".to_vec(), b"mqttv5".to_vec()];
        if quic_0rtt_enabled {
            if tls_config.ticketer.enabled() {
                return Err(anyhow!("QUIC 0-RTT requires stateful TLS tickets"));
            }
            tls_config.send_half_rtt_data = false;
            let profile = ZeroRttProfileFingerprint::mqtt_quic(
                tls_config.alpn_protocols.iter().map(Vec::as_slice),
                u64::from(self.quic_0rtt_pre_finished_read_budget),
                self.quic_0rtt_auth_policy_epoch,
                format!("{}:{}", self.quic_0rtt_credential_profile.as_str(), self.multistream_mode).as_str(),
            );
            tls_config.session_storage = ReplaySafeServerSessionStore::new(
                self.quic_0rtt_ticket_capacity,
                self.quic_0rtt_ticket_ttl,
                profile,
            );
            // Quinn requires QUIC max early data to be either 0 or 2^32-1.
            tls_config.max_early_data_size = u32::MAX;
        }
        let server_crypto = QuicServerConfig::try_from(tls_config)?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));

        let transport_config = Arc::get_mut(&mut server_config.transport)
            .ok_or_else(|| anyhow!("QUIC transport config is unexpectedly shared"))?;
        transport_config.max_concurrent_bidi_streams(1_u8.into());
        transport_config.max_concurrent_uni_streams(0_u8.into());
        transport_config.max_idle_timeout(Some(IdleTimeout::try_from(self.idle_timeout)?));
        if quic_0rtt_enabled {
            let pre_finished_budget = VarInt::from_u32(self.quic_0rtt_pre_finished_read_budget.max(1));
            transport_config.stream_receive_window(pre_finished_budget);
            transport_config.receive_window(pre_finished_budget);
        }

        let endpoint = quinn::Endpoint::server(server_config, self.laddr)?;
        let quic_handshake_permits = Arc::new(Semaphore::new(self.max_handshaking_limit.max(1)));
        let quic_prefix_limiter = Arc::new(QuicPrefixLimiter::new(self.max_handshaking_limit.max(1)));

        log::info!("MQTT Broker Listening on {} {}", self.name, endpoint.local_addr().unwrap_or(self.laddr));
        Ok(Listener {
            typ: ListenerType::QUIC,
            cfg: Arc::new(self),
            tcp_listener: None,
            #[cfg(feature = "tls")]
            tls_acceptor: None,
            quinn_endpoint: Some(endpoint),
            quic_handshake_permits,
            quic_prefix_limiter,
        })
    }

    #[cfg(feature = "tls")]
    fn build_tls_config(&self) -> Result<ServerConfig> {
        let cert_file = self.tls_cert.as_ref().ok_or(anyhow!("TLS certificate path not set"))?;
        let key_file = self.tls_key.as_ref().ok_or(anyhow!("TLS key path not set"))?;

        let cert_chain = read_ca_certs(cert_file).context("Failed to read TLS certificate chain")?;
        let key = rustls::pki_types::PrivateKeyDer::from_pem_file(key_file).map_err(|e| anyhow!(e))?;
        let client_ca_certs = if let Some(ca_certs_file) = self.tls_client_ca_certs.as_ref() {
            read_ca_certs(ca_certs_file).context("Failed to read TLS Client CA certificates")?
        } else {
            cert_chain.clone()
        };

        let provider = Arc::new(provider::default_provider());
        let client_auth = if self.tls_cross_certificate {
            let mut client_auth_roots = RootCertStore::empty();
            for root in client_ca_certs {
                client_auth_roots.add(root).map_err(|e| anyhow!(e))?;
            }
            WebPkiClientVerifier::builder_with_provider(client_auth_roots.into(), provider.clone())
                .build()
                .map_err(|e| anyhow!(e))?
        } else {
            WebPkiClientVerifier::no_client_auth()
        };

        ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| anyhow!(e))?
            .with_client_cert_verifier(client_auth)
            .with_single_cert(cert_chain, key)
            .map_err(|e| anyhow!(format!("Certificate error: {e}")))
    }
}

/// Protocol variants for network listeners
#[derive(Debug, Copy, Clone)]
pub enum ListenerType {
    /// Plain TCP listener
    TCP,
    #[cfg(feature = "tls")]
    /// TLS-secured TCP listener
    TLS,
    #[cfg(feature = "ws")]
    /// WebSocket listener
    WS,
    #[cfg(feature = "tls")]
    #[cfg(feature = "ws")]
    /// TLS-secured WebSocket listener
    WSS,
    #[cfg(feature = "quic")]
    ///QUIC listener (UDP-based, multiplexed and secured by default)
    QUIC,
}

/// Network listener for accepting client connections
pub struct Listener {
    /// Active listener protocol type
    pub typ: ListenerType,
    /// Shared server configuration
    pub cfg: Arc<Builder>,
    tcp_listener: Option<TcpListener>,
    #[cfg(feature = "tls")]
    tls_acceptor: Option<TlsAcceptor>,
    #[cfg(feature = "quic")]
    quinn_endpoint: Option<quinn::Endpoint>,
    #[cfg(feature = "quic")]
    quic_handshake_permits: Arc<Semaphore>,
    #[cfg(feature = "quic")]
    quic_prefix_limiter: Arc<QuicPrefixLimiter>,
}

#[cfg(feature = "quic")]
const QUIC_PREFIX_WINDOW: Duration = Duration::from_secs(1);

#[cfg(feature = "quic")]
#[derive(Debug)]
struct QuicAdmissionRejected(&'static str);

#[cfg(feature = "quic")]
impl std::fmt::Display for QuicAdmissionRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "QUIC admission rejected: {}", self.0)
    }
}

#[cfg(feature = "quic")]
impl std::error::Error for QuicAdmissionRejected {}

#[cfg(feature = "quic")]
/// Returns whether an error represents a connection already handled by QUIC admission control.
///
/// Such errors are non-fatal for the listener loop: the peer has already received a Retry or
/// refusal, so accepting the next datagram must continue without listener-level backoff.
pub fn is_quic_admission_rejection(error: &anyhow::Error) -> bool {
    error.downcast_ref::<QuicAdmissionRejected>().is_some()
}

#[cfg(feature = "quic")]
struct QuicPrefixLimiter {
    entries: Mutex<HashMap<IpAddr, (Instant, usize)>>,
    max_entries: usize,
    per_prefix_limit: usize,
}

#[cfg(feature = "quic")]
impl QuicPrefixLimiter {
    fn new(max_handshakes: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_entries: max_handshakes.saturating_mul(4).max(16),
            per_prefix_limit: (max_handshakes / 4).max(1),
        }
    }

    fn allow(&self, remote_addr: SocketAddr) -> bool {
        let now = Instant::now();
        let prefix = quic_remote_prefix(remote_addr.ip());
        let Ok(mut entries) = self.entries.lock() else {
            return false;
        };
        entries.retain(|_, (started, _)| now.duration_since(*started) < QUIC_PREFIX_WINDOW);
        if !entries.contains_key(&prefix) && entries.len() >= self.max_entries {
            return false;
        }
        let entry = entries.entry(prefix).or_insert((now, 0));
        if now.duration_since(entry.0) >= QUIC_PREFIX_WINDOW {
            *entry = (now, 0);
        }
        if entry.1 >= self.per_prefix_limit {
            return false;
        }
        entry.1 += 1;
        true
    }
}

#[cfg(feature = "quic")]
fn quic_remote_prefix(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::from(u32::from(ip) & 0xffff_ff00)),
        IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(u128::from(ip) & (!0_u128 << 72))),
    }
}

#[cfg(feature = "quic")]
fn reject_or_retry_quic(incoming: quinn::Incoming, reason: &'static str) -> Result<QuicIncoming> {
    if incoming.may_retry() {
        incoming.retry().map_err(|_| anyhow!("QUIC {reason}: Retry failed"))?;
        return Err(anyhow!(QuicAdmissionRejected(reason)));
    }
    incoming.refuse();
    Err(anyhow!(QuicAdmissionRejected(reason)))
}

/// # Examples
/// ```
/// # use rmqtt_net::{Builder, Listener};
/// # fn setup() -> Result<(), Box<dyn std::error::Error>> {
/// let builder = Builder::new();
/// let listener = builder.bind()?;
/// # Ok(())
/// # }
/// ```
impl Listener {
    /// Converts listener to plain TCP mode
    pub fn tcp(mut self) -> Result<Self> {
        let _err = anyhow!("Protocol downgrade from TLS/WS/WSS/QUIC to TCP is not permitted");
        #[cfg(feature = "tls")]
        if matches!(self.typ, ListenerType::TLS) {
            return Err(_err);
        }
        #[cfg(feature = "tls")]
        #[cfg(feature = "ws")]
        if matches!(self.typ, ListenerType::WSS) {
            return Err(_err);
        }
        #[cfg(feature = "ws")]
        if matches!(self.typ, ListenerType::WS) {
            return Err(_err);
        }
        #[cfg(feature = "quic")]
        if matches!(self.typ, ListenerType::QUIC) {
            return Err(_err);
        }

        self.typ = ListenerType::TCP;
        Ok(self)
    }

    #[cfg(feature = "ws")]
    /// Upgrades listener to WebSocket protocol
    pub fn ws(mut self) -> Result<Self> {
        if matches!(self.typ, ListenerType::TCP | ListenerType::WS) {
            self.typ = ListenerType::WS;
        } else {
            return Err(anyhow!("Protocol upgrade from TLS/WSS/QUIC to WS is not permitted"));
        }
        Ok(self)
    }

    #[cfg(feature = "tls")]
    #[cfg(feature = "ws")]
    /// Upgrades listener to secure WebSocket (WSS)
    pub fn wss(mut self) -> Result<Self> {
        #[cfg(feature = "quic")]
        if matches!(self.typ, ListenerType::QUIC) {
            return Err(anyhow!("Protocol upgrade from QUIC to WS is not permitted"));
        }

        if matches!(self.typ, ListenerType::TCP | ListenerType::WS) {
            self = self.tls()?;
        }
        self.typ = ListenerType::WSS;
        Ok(self)
    }

    #[cfg(feature = "tls")]
    /// Upgrades listener to TLS-secured TCP
    pub fn tls(mut self) -> Result<Listener> {
        match self.typ {
            #[cfg(feature = "ws")]
            ListenerType::WS | ListenerType::WSS => {
                return Err(anyhow!("Protocol downgrade from WS/WSS/QUIC to TLS is not permitted"));
            }
            #[cfg(feature = "quic")]
            ListenerType::QUIC => {
                return Err(anyhow!("Protocol downgrade from QUIC to TLS is not permitted"));
            }
            ListenerType::TLS => return Ok(self),
            ListenerType::TCP => {}
        }

        let tls_config = self.cfg.build_tls_config()?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        self.tls_acceptor = Some(acceptor);
        self.typ = ListenerType::TLS;
        Ok(self)
    }

    /// Accepts incoming client connections
    pub async fn accept(&self) -> Result<Acceptor<TcpStream>> {
        if let Some(tcp_listener) = &self.tcp_listener {
            self.accept_tcp(tcp_listener).await
        } else {
            Err(anyhow!(""))
        }
    }

    async fn accept_tcp(&self, tcp_listener: &TcpListener) -> Result<Acceptor<TcpStream>> {
        let (mut socket, mut remote_addr) = tcp_listener.accept().await?;
        if let Err(e) = socket.set_nodelay(self.cfg.nodelay) {
            return Err(Error::from(e));
        }
        log::debug!("remote_addr: {remote_addr}, proxy_protocol: {}", self.cfg.proxy_protocol);
        if self.cfg.proxy_protocol {
            let mut buffer = [0u8; u16::MAX as usize];
            let read_bytes =
                tokio::time::timeout(self.cfg.proxy_protocol_timeout, socket.peek(&mut buffer)).await??;
            let len = {
                let mut slice = &buffer[..read_bytes];
                let header = parse(&mut slice)?;
                if let Some((src, _)) = handle_header(header) {
                    remote_addr = src;
                }
                read_bytes - slice.len()
            };
            // skip proxy protocol data
            let _ = socket.read_exact(&mut buffer[..len]).await;
        }
        Ok(Acceptor {
            socket,
            remote_addr,
            #[cfg(feature = "tls")]
            acceptor: self.tls_acceptor.clone(),
            cfg: self.cfg.clone(),
            typ: self.typ,
        })
    }

    #[cfg(feature = "quic")]
    /// Accepts the next QUIC connection and returns the typed incoming connection handle.
    ///
    /// The returned `QuicIncoming` lets callers choose the verified typestate
    /// path, including control-stream activation and MQTT multistream handling.
    pub async fn next_quic(&self) -> Result<QuicIncoming> {
        let endpoint =
            self.quinn_endpoint.as_ref().ok_or_else(|| anyhow!("No active QUIC endpoint available"))?;
        let zero_rtt_enabled =
            self.cfg.enable_quic_0rtt || self.cfg.quic_0rtt_mode == ZeroRttMode::HandshakeGated;
        if !zero_rtt_enabled {
            let permit = self
                .quic_handshake_permits
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| anyhow!("QUIC handshake admission is closed"))?;
            let incoming =
                endpoint.accept().await.ok_or_else(|| anyhow!("No incoming QUIC connection available"))?;
            return QuicIncoming::new(incoming, self.cfg.clone(), permit);
        }

        let incoming =
            endpoint.accept().await.ok_or_else(|| anyhow!("No incoming QUIC connection available"))?;
        if !self.quic_prefix_limiter.allow(incoming.remote_address()) {
            return reject_or_retry_quic(incoming, "per-prefix handshake rate limit");
        }
        let permit = match self.quic_handshake_permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return reject_or_retry_quic(incoming, "handshake admission limit"),
        };
        QuicIncoming::new(incoming, self.cfg.clone(), permit)
    }

    #[cfg(feature = "quic")]
    /// Accepts the next QUIC connection and returns its MQTT control stream.
    ///
    /// This preserves the legacy single-stream accept path; new multistream
    /// callers should use `next_quic` and complete activation explicitly.
    pub async fn accept_quic(&self) -> Result<Acceptor<QuinnBiStream>> {
        let accepted = self.next_quic().await?.accept_control().await?;
        let (socket, meta, cfg) = accepted.into_legacy_parts();
        Ok(Acceptor {
            socket,
            remote_addr: meta.remote_addr,
            #[cfg(feature = "tls")]
            acceptor: self.tls_acceptor.clone(),
            cfg,
            typ: self.typ,
        })
    }

    /// Returns the bound local socket address for this listener.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        if let Some(tcp_listener) = &self.tcp_listener {
            Ok(tcp_listener.local_addr()?)
        } else {
            #[cfg(feature = "quic")]
            if let Some(endpoint) = &self.quinn_endpoint {
                Ok(endpoint.local_addr()?)
            } else {
                Err(anyhow!("No active listener (neither TCP nor QUIC endpoint is available)"))
            }
            #[cfg(not(feature = "quic"))]
            Err(anyhow!("No active listener"))
        }
    }
}

/// Connection handler for processing client streams
pub struct Acceptor<S> {
    /// Underlying network transport
    pub(crate) socket: S,
    #[cfg(feature = "tls")]
    acceptor: Option<TlsAcceptor>,
    /// Remote client address
    pub remote_addr: SocketAddr,
    /// Shared server configuration
    pub cfg: Arc<Builder>,
    /// Active protocol type
    pub typ: ListenerType,
}

#[cfg(feature = "quic")]
impl Acceptor<QuinnBiStream> {
    /// Returns whether the accepted QUIC stream was opened using 0-RTT data.
    pub fn is_quic_0rtt(&self) -> bool {
        self.socket.is_0rtt()
    }
}

impl<S> Acceptor<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Creates TCP protocol dispatcher
    #[inline]
    pub fn tcp(self) -> Result<Dispatcher<S>> {
        if matches!(self.typ, ListenerType::TCP) {
            Ok(Dispatcher::new(self.socket, self.remote_addr, None, self.cfg))
        } else {
            Err(anyhow!("Protocol mismatch: Expected TCP listener"))
        }
    }

    #[cfg(feature = "tls")]
    /// Performs TLS handshake and creates secure dispatcher
    #[inline]
    pub async fn tls(self) -> Result<Dispatcher<TlsStream<S>>> {
        if !matches!(self.typ, ListenerType::TLS) {
            return Err(anyhow!("Protocol mismatch: Expected TLS listener"));
        }

        let acceptor = self.acceptor.ok_or_else(|| crate::MqttError::ServiceUnavailable)?;
        let tls_s = match tokio::time::timeout(self.cfg.handshake_timeout, acceptor.accept(self.socket)).await
        {
            Ok(Ok(tls_s)) => tls_s,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(crate::MqttError::ReadTimeout.into()),
        };

        let cert_info = Self::get_extract_cert_info(
            &tls_s,
            self.cfg.cert_cn_as_username,
            self.cfg.cert_subject_dn_as_username,
            self.cfg.collect_cert_info,
        );

        Ok(Dispatcher::new(tls_s, self.remote_addr, cert_info, self.cfg))
    }

    #[cfg(feature = "ws")]
    /// Performs WebSocket upgrade and creates WS dispatcher
    #[inline]
    pub async fn ws(self) -> Result<Dispatcher<WsStream<S>>> {
        if !matches!(self.typ, ListenerType::WS) {
            return Err(anyhow!("Protocol mismatch: Expected WS listener"));
        }

        match tokio::time::timeout(self.cfg.handshake_timeout, accept_hdr_async(self.socket, on_handshake))
            .await
        {
            Ok(Ok(ws_stream)) => {
                Ok(Dispatcher::new(WsStream::new(ws_stream), self.remote_addr, None, self.cfg.clone()))
            }
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(crate::MqttError::ReadTimeout.into()),
        }
    }

    #[cfg(feature = "tls")]
    #[cfg(feature = "ws")]
    /// Performs TLS handshake and WebSocket upgrade
    #[inline]
    pub async fn wss(self) -> Result<Dispatcher<WsStream<TlsStream<S>>>> {
        if !matches!(self.typ, ListenerType::WSS) {
            return Err(anyhow!("Protocol mismatch: Expected WSS listener"));
        }

        let acceptor = self.acceptor.ok_or_else(|| crate::MqttError::ServiceUnavailable)?;
        let tls_s = match tokio::time::timeout(self.cfg.handshake_timeout, acceptor.accept(self.socket)).await
        {
            Ok(Ok(tls_s)) => tls_s,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(crate::MqttError::ReadTimeout.into()),
        };

        let cert_info = Self::get_extract_cert_info(
            &tls_s,
            self.cfg.cert_cn_as_username,
            self.cfg.cert_subject_dn_as_username,
            self.cfg.collect_cert_info,
        );

        match tokio::time::timeout(self.cfg.handshake_timeout, accept_hdr_async(tls_s, on_handshake)).await {
            Ok(Ok(ws_stream)) => {
                Ok(Dispatcher::new(WsStream::new(ws_stream), self.remote_addr, cert_info, self.cfg.clone()))
            }
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(crate::MqttError::ReadTimeout.into()),
        }
    }

    #[cfg(feature = "quic")]
    #[inline]
    pub async fn quic(self) -> Result<Dispatcher<S>> {
        if !matches!(self.typ, ListenerType::QUIC) {
            return Err(anyhow!("Protocol mismatch: Expected QUIC listener"));
        }
        Ok(Dispatcher::new(self.socket, self.remote_addr, None, self.cfg))
    }

    #[inline]
    #[cfg(feature = "tls")]
    fn get_extract_cert_info<C: TlsCertExtractor>(
        io: &C,
        cert_cn_as_username: bool,
        cert_subject_dn_as_username: bool,
        collect_cert_info: bool,
    ) -> Option<CertInfo> {
        if cert_cn_as_username || cert_subject_dn_as_username || collect_cert_info {
            // Extract cert info BEFORE consuming self
            let cert_info: Option<CertInfo> = io.extract_cert_info();
            // Certificate info is now available in s.cert_info
            if let Some(ref cert) = cert_info {
                log::debug!("Client certificate: {cert}");
                log::debug!("CN: {:?}, Org: {:?}", cert.common_name, cert.organization);
            }
            cert_info
        } else {
            None
        }
    }
}

#[allow(clippy::result_large_err)]
#[cfg(feature = "ws")]
/// Validates WebSocket handshake requests for MQTT protocol
fn on_handshake(req: &Request, mut response: Response) -> std::result::Result<Response, ErrorResponse> {
    const PROTOCOL_ERROR: &str = "Missing required 'Sec-WebSocket-Protocol: mqtt' header";
    let mqtt_protocol = req
        .headers()
        .get("Sec-WebSocket-Protocol")
        .ok_or_else(|| ErrorResponse::new(Some(PROTOCOL_ERROR.into())))?
        .to_str()
        .map_err(|_| ErrorResponse::new(Some(PROTOCOL_ERROR.into())))?;
    match mqtt_protocol {
        "mqtt" => {
            response.headers_mut().append(
                "Sec-WebSocket-Protocol",
                "mqtt".parse().map_err(|_| ErrorResponse::new(Some("InvalidHeaderValue".into())))?,
            );
        }
        "mqttv3.1" => {
            response.headers_mut().append(
                "Sec-WebSocket-Protocol",
                "mqttv3.1".parse().map_err(|_| ErrorResponse::new(Some("InvalidHeaderValue".into())))?,
            );
        }
        _ => {
            return Err(ErrorResponse::new(Some(PROTOCOL_ERROR.into())));
        }
    }
    Ok(response)
}

// from https://github.com/zhboner/realm/blob/master/realm_core/src/tcp/proxy.rs
fn handle_header(header: ProxyHeader) -> Option<(SocketAddr, SocketAddr)> {
    use ProxyHeader::{Version1, Version2};
    match header {
        Version1 { addresses } => handle_header_v1(addresses),
        Version2 { command, transport_protocol, addresses } => {
            handle_header_v2(command, transport_protocol, addresses)
        }
        _ => {
            log::info!("[tcp]accept proxy-protocol-v?");
            None
        }
    }
}

fn handle_header_v1(addr: v1::ProxyAddresses) -> Option<(SocketAddr, SocketAddr)> {
    use v1::ProxyAddresses::*;
    match addr {
        Unknown => {
            log::debug!("[tcp]accept proxy-protocol-v1: unknown");
            None
        }
        Ipv4 { source, destination } => {
            log::debug!("[tcp]accept proxy-protocol-v1: {} => {}", source, destination);
            Some((SocketAddr::V4(source), SocketAddr::V4(destination)))
        }
        Ipv6 { source, destination } => {
            log::debug!("[tcp]accept proxy-protocol-v1: {} => {}", source, destination);
            Some((SocketAddr::V6(source), SocketAddr::V6(destination)))
        }
    }
}

fn handle_header_v2(
    cmd: v2::ProxyCommand,
    proto: v2::ProxyTransportProtocol,
    addr: v2::ProxyAddresses,
) -> Option<(SocketAddr, SocketAddr)> {
    use v2::ProxyAddresses as Address;
    use v2::ProxyCommand as Command;
    use v2::ProxyTransportProtocol as Protocol;

    // The connection endpoints are the sender and the receiver.
    // Such connections exist when the proxy sends health-checks to the server.
    // The receiver must accept this connection as valid and must use the
    // real connection endpoints and discard the protocol block including the
    // family which is ignored
    if let Command::Local = cmd {
        log::debug!("[tcp]accept proxy-protocol-v2: command = LOCAL, ignore");
        return None;
    }

    // only get tcp address
    match proto {
        Protocol::Stream => {}
        Protocol::Unspec => {
            log::debug!("[tcp]accept proxy-protocol-v2: protocol = UNSPEC, ignore");
            return None;
        }
        Protocol::Datagram => {
            log::debug!("[tcp]accept proxy-protocol-v2: protocol = DGRAM, ignore");
            return None;
        }
    }

    match addr {
        Address::Ipv4 { source, destination } => {
            log::debug!("[tcp]accept proxy-protocol-v2: {} => {}", source, destination);
            Some((SocketAddr::V4(source), SocketAddr::V4(destination)))
        }
        Address::Ipv6 { source, destination } => {
            log::debug!("[tcp]accept proxy-protocol-v2: {} => {}", source, destination);
            Some((SocketAddr::V6(source), SocketAddr::V6(destination)))
        }
        Address::Unspec => {
            log::debug!("[tcp]accept proxy-protocol-v2: af_family = AF_UNSPEC, ignore");
            None
        }
        Address::Unix { .. } => {
            log::debug!("[tcp]accept proxy-protocol-v2: af_family = AF_UNIX, ignore");
            None
        }
    }
}

#[cfg(feature = "tls")]
fn read_ca_certs(cert_file: &str) -> Result<Vec<CertificateDer<'static>>> {
    CertificateDer::pem_file_iter(cert_file)
        .map_err(|e| anyhow!(e))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow!(e))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Builder, ZeroRttCredentialProfile, ZeroRttMode};

    #[test]
    fn builder_carries_default_and_bounded_multistream_config() {
        let builder = Builder::new();

        assert_eq!(builder.multistream_mode, "disabled");
        assert_eq!(builder.multistream_max_data_streams, 8);
        assert_eq!(builder.multistream_stream_open_rate, 32);
        assert_eq!(builder.multistream_stream_idle_timeout, Duration::from_secs(60));
        assert_eq!(builder.multistream_connection_mailbox_packets, 256);
        assert_eq!(builder.multistream_connection_buffer_bytes, 1024 * 1024);

        let builder = Builder::new()
            .multistream_mode("simple")
            .multistream_max_data_streams(u32::MAX)
            .multistream_stream_open_rate(16)
            .multistream_stream_idle_timeout(Duration::from_secs(30))
            .multistream_connection_mailbox_packets(128)
            .multistream_connection_buffer_bytes(512 * 1024);

        assert_eq!(builder.multistream_mode, "simple");
        assert_eq!(builder.multistream_max_data_streams, u32::MAX - 1);
        assert_eq!(builder.multistream_stream_open_rate, 16);
        assert_eq!(builder.multistream_stream_idle_timeout, Duration::from_secs(30));
        assert_eq!(builder.multistream_connection_mailbox_packets, 128);
        assert_eq!(builder.multistream_connection_buffer_bytes, 512 * 1024);
    }

    #[test]
    fn builder_carries_default_zero_rtt_policy() {
        let builder = Builder::new();

        assert!(!builder.enable_quic_0rtt);
        assert_eq!(builder.quic_0rtt_mode, ZeroRttMode::Disabled);
        assert_eq!(builder.quic_0rtt_credential_profile, ZeroRttCredentialProfile::Deny);
        assert_eq!(builder.quic_0rtt_auth_policy_epoch, 0);
        assert_eq!(builder.quic_0rtt_ticket_capacity, 4096);
        assert_eq!(builder.quic_0rtt_ticket_ttl, Duration::from_secs(10 * 60));
        assert_eq!(builder.quic_0rtt_pre_finished_read_budget, 64 * 1024);
    }

    #[test]
    fn builder_configures_zero_rtt_policy() {
        let builder = Builder::new()
            .quic_0rtt_mode("handshake_gated")
            .quic_0rtt_credential_profile("short_lived_token")
            .quic_0rtt_auth_policy_epoch(9)
            .quic_0rtt_ticket_capacity(128)
            .quic_0rtt_ticket_ttl(Duration::from_secs(30))
            .quic_0rtt_pre_finished_read_budget(32 * 1024);

        assert!(builder.enable_quic_0rtt);
        assert_eq!(builder.quic_0rtt_mode, ZeroRttMode::HandshakeGated);
        assert_eq!(builder.quic_0rtt_credential_profile, ZeroRttCredentialProfile::ShortLivedToken);
        assert_eq!(builder.quic_0rtt_auth_policy_epoch, 9);
        assert_eq!(builder.quic_0rtt_ticket_capacity, 128);
        assert_eq!(builder.quic_0rtt_ticket_ttl, Duration::from_secs(30));
        assert_eq!(builder.quic_0rtt_pre_finished_read_budget, 32 * 1024);
    }
}
