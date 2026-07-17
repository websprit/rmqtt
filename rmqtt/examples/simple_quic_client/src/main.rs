//! Example: MQTT client over QUIC transport.
//! Establishes one MQTT/QUIC connection to obtain a TLS session ticket, then reconnects and sends
//! MQTT CONNECT as QUIC 0-RTT data. The example waits for 0-RTT acceptance before sending PUBLISH,
//! because non-idempotent MQTT packets must not be sent as replayable early data.

use bytes::Bytes;
use bytestring::ByteString;
use futures::{SinkExt, StreamExt};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::Endpoint;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{DigitallySignedStruct, SignatureScheme};
use simple_logger::SimpleLogger;
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::codec::Framed;

/// AWS-LC based TLS provider (non-Windows platforms)
#[cfg(not(target_os = "windows"))]
pub use rustls::crypto::aws_lc_rs as tls_provider;
/// Ring-based TLS provider (Windows platforms)
#[cfg(target_os = "windows")]
pub use rustls::crypto::ring as tls_provider;

use rmqtt_codec::{
    types::{Protocol, Publish, QoS},
    v3::{Codec as CodecV3, Connect},
    MqttCodec, MqttPacket,
};
use rmqtt_net::{QuinnBiStream, Result};

type MqttQuicStream = Framed<QuinnBiStream, MqttCodec>;

#[tokio::main]
async fn main() -> Result<()> {
    SimpleLogger::new().with_level(log::LevelFilter::Info).init()?;

    let client_config = build_client_config()?;

    // Bind local UDP port
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    let server_addr = "127.0.0.1:9443".parse()?;

    // The first connection completes a normal handshake so the client can receive a session ticket.
    let first = endpoint.connect(server_addr, "localhost")?.await?;
    let mut framed = send_connect(&first, "cid-ticket").await?;
    recv_connack(&mut framed).await?;
    publish_once(&mut framed).await?;
    framed.close().await?;
    first.close(0_u32.into(), b"reconnect with 0-rtt");
    tokio::time::sleep(Duration::from_millis(50)).await;

    // The second connection sends CONNECT before the resumed TLS handshake completes.
    let connecting = endpoint.connect(server_addr, "localhost")?;
    let (connection, mut framed) = match connecting.into_0rtt() {
        Ok((connection, accepted)) => {
            let mut framed = send_connect(&connection, "cid-0rtt").await?;
            if accepted.await {
                log::info!("Server accepted MQTT CONNECT as QUIC 0-RTT data");
                recv_connack(&mut framed).await?;
                (connection, framed)
            } else {
                log::warn!("Server rejected QUIC 0-RTT; retransmitting CONNECT after the handshake");
                drop(framed);
                let mut framed = send_connect(&connection, "cid-0rtt").await?;
                recv_connack(&mut framed).await?;
                (connection, framed)
            }
        }
        Err(connecting) => {
            log::warn!("No reusable 0-RTT ticket; falling back to a normal QUIC handshake");
            let connection = connecting.await?;
            let mut framed = send_connect(&connection, "cid-0rtt").await?;
            recv_connack(&mut framed).await?;
            (connection, framed)
        }
    };

    // Wait until early data is accepted before sending state-changing MQTT packets.
    publish_once(&mut framed).await?;
    framed.close().await?;
    connection.close(0_u32.into(), b"done");
    endpoint.wait_idle().await;

    Ok(())
}

async fn send_connect(connection: &quinn::Connection, client_id: &str) -> Result<MqttQuicStream> {
    let (send, recv) = connection.open_bi().await?;
    let stream = QuinnBiStream::new(send, recv);
    let mut framed = Framed::new(stream, MqttCodec::V3(CodecV3::new(1024 * 1024)));
    let connect = Connect {
        protocol: Protocol(4),
        clean_session: true,
        keep_alive: 60,
        last_will: None,
        client_id: client_id.into(),
        username: None,
        password: None,
        cert: None,
    };
    framed.send(MqttPacket::V3(rmqtt_codec::v3::Packet::Connect(Box::new(connect)))).await?;
    framed.flush().await?;
    log::info!("Sent CONNECT");
    Ok(framed)
}

async fn recv_connack(framed: &mut MqttQuicStream) -> Result<()> {
    if let Some(Ok((MqttPacket::V3(rmqtt_codec::v3::Packet::ConnectAck(ack)), _))) = framed.next().await {
        log::info!("Received CONNACK: {ack:?}");
        Ok(())
    } else {
        Err(anyhow::anyhow!("Expected CONNACK from MQTT/QUIC server"))
    }
}

async fn publish_once(framed: &mut MqttQuicStream) -> Result<()> {
    let publish = Publish {
        dup: false,
        retain: false,
        qos: QoS::AtLeastOnce,
        topic: ByteString::from_static("test"),
        packet_id: Some(NonZeroU16::new(1).unwrap()),
        payload: Bytes::from_static(b"data ..."),
        properties: None,
    };
    framed.send(MqttPacket::V3(rmqtt_codec::v3::Packet::Publish(Box::new(publish)))).await?;
    framed.flush().await?;
    log::info!("Sent PUBLISH");

    if let Some(Ok((MqttPacket::V3(rmqtt_codec::v3::Packet::PublishAck { packet_id }), _))) =
        framed.next().await
    {
        log::info!("Received PUBACK for packet_id {packet_id:?}");
        Ok(())
    } else {
        Err(anyhow::anyhow!("Expected PUBACK from MQTT/QUIC server"))
    }
}

fn build_client_config() -> Result<quinn::ClientConfig> {
    // Select TLS provider
    let provider = Arc::new(tls_provider::default_provider());

    // Client-side TLS configuration (allow self-signed certificates)
    let roots = rustls::RootCertStore::empty();
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();

    client_crypto.alpn_protocols = vec![b"mqtt".to_vec(), b"mqttv5".to_vec()];
    client_crypto.enable_early_data = true;
    client_crypto.dangerous().set_certificate_verifier(Arc::new(SkipServerVerification));

    let server_crypto = QuicClientConfig::try_from(client_crypto)?;
    let client_config = quinn::ClientConfig::new(Arc::new(server_crypto));

    Ok(client_config)
}

// ======== SkipServerVerification ========
/// Custom certificate verifier that skips all certificate validation.
/// This should **only** be used for testing purposes.
#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
        ]
    }
}
