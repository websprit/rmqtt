#![cfg(feature = "quic")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{Connection, Endpoint};
use rustls::pki_types::pem::PemObject;
use tokio_util::codec::Framed;

use rmqtt_codec::types::Protocol;
use rmqtt_codec::v3::{Codec, Connect, ConnectAckReason, Packet};
use rmqtt_codec::{MqttCodec, MqttPacket};
use rmqtt_net::{tls_provider, Builder, MqttStream, QuinnBiStream, Result};

#[tokio::test]
async fn enabled_quic_listener_accepts_mqtt_data_in_zero_rtt() -> Result<()> {
    let listener = Builder::new()
        .name("quic-0rtt-test")
        .laddr("127.0.0.1:0".parse()?)
        .tls_cert(Some(test_certificate_path().to_string_lossy()))
        .tls_key(Some(test_private_key_path().to_string_lossy()))
        .enable_quic_0rtt(true)
        .bind_quic()?;
    let server_addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        for (expected, expected_0rtt) in [("first", false), ("zero-rtt", true)] {
            let mut acceptor = listener.accept_quic().await?;
            assert_eq!(acceptor.is_quic_0rtt(), expected_0rtt);
            let handshake_complete = acceptor.take_quic_handshake_complete();
            assert!(handshake_complete.is_some());
            let stream = acceptor.quic().await?;
            let MqttStream::V3(mut stream) = stream.mqtt().await? else {
                panic!("expected MQTT v3 stream");
            };
            handshake_complete.unwrap().await;
            let connect = stream.recv_connect(Duration::from_secs(1)).await?;
            assert_eq!(AsRef::<str>::as_ref(&connect.client_id), expected);
            stream.send_connect_ack(ConnectAckReason::ConnectionAccepted, false).await?;
            stream.flush().await?;
            let _ = stream.next().await;
        }
        Result::<()>::Ok(())
    });

    let mut endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(test_client_config()?);

    let first = endpoint.connect(server_addr, "localhost")?.await?;
    exchange_connect(&first, "first").await?;
    first.close(0_u32.into(), b"ticket received");
    tokio::time::sleep(Duration::from_millis(20)).await;

    let connecting = endpoint.connect(server_addr, "localhost")?;
    let (resumed, accepted) = connecting.into_0rtt().expect("server did not advertise QUIC 0-RTT");
    exchange_connect(&resumed, "zero-rtt").await?;
    assert!(accepted.await, "server rejected QUIC 0-RTT data");
    resumed.close(0_u32.into(), b"done");

    server.await??;
    endpoint.wait_idle().await;
    Ok(())
}

#[tokio::test]
async fn quic_0rtt_rejects_mutual_tls_listener() -> Result<()> {
    let result = Builder::new()
        .name("quic-0rtt-mtls-test")
        .laddr("127.0.0.1:0".parse()?)
        .tls_cross_certificate(true)
        .tls_cert(Some(test_certificate_path().to_string_lossy()))
        .tls_key(Some(test_private_key_path().to_string_lossy()))
        .enable_quic_0rtt(true)
        .bind_quic();

    let Err(error) = result else {
        panic!("0-RTT must not bypass completion of mutual TLS authentication");
    };
    assert!(error.to_string().contains("mutual TLS"));
    Ok(())
}

async fn exchange_connect(connection: &Connection, client_id: &str) -> Result<()> {
    let (send, recv) = connection.open_bi().await?;
    let stream = QuinnBiStream::new(send, recv);
    let mut framed = Framed::new(stream, MqttCodec::V3(Codec::new(1024 * 1024)));
    let connect = Connect {
        protocol: Protocol(4),
        clean_session: false,
        keep_alive: 60,
        last_will: None,
        client_id: client_id.into(),
        username: None,
        password: None,
        cert: None,
    };
    framed.send(MqttPacket::V3(Packet::Connect(Box::new(connect)))).await?;
    framed.flush().await?;

    let response = framed.next().await;
    let Some(Ok((MqttPacket::V3(Packet::ConnectAck(ack)), _))) = response else {
        panic!("expected MQTT CONNACK, got {response:?}");
    };
    assert_eq!(ack.return_code, ConnectAckReason::ConnectionAccepted);
    framed.close().await?;
    Ok(())
}

fn test_client_config() -> Result<quinn::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls::pki_types::CertificateDer::pem_file_iter(test_ca_path())? {
        roots.add(cert?)?;
    }

    let provider = Arc::new(tls_provider::default_provider());
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"mqtt".to_vec(), b"mqttv5".to_vec()];
    crypto.enable_early_data = true;

    Ok(quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?)))
}

fn test_certificate_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rmqtt-bin/rmqtt.pem")
}

fn test_private_key_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rmqtt-bin/rmqtt.key")
}

fn test_ca_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rmqtt-bin/root.pem")
}
