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
        .quic_0rtt_credential_profile("anonymous")
        .bind_quic()?;
    let server_addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let result: Result<()> = async {
            for (expected, expected_0rtt) in [("first", false), ("zero-rtt", true)] {
                let accepted = listener.next_quic().await?.accept_control().await?;
                assert_eq!(accepted.meta().is_0rtt, expected_0rtt);
                let (stream, _activation, _) = accepted.mqtt().await?.into_parts();
                let MqttStream::V3(mut stream) = stream else {
                    panic!("expected MQTT v3 stream");
                };
                let connect = stream.recv_connect(Duration::from_secs(1)).await?;
                assert_eq!(AsRef::<str>::as_ref(&connect.client_id), expected);
                stream.send_connect_ack(ConnectAckReason::ConnectionAccepted, false).await?;
                stream.flush().await?;
                let _ = stream.next().await;
            }
            Ok(())
        }
        .await;
        if let Err(error) = &result {
            eprintln!("QUIC test server failed: {error:#}");
        }
        result
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
        .quic_0rtt_credential_profile("anonymous")
        .bind_quic();

    let Err(error) = result else {
        panic!("0-RTT must not bypass completion of mutual TLS authentication");
    };
    assert!(error.to_string().contains("mutual TLS"));
    Ok(())
}

#[tokio::test]
async fn quic_0rtt_rejects_default_deny_credential_profile() -> Result<()> {
    let result = Builder::new()
        .name("quic-0rtt-deny-test")
        .laddr("127.0.0.1:0".parse()?)
        .tls_cert(Some(test_certificate_path().to_string_lossy()))
        .tls_key(Some(test_private_key_path().to_string_lossy()))
        .quic_0rtt_mode("handshake_gated")
        .bind_quic();

    let Err(error) = result else {
        panic!("0-RTT must require an explicit credential profile");
    };
    assert!(error.to_string().contains("credential profile"));
    Ok(())
}

#[tokio::test]
async fn quic_0rtt_rejects_anonymous_profile_on_non_anonymous_listener() -> Result<()> {
    let result = Builder::new()
        .name("quic-0rtt-anonymous-policy-test")
        .laddr("127.0.0.1:0".parse()?)
        .allow_anonymous(false)
        .tls_cert(Some(test_certificate_path().to_string_lossy()))
        .tls_key(Some(test_private_key_path().to_string_lossy()))
        .quic_0rtt_mode("handshake_gated")
        .quic_0rtt_credential_profile("anonymous")
        .bind_quic();

    let Err(error) = result else {
        panic!("0-RTT anonymous credentials must not be accepted on non-anonymous listeners");
    };
    assert!(error.to_string().contains("anonymous"));
    Ok(())
}

#[tokio::test]
async fn quic_0rtt_accepts_short_lived_token_policy_on_non_anonymous_listener() -> Result<()> {
    let listener = Builder::new()
        .name("quic-0rtt-token-policy-test")
        .laddr("127.0.0.1:0".parse()?)
        .allow_anonymous(false)
        .tls_cert(Some(test_certificate_path().to_string_lossy()))
        .tls_key(Some(test_private_key_path().to_string_lossy()))
        .quic_0rtt_mode("handshake_gated")
        .quic_0rtt_credential_profile("short_lived_token")
        .quic_0rtt_auth_policy_epoch(11)
        .quic_0rtt_ticket_capacity(32)
        .quic_0rtt_ticket_ttl(Duration::from_secs(20))
        .quic_0rtt_pre_finished_read_budget(16 * 1024)
        .bind_quic()?;

    assert_eq!(listener.local_addr()?.ip().to_string(), "127.0.0.1");
    Ok(())
}

#[tokio::test]
async fn quic_0rtt_rejects_short_lived_token_profile_on_anonymous_listener() -> Result<()> {
    let result = Builder::new()
        .name("quic-0rtt-token-anonymous-test")
        .laddr("127.0.0.1:0".parse()?)
        .allow_anonymous(true)
        .tls_cert(Some(test_certificate_path().to_string_lossy()))
        .tls_key(Some(test_private_key_path().to_string_lossy()))
        .quic_0rtt_mode("handshake_gated")
        .quic_0rtt_credential_profile("short_lived_token")
        .bind_quic();

    let Err(error) = result else {
        panic!("short-lived token profile must not silently allow anonymous access");
    };
    assert!(error.to_string().contains("anonymous access"));
    Ok(())
}

#[tokio::test]
async fn quic_listener_initially_allows_only_the_control_bidi_stream() -> Result<()> {
    let listener = Builder::new()
        .name("quic-control-stream-limit-test")
        .laddr("127.0.0.1:0".parse()?)
        .tls_cert(Some(test_certificate_path().to_string_lossy()))
        .tls_key(Some(test_private_key_path().to_string_lossy()))
        .bind_quic()?;
    let server_addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let _control = listener.accept_quic().await?;
        tokio::time::sleep(Duration::from_millis(250)).await;
        Result::<()>::Ok(())
    });

    let mut endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(test_client_config()?);
    let connection = endpoint.connect(server_addr, "localhost")?.await?;

    let (mut control_send, _control_recv) = connection.open_bi().await?;
    control_send.write_all(b"control").await?;

    let second = tokio::time::timeout(Duration::from_millis(100), connection.open_bi()).await;
    assert!(second.is_err(), "a data stream must remain blocked until MQTT CONNACK activation");

    connection.close(0_u32.into(), b"done");
    server.await??;
    endpoint.wait_idle().await;
    Ok(())
}

#[tokio::test]
async fn slow_connection_without_a_control_stream_does_not_block_next_quic_incoming() -> Result<()> {
    let listener = Arc::new(
        Builder::new()
            .name("quic-incoming-seam-test")
            .laddr("127.0.0.1:0".parse()?)
            .tls_cert(Some(test_certificate_path().to_string_lossy()))
            .tls_key(Some(test_private_key_path().to_string_lossy()))
            .bind_quic()?,
    );
    let server_addr = listener.local_addr()?;

    let server_listener = listener.clone();
    let server = tokio::spawn(async move {
        let _slow = server_listener.next_quic().await?;
        let next = tokio::time::timeout(Duration::from_secs(1), server_listener.next_quic()).await??;
        let _accepted = next.accept_control().await?;
        Result::<()>::Ok(())
    });

    let mut endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(test_client_config()?);

    let slow = endpoint.connect(server_addr, "localhost")?.await?;
    let fast = endpoint.connect(server_addr, "localhost")?.await?;
    let (mut send, _recv) = fast.open_bi().await?;
    send.write_all(b"control").await?;

    server.await??;
    slow.close(0_u32.into(), b"done");
    fast.close(0_u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

#[tokio::test]
async fn quic_pending_handshake_limit_bounds_unverified_connections() -> Result<()> {
    let listener = Arc::new(
        Builder::new()
            .name("quic-pending-handshake-limit-test")
            .laddr("127.0.0.1:0".parse()?)
            .max_handshaking_limit(1)
            .tls_cert(Some(test_certificate_path().to_string_lossy()))
            .tls_key(Some(test_private_key_path().to_string_lossy()))
            .bind_quic()?,
    );
    let server_addr = listener.local_addr()?;
    let (first_seen_tx, first_seen_rx) = tokio::sync::oneshot::channel();

    let server_listener = listener.clone();
    let server = tokio::spawn(async move {
        let first = server_listener.next_quic().await?;
        let _ = first_seen_tx.send(());

        let while_full = tokio::time::timeout(Duration::from_millis(100), server_listener.next_quic()).await;
        assert!(while_full.is_err(), "unverified QUIC connections must consume the pending-handshake quota");

        drop(first);
        let _second = tokio::time::timeout(Duration::from_secs(1), server_listener.next_quic()).await??;
        Result::<()>::Ok(())
    });

    let mut endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(test_client_config()?);
    let first_endpoint = endpoint.clone();
    let first = tokio::spawn(async move {
        Result::<quinn::Connection>::Ok(first_endpoint.connect(server_addr, "localhost")?.await?)
    });
    first_seen_rx.await?;
    let second_endpoint = endpoint.clone();
    let second = tokio::spawn(async move {
        Result::<quinn::Connection>::Ok(second_endpoint.connect(server_addr, "localhost")?.await?)
    });

    server.await??;
    first.abort();
    second.abort();
    endpoint.close(0_u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

#[tokio::test]
async fn quic_control_timeout_releases_pending_handshake_permit() -> Result<()> {
    let listener = Arc::new(
        Builder::new()
            .name("quic-handshake-timeout-release-test")
            .laddr("127.0.0.1:0".parse()?)
            .max_handshaking_limit(1)
            .handshake_timeout(Duration::from_millis(100))
            .tls_cert(Some(test_certificate_path().to_string_lossy()))
            .tls_key(Some(test_private_key_path().to_string_lossy()))
            .bind_quic()?,
    );
    let server_addr = listener.local_addr()?;
    let (first_seen_tx, first_seen_rx) = tokio::sync::oneshot::channel();

    let server_listener = listener.clone();
    let server = tokio::spawn(async move {
        let first = server_listener.next_quic().await?;
        let _ = first_seen_tx.send(());
        let Err(error) = first.accept_control().await else {
            panic!("control stream timeout must fail ingress");
        };
        assert!(error.to_string().contains("Timed out waiting for MQTT control stream"));

        let second = tokio::time::timeout(Duration::from_secs(1), server_listener.next_quic()).await??;
        let _accepted = second.accept_control().await?;
        Result::<()>::Ok(())
    });

    let mut endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(test_client_config()?);
    let first = endpoint.connect(server_addr, "localhost")?.await?;
    first_seen_rx.await?;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let second = endpoint.connect(server_addr, "localhost")?.await?;
    let (mut send, _recv) = second.open_bi().await?;
    send.write_all(b"control").await?;

    server.await??;
    first.close(0_u32.into(), b"done");
    second.close(0_u32.into(), b"done");
    endpoint.wait_idle().await;
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
        panic!("expected MQTT CONNACK for {client_id}, got {response:?}");
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
