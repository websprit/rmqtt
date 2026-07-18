#![cfg(feature = "quic")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::Endpoint;
use rmqtt_codec::types::{Protocol, Publish, QoS};
use rmqtt_codec::v3::{Codec, Connect, ConnectAckReason, Packet};
use rmqtt_codec::{MqttCodec, MqttPacket};
use rmqtt_net::{
    tls_provider, Builder, FlowCloseReason, LinkEvent, MqttLink, MqttStream, QuinnBiStream, Result,
    SendTarget,
};
use rustls::pki_types::pem::PemObject;
use tokio::sync::oneshot;
use tokio_util::codec::Framed;

#[tokio::test]
async fn connack_commit_activates_only_the_configured_data_streams() -> Result<()> {
    let listener = Builder::new()
        .name("quic-multistream-activation-test")
        .laddr("127.0.0.1:0".parse()?)
        .tls_cert(Some(test_certificate_path().to_string_lossy()))
        .tls_key(Some(test_private_key_path().to_string_lossy()))
        .multistream_mode("simple")
        .multistream_max_data_streams(2)
        .bind_quic()?;
    let server_addr = listener.local_addr()?;
    let (connect_read_tx, connect_read_rx) = oneshot::channel();
    let (commit_tx, commit_rx) = oneshot::channel();
    let (flows_received_tx, flows_received_rx) = oneshot::channel();
    let (close_tx, close_rx) = oneshot::channel();

    let server = tokio::spawn(async move {
        let accepted = listener.next_quic().await?.accept_control().await?.mqtt().await?;
        let (stream, activation, _) = accepted.into_parts();
        let MqttStream::V3(mut control) = stream else {
            panic!("expected MQTT v3 control stream");
        };
        let connect = control.recv_connect(Duration::from_secs(1)).await?;
        assert_eq!(AsRef::<str>::as_ref(&connect.client_id), "multistream");
        let _ = connect_read_tx.send(());
        let _ = commit_rx.await;

        let committed = activation
            .send_v3_connack_and_commit(&mut control, ConnectAckReason::ConnectionAccepted, false)
            .await?;
        let mut link = committed.activate_multistream(MqttStream::V3(control), 2);

        let first = link.recv().await?.expect("first data-flow packet");
        let second = link.recv().await?.expect("second data-flow packet");
        let (first_path, second_path) = match (first, second) {
            (
                LinkEvent::Packet { packet: MqttPacket::V3(Packet::Publish(_)), reply_path: first },
                LinkEvent::Packet { packet: MqttPacket::V3(Packet::Publish(_)), reply_path: second },
            ) => (first, second),
            events => panic!("unexpected multistream events: {events:?}"),
        };
        assert_ne!(first_path.flow_id(), second_path.flow_id());
        assert_eq!(first_path.generation(), second_path.generation());
        link.send(
            SendTarget::Reply(first_path),
            MqttPacket::V3(Packet::Publish(Box::new(test_publish("reply-one")))),
        )
        .await?;
        link.send(
            SendTarget::Reply(second_path),
            MqttPacket::V3(Packet::Publish(Box::new(test_publish("reply-two")))),
        )
        .await?;
        let _ = flows_received_tx.send(());
        let _ = close_rx.await;
        link.close().await?;
        Result::<()>::Ok(())
    });

    let mut endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(test_client_config()?);
    let connection = endpoint.connect(server_addr, "localhost")?.await?;
    let (control_send, control_recv) = connection.open_bi().await?;
    let mut control =
        Framed::new(QuinnBiStream::new(control_send, control_recv), MqttCodec::V3(Codec::new(1024 * 1024)));
    control.send(MqttPacket::V3(Packet::Connect(Box::new(test_connect())))).await?;
    connect_read_rx.await?;

    let preactivation = tokio::time::timeout(Duration::from_millis(100), connection.open_bi()).await;
    assert!(preactivation.is_err(), "data streams must stay blocked before CONNACK commit");
    let _ = commit_tx.send(());

    let response = control.next().await.expect("CONNACK packet")?;
    assert!(matches!(
        response.0,
        MqttPacket::V3(Packet::ConnectAck(ref ack)) if ack.return_code == ConnectAckReason::ConnectionAccepted
    ));

    let mut first = open_v3_data_flow(&connection).await?;
    let mut second = open_v3_data_flow(&connection).await?;
    first.send(MqttPacket::V3(Packet::Publish(Box::new(test_publish("one"))))).await?;
    second.send(MqttPacket::V3(Packet::Publish(Box::new(test_publish("two"))))).await?;
    flows_received_rx.await?;
    assert!(matches!(first.next().await.expect("first flow reply")?.0, MqttPacket::V3(Packet::Publish(_))));
    assert!(matches!(second.next().await.expect("second flow reply")?.0, MqttPacket::V3(Packet::Publish(_))));

    let extra = tokio::time::timeout(Duration::from_millis(100), connection.open_bi()).await;
    assert!(extra.is_err(), "the negotiated data-flow limit must remain bounded");
    let _ = close_tx.send(());

    server.await??;
    endpoint.wait_idle().await;
    Ok(())
}

#[tokio::test]
async fn ping_on_data_flow_resets_only_that_flow() -> Result<()> {
    let listener = Builder::new()
        .name("quic-data-ping-test")
        .laddr("127.0.0.1:0".parse()?)
        .tls_cert(Some(test_certificate_path().to_string_lossy()))
        .tls_key(Some(test_private_key_path().to_string_lossy()))
        .multistream_mode("simple")
        .multistream_max_data_streams(1)
        .bind_quic()?;
    let server_addr = listener.local_addr()?;
    let (flow_reset_tx, flow_reset_rx) = oneshot::channel();

    let server = tokio::spawn(async move {
        let accepted = listener.next_quic().await?.accept_control().await?.mqtt().await?;
        let (stream, activation, _) = accepted.into_parts();
        let MqttStream::V3(mut control) = stream else {
            panic!("expected MQTT v3 control stream");
        };
        control.recv_connect(Duration::from_secs(1)).await?;
        let committed = activation
            .send_v3_connack_and_commit(&mut control, ConnectAckReason::ConnectionAccepted, false)
            .await?;
        let mut link = committed.activate_multistream(MqttStream::V3(control), 1);

        assert!(matches!(
            link.recv().await?,
            Some(LinkEvent::FlowClosed { reason: FlowCloseReason::ProtocolViolation, .. })
        ));
        let _ = flow_reset_tx.send(());
        assert!(matches!(
            link.recv().await?,
            Some(LinkEvent::Packet {
                packet: MqttPacket::V3(Packet::PingRequest),
                reply_path,
            }) if reply_path.flow_id() == rmqtt_net::FlowId::CONTROL
        ));
        link.close().await?;
        Result::<()>::Ok(())
    });

    let mut endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(test_client_config()?);
    let connection = endpoint.connect(server_addr, "localhost")?.await?;
    let (control_send, control_recv) = connection.open_bi().await?;
    let mut control =
        Framed::new(QuinnBiStream::new(control_send, control_recv), MqttCodec::V3(Codec::new(1024 * 1024)));
    control.send(MqttPacket::V3(Packet::Connect(Box::new(test_connect())))).await?;
    let _ = control.next().await.expect("CONNACK")?;

    let mut data = open_v3_data_flow(&connection).await?;
    data.send(MqttPacket::V3(Packet::PingRequest)).await?;
    flow_reset_rx.await?;
    control.send(MqttPacket::V3(Packet::PingRequest)).await?;

    server.await??;
    endpoint.wait_idle().await;
    Ok(())
}

#[tokio::test]
async fn data_flow_exceeding_connection_byte_budget_is_reset() -> Result<()> {
    let listener = Builder::new()
        .name("quic-data-buffer-budget-test")
        .laddr("127.0.0.1:0".parse()?)
        .tls_cert(Some(test_certificate_path().to_string_lossy()))
        .tls_key(Some(test_private_key_path().to_string_lossy()))
        .multistream_mode("simple")
        .multistream_max_data_streams(1)
        .multistream_connection_buffer_bytes(8)
        .bind_quic()?;
    let server_addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let accepted = listener.next_quic().await?.accept_control().await?.mqtt().await?;
        let (stream, activation, _) = accepted.into_parts();
        let MqttStream::V3(mut control) = stream else {
            panic!("expected MQTT v3 control stream");
        };
        control.recv_connect(Duration::from_secs(1)).await?;
        let committed = activation
            .send_v3_connack_and_commit(&mut control, ConnectAckReason::ConnectionAccepted, false)
            .await?;
        let mut link = committed.activate_multistream(MqttStream::V3(control), 1);

        assert!(matches!(
            link.recv().await?,
            Some(LinkEvent::FlowClosed { reason: FlowCloseReason::ResourceLimit, .. })
        ));
        link.close().await?;
        Result::<()>::Ok(())
    });

    let mut endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(test_client_config()?);
    let connection = endpoint.connect(server_addr, "localhost")?.await?;
    let (control_send, control_recv) = connection.open_bi().await?;
    let mut control =
        Framed::new(QuinnBiStream::new(control_send, control_recv), MqttCodec::V3(Codec::new(1024 * 1024)));
    control.send(MqttPacket::V3(Packet::Connect(Box::new(test_connect())))).await?;
    let _ = control.next().await.expect("CONNACK")?;

    let mut data = open_v3_data_flow(&connection).await?;
    data.send(MqttPacket::V3(Packet::Publish(Box::new(test_publish("exceeds-budget"))))).await?;

    server.await??;
    endpoint.wait_idle().await;
    Ok(())
}

#[tokio::test]
async fn peer_reset_on_idle_data_flow_does_not_close_control_flow() -> Result<()> {
    let listener = Builder::new()
        .name("quic-data-peer-reset-test")
        .laddr("127.0.0.1:0".parse()?)
        .tls_cert(Some(test_certificate_path().to_string_lossy()))
        .tls_key(Some(test_private_key_path().to_string_lossy()))
        .multistream_mode("simple")
        .multistream_max_data_streams(1)
        .bind_quic()?;
    let server_addr = listener.local_addr()?;
    let (flow_reset_tx, flow_reset_rx) = oneshot::channel();

    let server = tokio::spawn(async move {
        let accepted = listener.next_quic().await?.accept_control().await?.mqtt().await?;
        let (stream, activation, _) = accepted.into_parts();
        let MqttStream::V3(mut control) = stream else {
            panic!("expected MQTT v3 control stream");
        };
        control.recv_connect(Duration::from_secs(1)).await?;
        let committed = activation
            .send_v3_connack_and_commit(&mut control, ConnectAckReason::ConnectionAccepted, false)
            .await?;
        let mut link = committed.activate_multistream(MqttStream::V3(control), 1);

        assert!(matches!(
            link.recv().await?,
            Some(LinkEvent::FlowClosed { reason: FlowCloseReason::RecvReset(77), .. })
        ));
        let _ = flow_reset_tx.send(());
        assert!(matches!(
            link.recv().await?,
            Some(LinkEvent::Packet {
                packet: MqttPacket::V3(Packet::PingRequest),
                reply_path,
            }) if reply_path.flow_id() == rmqtt_net::FlowId::CONTROL
        ));
        link.close().await?;
        Result::<()>::Ok(())
    });

    let mut endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(test_client_config()?);
    let connection = endpoint.connect(server_addr, "localhost")?.await?;
    let (control_send, control_recv) = connection.open_bi().await?;
    let mut control =
        Framed::new(QuinnBiStream::new(control_send, control_recv), MqttCodec::V3(Codec::new(1024 * 1024)));
    control.send(MqttPacket::V3(Packet::Connect(Box::new(test_connect())))).await?;
    let _ = control.next().await.expect("CONNACK")?;

    let (mut data_send, _data_recv) = connection.open_bi().await?;
    data_send.reset(77_u32.into())?;
    flow_reset_rx.await?;
    control.send(MqttPacket::V3(Packet::PingRequest)).await?;

    server.await??;
    endpoint.wait_idle().await;
    Ok(())
}

#[tokio::test]
async fn peer_stop_on_data_flow_send_isolated_from_control_flow() -> Result<()> {
    let listener = Builder::new()
        .name("quic-data-peer-stop-test")
        .laddr("127.0.0.1:0".parse()?)
        .tls_cert(Some(test_certificate_path().to_string_lossy()))
        .tls_key(Some(test_private_key_path().to_string_lossy()))
        .multistream_mode("simple")
        .multistream_max_data_streams(1)
        .bind_quic()?;
    let server_addr = listener.local_addr()?;
    let (flow_seen_tx, flow_seen_rx) = oneshot::channel();
    let (peer_stopped_tx, peer_stopped_rx) = oneshot::channel();
    let (flow_closed_tx, flow_closed_rx) = oneshot::channel();

    let server = tokio::spawn(async move {
        let accepted = listener.next_quic().await?.accept_control().await?.mqtt().await?;
        let (stream, activation, _) = accepted.into_parts();
        let MqttStream::V3(mut control) = stream else {
            panic!("expected MQTT v3 control stream");
        };
        control.recv_connect(Duration::from_secs(1)).await?;
        let committed = activation
            .send_v3_connack_and_commit(&mut control, ConnectAckReason::ConnectionAccepted, false)
            .await?;
        let mut link = committed.activate_multistream(MqttStream::V3(control), 1);

        let Some(LinkEvent::Packet { packet: MqttPacket::V3(Packet::Publish(_)), reply_path }) =
            link.recv().await?
        else {
            panic!("expected data-flow PUBLISH");
        };
        let _ = flow_seen_tx.send(());
        let _ = peer_stopped_rx.await;
        assert!(link
            .send(
                SendTarget::Reply(reply_path),
                MqttPacket::V3(Packet::Publish(Box::new(test_publish("reply")))),
            )
            .await
            .is_err());
        assert!(matches!(
            link.recv().await?,
            Some(LinkEvent::FlowClosed { reason: FlowCloseReason::SendStopped(88), .. })
        ));
        let _ = flow_closed_tx.send(());
        assert!(matches!(
            link.recv().await?,
            Some(LinkEvent::Packet {
                packet: MqttPacket::V3(Packet::PingRequest),
                reply_path,
            }) if reply_path.flow_id() == rmqtt_net::FlowId::CONTROL
        ));
        link.close().await?;
        Result::<()>::Ok(())
    });

    let mut endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(test_client_config()?);
    let connection = endpoint.connect(server_addr, "localhost")?.await?;
    let (control_send, control_recv) = connection.open_bi().await?;
    let mut control =
        Framed::new(QuinnBiStream::new(control_send, control_recv), MqttCodec::V3(Codec::new(1024 * 1024)));
    control.send(MqttPacket::V3(Packet::Connect(Box::new(test_connect())))).await?;
    let _ = control.next().await.expect("CONNACK")?;

    let mut data = open_v3_data_flow(&connection).await?;
    data.send(MqttPacket::V3(Packet::Publish(Box::new(test_publish("request"))))).await?;
    flow_seen_rx.await?;
    data.get_mut().stop_receiving(88)?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = peer_stopped_tx.send(());
    flow_closed_rx.await?;
    control.send(MqttPacket::V3(Packet::PingRequest)).await?;

    server.await??;
    endpoint.wait_idle().await;
    Ok(())
}

async fn open_v3_data_flow(connection: &quinn::Connection) -> Result<Framed<QuinnBiStream, MqttCodec>> {
    let (send, recv) = connection.open_bi().await?;
    Ok(Framed::new(QuinnBiStream::new(send, recv), MqttCodec::V3(Codec::new(1024 * 1024))))
}

fn test_connect() -> Connect {
    Connect {
        protocol: Protocol(4),
        clean_session: true,
        keep_alive: 60,
        last_will: None,
        client_id: "multistream".into(),
        username: None,
        password: None,
        cert: None,
    }
}

fn test_publish(payload: &'static str) -> Publish {
    Publish {
        dup: false,
        retain: false,
        qos: QoS::AtMostOnce,
        topic: "test/data".into(),
        packet_id: None,
        payload: payload.as_bytes().to_vec().into(),
        properties: None,
    }
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
