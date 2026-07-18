use rmqtt_net::{
    Builder, FlowId, FlowKind, LinkEvent, MqttLink, MqttStream, ReplyPath, Result, SendTarget, SerialMqttLink,
};

use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use rmqtt_codec::types::Protocol;
use rmqtt_codec::v3::{Codec, Connect, Packet};
use rmqtt_codec::{MqttCodec, MqttPacket};
use tokio::io::duplex;
use tokio_util::codec::Framed;

type TestIo = tokio::io::DuplexStream;
type TestClient = Framed<TestIo, MqttCodec>;

#[tokio::test]
async fn serial_link_receives_and_sends_control_packets() -> Result<()> {
    let (mut client, mut link) = serial_v3_link()?;

    client
        .send(MqttPacket::V3(Packet::Connect(Box::new(Connect {
            protocol: Protocol(4),
            clean_session: true,
            keep_alive: 30,
            last_will: None,
            client_id: "serial-link".into(),
            username: None,
            password: None,
            cert: None,
        }))))
        .await?;

    let event = link.recv().await?.expect("packet event");
    let LinkEvent::Packet { packet, reply_path } = event else {
        panic!("serial links only emit packet events");
    };
    assert_eq!(reply_path, ReplyPath::control());
    assert!(matches!(packet, MqttPacket::V3(Packet::Connect(_))));

    let receipt = link.send(SendTarget::Reply(reply_path), MqttPacket::V3(Packet::PingResponse {})).await?;
    assert_eq!(receipt.path(), ReplyPath::control());
    link.flush().await?;
    assert_ping_response(&mut client).await?;

    link.send(SendTarget::Control, MqttPacket::V3(Packet::PingResponse {})).await?;
    link.flush().await?;
    assert_ping_response(&mut client).await?;

    link.send(SendTarget::Bound(ReplyPath::control().flow_id()), MqttPacket::V3(Packet::PingResponse {}))
        .await?;
    link.flush().await?;
    assert_ping_response(&mut client).await?;

    let data_reply_path = ReplyPath::new(FlowId::new(1), FlowKind::Data, 7);
    let error = link
        .send(SendTarget::Reply(data_reply_path), MqttPacket::V3(Packet::PingResponse {}))
        .await
        .expect_err("data reply paths are not valid on serial links");
    assert!(error.to_string().contains("control flow"));

    let error = link
        .send(SendTarget::Bound(FlowId::new(1)), MqttPacket::V3(Packet::PingResponse {}))
        .await
        .expect_err("data flows are not valid on serial links");
    assert!(error.to_string().contains("control flow"));

    link.close().await?;
    Ok(())
}

#[test]
fn reply_paths_include_connection_generation() {
    let first = ReplyPath::new(FlowId::new(4), FlowKind::Data, 11);
    let second = ReplyPath::new(FlowId::new(4), FlowKind::Data, 12);

    assert_ne!(first, second);
    assert_eq!(first.generation(), 11);
    assert_eq!(second.generation(), 12);
}

#[test]
fn serial_link_can_return_inner_stream() -> Result<()> {
    let (_client, link) = serial_v3_link()?;
    let _stream = link.into_inner();
    Ok(())
}

async fn assert_ping_response(client: &mut TestClient) -> Result<()> {
    let response = client.next().await.expect("response packet")?;
    assert!(matches!(response.0, MqttPacket::V3(Packet::PingResponse)));
    Ok(())
}

fn serial_v3_link() -> Result<(TestClient, SerialMqttLink<TestIo>)> {
    let (client_io, server_io) = duplex(4096);
    let client = Framed::new(client_io, MqttCodec::V3(Codec::new(1024 * 1024)));
    let server_stream = rmqtt_net::v3::MqttStream {
        io: Framed::new(server_io, MqttCodec::V3(Codec::new(1024 * 1024))),
        remote_addr: "127.0.0.1:1883".parse()?,
        cfg: Arc::new(Builder::new().send_timeout(Duration::from_secs(1))),
        #[cfg(feature = "tls")]
        cert_info: None,
    };
    Ok((client, SerialMqttLink::new(MqttStream::V3(server_stream))))
}
