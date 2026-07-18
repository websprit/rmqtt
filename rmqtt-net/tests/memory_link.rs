use rmqtt_codec::v3;
use rmqtt_codec::v5;
use rmqtt_codec::MqttPacket;
pub use rmqtt_net::{
    ClosedEvent, ConnectionCloseReason, FlowCloseReason, FlowId, FlowKind, LinkEvent, MemoryMqttLink,
    MqttLink, ReplyPath, Result, SendReceipt, SendTarget, SentPacket,
};

#[tokio::test]
async fn memory_link_receives_injected_events_for_multiple_flows_in_order() -> Result<()> {
    let (mut link, handle) = MemoryMqttLink::new();
    let cloned_handle = link.handle();
    let first_path = handle.next_reply_path(FlowKind::Data);
    let second_path = handle.next_reply_path(FlowKind::Data);

    handle.inject_packet(v3_ping_request(), first_path);
    handle.inject_event(LinkEvent::FlowClosed {
        flow_id: second_path.flow_id(),
        reason: FlowCloseReason::RecvFinished,
    });
    handle.inject_packet(v5_ping_request(), second_path);
    assert_eq!(cloned_handle.queued_len(), 3);

    let first = link.recv().await?.expect("first event");
    let LinkEvent::Packet { packet, reply_path } = first else {
        panic!("expected packet event");
    };
    assert_eq!(reply_path, first_path);
    assert!(matches!(packet, MqttPacket::V3(v3::Packet::PingRequest)));

    let second = link.recv().await?.expect("second event");
    assert!(matches!(
        second,
        LinkEvent::FlowClosed {
            flow_id,
            reason: FlowCloseReason::RecvFinished,
        } if flow_id == second_path.flow_id()
    ));

    let third = link.recv().await?.expect("third event");
    let LinkEvent::Packet { packet, reply_path } = third else {
        panic!("expected packet event");
    };
    assert_eq!(reply_path, second_path);
    assert!(matches!(packet, MqttPacket::V5(v5::Packet::PingRequest)));
    assert!(link.recv().await?.is_none());

    Ok(())
}

#[tokio::test]
async fn memory_link_captures_ordered_sends_with_resolved_receipts() -> Result<()> {
    let (mut link, handle) = MemoryMqttLink::new();
    let data_path = handle.next_reply_path(FlowKind::Data);

    let control_receipt = link.send(SendTarget::Control, v3_ping_response()).await?;
    let reply_receipt = link.send(SendTarget::Reply(data_path), v5_ping_response()).await?;
    let bound_receipt = link.send(SendTarget::Bound(data_path.flow_id()), v3_ping_response()).await?;

    assert_eq!(control_receipt.path(), ReplyPath::control());
    assert_eq!(reply_receipt.path(), data_path);
    assert_eq!(bound_receipt.path(), data_path);

    let sent = handle.take_sent();
    assert_eq!(sent.len(), 3);

    assert_sent(&sent[0], SendTarget::Control, control_receipt, |packet| {
        matches!(packet, MqttPacket::V3(v3::Packet::PingResponse))
    });
    assert_sent(&sent[1], SendTarget::Reply(data_path), reply_receipt, |packet| {
        matches!(packet, MqttPacket::V5(v5::Packet::PingResponse))
    });
    assert_sent(&sent[2], SendTarget::Bound(data_path.flow_id()), bound_receipt, |packet| {
        matches!(packet, MqttPacket::V3(v3::Packet::PingResponse))
    });
    assert_eq!(handle.sent_len(), 0);

    Ok(())
}

#[tokio::test]
async fn memory_link_can_fail_the_next_send_or_flush_deterministically() -> Result<()> {
    let (mut link, handle) = MemoryMqttLink::new();

    handle.fail_next_send("injected send failure");
    let send_error =
        link.send(SendTarget::Control, v3_ping_response()).await.expect_err("next send should fail");
    assert!(send_error.to_string().contains("injected send failure"));
    assert_eq!(handle.sent_len(), 0);

    link.send(SendTarget::Control, v3_ping_response()).await?;
    assert_eq!(handle.sent_len(), 1);

    handle.fail_next_flush("injected flush failure");
    let flush_error = link.flush().await.expect_err("next flush should fail");
    assert!(flush_error.to_string().contains("injected flush failure"));
    link.flush().await?;

    Ok(())
}

#[tokio::test]
async fn memory_link_records_reset_and_close_as_closed_state_and_events() -> Result<()> {
    let (mut link, handle) = MemoryMqttLink::new();
    let data_path = handle.next_reply_path(FlowKind::Data);

    link.reset_flow(data_path.flow_id(), FlowCloseReason::SendFailed).await?;
    link.close_connection(ConnectionCloseReason::ProtocolViolation).await?;
    assert_eq!(handle.closed_len(), 2);

    let closed = handle.take_closed();
    assert_eq!(
        closed,
        vec![
            ClosedEvent::Flow { flow_id: data_path.flow_id(), reason: FlowCloseReason::SendFailed },
            ClosedEvent::Connection { reason: ConnectionCloseReason::ProtocolViolation },
        ]
    );

    assert!(matches!(
        link.recv().await?,
        Some(LinkEvent::FlowClosed {
            flow_id,
            reason: FlowCloseReason::SendFailed,
        }) if flow_id == data_path.flow_id()
    ));
    assert!(matches!(
        link.recv().await?,
        Some(LinkEvent::ConnectionClosed { reason: ConnectionCloseReason::ProtocolViolation })
    ));

    Ok(())
}

#[test]
fn memory_link_generates_deterministic_reply_paths() {
    let (_link, handle) = MemoryMqttLink::new();

    let first = handle.next_reply_path(FlowKind::Data);
    let second = handle.next_reply_path(FlowKind::Data);
    let first_again = handle.reply_path_for(first.flow_id(), FlowKind::Data);

    assert_eq!(first, ReplyPath::new(FlowId::new(1), FlowKind::Data, 1));
    assert_eq!(second, ReplyPath::new(FlowId::new(2), FlowKind::Data, 1));
    assert_eq!(first_again, first);
    assert_eq!(handle.next_reply_path(FlowKind::Control), ReplyPath::control());
}

fn assert_sent(
    sent: &SentPacket,
    target: SendTarget,
    receipt: SendReceipt,
    packet_matches: impl FnOnce(&MqttPacket) -> bool,
) {
    assert_eq!(sent.target, target);
    assert_eq!(sent.receipt, receipt);
    assert!(packet_matches(&sent.packet));
}

fn v3_ping_request() -> MqttPacket {
    MqttPacket::V3(v3::Packet::PingRequest)
}

fn v3_ping_response() -> MqttPacket {
    MqttPacket::V3(v3::Packet::PingResponse)
}

fn v5_ping_request() -> MqttPacket {
    MqttPacket::V5(v5::Packet::PingRequest)
}

fn v5_ping_response() -> MqttPacket {
    MqttPacket::V5(v5::Packet::PingResponse)
}
