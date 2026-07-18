use std::num::{NonZeroU16, NonZeroU32};
use std::sync::Arc;

use anyhow::anyhow;
use rmqtt_codec::version::ProtocolVersion;
use rmqtt_codec::MqttPacket;
use rmqtt_net::{
    ConnectionCloseReason, FlowCloseReason, FlowId, LinkEvent, MqttLink, ReplyPath, SendReceipt, SendTarget,
};

use crate::codec::{v3, v5};
use crate::types::{Packet, Publish, PublishResult, ServerTopicAliases};
use crate::Result;

#[derive(Debug)]
pub(crate) enum SessionLinkEvent {
    Packet { packet: Packet, reply_path: ReplyPath },
    FlowClosed { flow_id: FlowId, reason: FlowCloseReason },
    ConnectionClosed { reason: ConnectionCloseReason },
}

#[derive(Debug)]
pub(crate) struct SessionLink<L> {
    protocol: ProtocolVersion,
    inner: L,
}

impl<L> SessionLink<L> {
    #[inline]
    pub(crate) fn new(protocol: ProtocolVersion, inner: L) -> Self {
        Self { protocol, inner }
    }

    #[inline]
    pub(crate) fn protocol(&self) -> ProtocolVersion {
        self.protocol
    }

    #[cfg(test)]
    #[inline]
    fn inner(&self) -> &L {
        &self.inner
    }
}

impl<L> SessionLink<L>
where
    L: MqttLink,
{
    #[inline]
    pub(crate) async fn recv(&mut self) -> Result<Option<SessionLinkEvent>> {
        let Some(event) = self.inner.recv().await? else {
            return Ok(None);
        };

        match event {
            LinkEvent::Packet { packet, reply_path } => {
                let packet = self.decode_packet(packet)?;
                Ok(Some(SessionLinkEvent::Packet { packet, reply_path }))
            }
            LinkEvent::FlowClosed { flow_id, reason } => {
                Ok(Some(SessionLinkEvent::FlowClosed { flow_id, reason }))
            }
            LinkEvent::ConnectionClosed { reason } => Ok(Some(SessionLinkEvent::ConnectionClosed { reason })),
        }
    }

    #[inline]
    pub(crate) async fn close(&mut self) -> Result<()> {
        self.inner.close().await
    }

    #[inline]
    pub(crate) async fn reset_flow(&mut self, flow_id: FlowId, reason: FlowCloseReason) -> Result<()> {
        self.inner.reset_flow(flow_id, reason).await
    }

    #[inline]
    pub(crate) async fn close_connection(&mut self, reason: ConnectionCloseReason) -> Result<()> {
        self.inner.close_connection(reason).await
    }

    #[inline]
    pub(crate) async fn publish(
        &mut self,
        target: SendTarget,
        mut publish: Publish,
        message_expiry_interval: Option<NonZeroU32>,
        server_topic_aliases: Option<&Arc<ServerTopicAliases>>,
    ) -> Result<SendReceipt> {
        if self.protocol == ProtocolVersion::MQTT5 {
            let (topic, alias) = if let Some(server_topic_aliases) = server_topic_aliases {
                server_topic_aliases.get(publish.topic.clone()).await
            } else {
                (Some(publish.topic.clone()), None)
            };

            publish.topic = topic.unwrap_or_default();
            if let Some(properties) = &mut publish.properties {
                properties.message_expiry_interval = message_expiry_interval;
                properties.topic_alias = alias;
            }
        }

        let packet = match self.protocol {
            ProtocolVersion::MQTT3 => MqttPacket::V3(v3::Packet::Publish(publish.take())),
            ProtocolVersion::MQTT5 => MqttPacket::V5(v5::Packet::Publish(publish.take())),
        };
        self.inner.send(target, packet).await
    }

    #[inline]
    pub(crate) async fn send_publish_ack(
        &mut self,
        target: SendTarget,
        packet_id: NonZeroU16,
        pubres: PublishResult,
    ) -> Result<SendReceipt> {
        let packet = match self.protocol {
            ProtocolVersion::MQTT3 => MqttPacket::V3(v3::Packet::PublishAck { packet_id }),
            ProtocolVersion::MQTT5 => MqttPacket::V5(v5::Packet::PublishAck(v5::PublishAck {
                packet_id,
                reason_code: pubres.reason_code,
                properties: pubres.properties,
                reason_string: pubres.reason_string,
            })),
        };
        self.inner.send(target, packet).await
    }

    #[inline]
    pub(crate) async fn send_publish_received(
        &mut self,
        target: SendTarget,
        packet_id: NonZeroU16,
        pubres: PublishResult,
    ) -> Result<SendReceipt> {
        let packet = match self.protocol {
            ProtocolVersion::MQTT3 => MqttPacket::V3(v3::Packet::PublishReceived { packet_id }),
            ProtocolVersion::MQTT5 => MqttPacket::V5(v5::Packet::PublishReceived(v5::PublishAck {
                packet_id,
                reason_code: pubres.reason_code,
                properties: pubres.properties,
                reason_string: pubres.reason_string,
            })),
        };
        self.inner.send(target, packet).await
    }

    #[inline]
    pub(crate) async fn send_publish_release(
        &mut self,
        target: SendTarget,
        packet_id: NonZeroU16,
        reason_code: Option<v5::PublishAck2Reason>,
    ) -> Result<SendReceipt> {
        let packet = match self.protocol {
            ProtocolVersion::MQTT3 => {
                if matches!(reason_code, Some(v5::PublishAck2Reason::PacketIdNotFound)) {
                    return Err(anyhow!("MQTT v3 PUBREL does not support non-success reason codes"));
                }
                MqttPacket::V3(v3::Packet::PublishRelease { packet_id })
            }
            ProtocolVersion::MQTT5 => MqttPacket::V5(v5::Packet::PublishRelease(v5::PublishAck2 {
                packet_id,
                reason_code: reason_code.unwrap_or(v5::PublishAck2Reason::Success),
                ..Default::default()
            })),
        };
        self.inner.send(target, packet).await
    }

    #[inline]
    pub(crate) async fn send_publish_complete(
        &mut self,
        target: SendTarget,
        packet_id: NonZeroU16,
        reason_code: Option<v5::PublishAck2Reason>,
    ) -> Result<SendReceipt> {
        let packet = match self.protocol {
            ProtocolVersion::MQTT3 => {
                if matches!(reason_code, Some(v5::PublishAck2Reason::PacketIdNotFound)) {
                    return Err(anyhow!("MQTT v3 PUBCOMP does not support non-success reason codes"));
                }
                MqttPacket::V3(v3::Packet::PublishComplete { packet_id })
            }
            ProtocolVersion::MQTT5 => MqttPacket::V5(v5::Packet::PublishComplete(v5::PublishAck2 {
                packet_id,
                reason_code: reason_code.unwrap_or(v5::PublishAck2Reason::Success),
                ..Default::default()
            })),
        };
        self.inner.send(target, packet).await
    }

    #[inline]
    pub(crate) async fn send_subscribe_ack_v3(
        &mut self,
        target: SendTarget,
        packet_id: NonZeroU16,
        status: Vec<v3::SubscribeReturnCode>,
    ) -> Result<SendReceipt> {
        self.send(target, Packet::V3(v3::Packet::SubscribeAck { packet_id, status })).await
    }

    #[inline]
    pub(crate) async fn send_subscribe_ack_v5(
        &mut self,
        target: SendTarget,
        ack: v5::SubscribeAck,
    ) -> Result<SendReceipt> {
        self.send(target, Packet::V5(v5::Packet::SubscribeAck(ack))).await
    }

    #[inline]
    pub(crate) async fn send_unsubscribe_ack_v3(
        &mut self,
        target: SendTarget,
        packet_id: NonZeroU16,
    ) -> Result<SendReceipt> {
        self.send(target, Packet::V3(v3::Packet::UnsubscribeAck { packet_id })).await
    }

    #[inline]
    pub(crate) async fn send_unsubscribe_ack_v5(
        &mut self,
        target: SendTarget,
        ack: v5::UnsubscribeAck,
    ) -> Result<SendReceipt> {
        self.send(target, Packet::V5(v5::Packet::UnsubscribeAck(ack))).await
    }

    #[inline]
    pub(crate) async fn send_ping_response(&mut self, target: SendTarget) -> Result<SendReceipt> {
        let packet = match self.protocol {
            ProtocolVersion::MQTT3 => Packet::V3(v3::Packet::PingResponse),
            ProtocolVersion::MQTT5 => Packet::V5(v5::Packet::PingResponse),
        };
        self.send(target, packet).await
    }

    #[inline]
    pub(crate) async fn send_auth(&mut self, target: SendTarget, auth: v5::Auth) -> Result<SendReceipt> {
        self.send(target, Packet::V5(v5::Packet::Auth(auth))).await
    }

    #[inline]
    pub(crate) async fn send_disconnect(
        &mut self,
        target: SendTarget,
        disconnect: v5::Disconnect,
    ) -> Result<SendReceipt> {
        self.send(target, Packet::V5(v5::Packet::Disconnect(disconnect))).await
    }

    #[inline]
    pub(crate) async fn send(&mut self, target: SendTarget, packet: Packet) -> Result<SendReceipt> {
        let packet = self.encode_packet(packet)?;
        self.inner.send(target, packet).await
    }

    #[inline]
    fn decode_packet(&self, packet: MqttPacket) -> Result<Packet> {
        match (self.protocol, packet) {
            (ProtocolVersion::MQTT3, MqttPacket::V3(packet)) => Ok(Packet::V3(packet)),
            (ProtocolVersion::MQTT5, MqttPacket::V5(packet)) => Ok(Packet::V5(packet)),
            (ProtocolVersion::MQTT3, MqttPacket::V5(_)) => {
                Err(anyhow!("received MQTT v5 packet on MQTT v3 session link"))
            }
            (ProtocolVersion::MQTT5, MqttPacket::V3(_)) => {
                Err(anyhow!("received MQTT v3 packet on MQTT v5 session link"))
            }
            (_, MqttPacket::Version(_)) => {
                Err(anyhow!("received protocol version probe packet on active session link"))
            }
        }
    }

    #[inline]
    fn encode_packet(&self, packet: Packet) -> Result<MqttPacket> {
        match (self.protocol, packet) {
            (ProtocolVersion::MQTT3, Packet::V3(packet)) => Ok(MqttPacket::V3(packet)),
            (ProtocolVersion::MQTT5, Packet::V5(packet)) => Ok(MqttPacket::V5(packet)),
            (ProtocolVersion::MQTT3, Packet::V5(_)) => {
                Err(anyhow!("cannot send MQTT v5 packet on MQTT v3 session link"))
            }
            (ProtocolVersion::MQTT5, Packet::V3(_)) => {
                Err(anyhow!("cannot send MQTT v3 packet on MQTT v5 session link"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use bytes::Bytes;
    use bytestring::ByteString;
    use rmqtt_codec::types::{Publish as CodecPublish, QoS};
    use rmqtt_codec::v5::{PublishProperties, SubscribeAckReason, UnsubscribeAckReason};
    use rmqtt_net::{FlowKind, SendReceipt};

    use super::*;

    #[derive(Debug, Default)]
    struct FakeMqttLink {
        events: VecDeque<LinkEvent>,
        sent: Vec<(SendTarget, MqttPacket)>,
        closed: bool,
    }

    impl FakeMqttLink {
        fn push_packet(&mut self, packet: MqttPacket, reply_path: ReplyPath) {
            self.events.push_back(LinkEvent::Packet { packet, reply_path });
        }

        fn last_sent(&self) -> &(SendTarget, MqttPacket) {
            self.sent.last().expect("packet should have been sent")
        }
    }

    impl MqttLink for FakeMqttLink {
        async fn recv(&mut self) -> rmqtt_net::Result<Option<LinkEvent>> {
            Ok(self.events.pop_front())
        }

        async fn send(&mut self, target: SendTarget, packet: MqttPacket) -> rmqtt_net::Result<SendReceipt> {
            self.sent.push((target, packet));
            let reply_path = match target {
                SendTarget::Control => ReplyPath::control(),
                SendTarget::Reply(path) => path,
                SendTarget::Bound(flow_id) => ReplyPath::new(flow_id, FlowKind::Data, 9),
            };
            Ok(SendReceipt::new(reply_path))
        }

        async fn flush(&mut self) -> rmqtt_net::Result<()> {
            Ok(())
        }

        async fn reset_flow(&mut self, _flow_id: FlowId, _reason: FlowCloseReason) -> rmqtt_net::Result<()> {
            Ok(())
        }

        async fn close_connection(&mut self, _reason: ConnectionCloseReason) -> rmqtt_net::Result<()> {
            self.closed = true;
            Ok(())
        }
    }

    #[tokio::test]
    async fn recv_maps_packets_and_preserves_reply_path() {
        let reply_path = ReplyPath::new(FlowId::new(7), FlowKind::Data, 3);
        let mut fake = FakeMqttLink::default();
        fake.push_packet(MqttPacket::V3(v3::Packet::PingRequest), reply_path);

        let mut link = SessionLink::new(ProtocolVersion::MQTT3, fake);
        let event = link.recv().await.unwrap().unwrap();

        match event {
            SessionLinkEvent::Packet { packet: Packet::V3(v3::Packet::PingRequest), reply_path: actual } => {
                assert_eq!(actual, reply_path)
            }
            event => panic!("unexpected event: {event:?}"),
        }
    }

    #[tokio::test]
    async fn send_ping_response_preserves_target() {
        let reply_path = ReplyPath::new(FlowId::new(11), FlowKind::Data, 5);
        let mut link = SessionLink::new(ProtocolVersion::MQTT3, FakeMqttLink::default());

        let receipt = link.send_ping_response(SendTarget::Reply(reply_path)).await.unwrap();

        assert_eq!(receipt.path(), reply_path);
        let (target, packet) = link.inner().last_sent();
        assert_eq!(*target, SendTarget::Reply(reply_path));
        assert!(matches!(packet, MqttPacket::V3(v3::Packet::PingResponse)));
    }

    #[tokio::test]
    async fn v3_helpers_construct_v3_ack_packets() {
        let packet_id = packet_id(12);
        let mut link = SessionLink::new(ProtocolVersion::MQTT3, FakeMqttLink::default());

        link.send_publish_ack(SendTarget::Control, packet_id, PublishResult::success()).await.unwrap();
        link.send_publish_received(SendTarget::Control, packet_id, PublishResult::success()).await.unwrap();
        link.send_publish_release(SendTarget::Control, packet_id, None).await.unwrap();
        link.send_publish_complete(SendTarget::Control, packet_id, None).await.unwrap();
        link.send_subscribe_ack_v3(
            SendTarget::Control,
            packet_id,
            vec![v3::SubscribeReturnCode::Success(QoS::AtLeastOnce)],
        )
        .await
        .unwrap();
        link.send_unsubscribe_ack_v3(SendTarget::Control, packet_id).await.unwrap();

        let sent = &link.inner().sent;
        assert!(matches!(
            sent[0].1,
            MqttPacket::V3(v3::Packet::PublishAck { packet_id: id }) if id == packet_id
        ));
        assert!(matches!(
            sent[1].1,
            MqttPacket::V3(v3::Packet::PublishReceived { packet_id: id }) if id == packet_id
        ));
        assert!(matches!(
            sent[2].1,
            MqttPacket::V3(v3::Packet::PublishRelease { packet_id: id }) if id == packet_id
        ));
        assert!(matches!(
            sent[3].1,
            MqttPacket::V3(v3::Packet::PublishComplete { packet_id: id }) if id == packet_id
        ));
        assert!(matches!(
            &sent[4].1,
            MqttPacket::V3(v3::Packet::SubscribeAck { packet_id: id, status })
                if *id == packet_id
                    && status == &vec![v3::SubscribeReturnCode::Success(QoS::AtLeastOnce)]
        ));
        assert!(matches!(
            sent[5].1,
            MqttPacket::V3(v3::Packet::UnsubscribeAck { packet_id: id }) if id == packet_id
        ));
    }

    #[tokio::test]
    async fn v5_helpers_construct_v5_packets() {
        let packet_id = packet_id(21);
        let mut link = SessionLink::new(ProtocolVersion::MQTT5, FakeMqttLink::default());

        link.send_publish_ack(SendTarget::Control, packet_id, PublishResult::success()).await.unwrap();
        link.send_publish_received(SendTarget::Control, packet_id, PublishResult::success()).await.unwrap();
        link.send_publish_release(
            SendTarget::Control,
            packet_id,
            Some(v5::PublishAck2Reason::PacketIdNotFound),
        )
        .await
        .unwrap();
        link.send_publish_complete(SendTarget::Control, packet_id, None).await.unwrap();
        link.send_subscribe_ack_v5(
            SendTarget::Control,
            v5::SubscribeAck {
                packet_id,
                properties: Vec::new(),
                reason_string: None,
                status: vec![SubscribeAckReason::GrantedQos1],
            },
        )
        .await
        .unwrap();
        link.send_unsubscribe_ack_v5(
            SendTarget::Control,
            v5::UnsubscribeAck {
                packet_id,
                properties: Vec::new(),
                reason_string: None,
                status: vec![UnsubscribeAckReason::Success],
            },
        )
        .await
        .unwrap();
        link.send_auth(SendTarget::Control, v5::Auth::default()).await.unwrap();
        link.send_disconnect(
            SendTarget::Control,
            v5::Disconnect::new(v5::DisconnectReasonCode::NormalDisconnection),
        )
        .await
        .unwrap();

        let sent = &link.inner().sent;
        assert!(matches!(
            sent[0].1,
            MqttPacket::V5(v5::Packet::PublishAck(v5::PublishAck { packet_id: id, .. })) if id == packet_id
        ));
        assert!(matches!(
            sent[1].1,
            MqttPacket::V5(v5::Packet::PublishReceived(v5::PublishAck { packet_id: id, .. })) if id == packet_id
        ));
        assert!(matches!(
            sent[2].1,
            MqttPacket::V5(v5::Packet::PublishRelease(v5::PublishAck2 {
                packet_id: id,
                reason_code: v5::PublishAck2Reason::PacketIdNotFound,
                ..
            })) if id == packet_id
        ));
        assert!(matches!(
            sent[3].1,
            MqttPacket::V5(v5::Packet::PublishComplete(v5::PublishAck2 {
                packet_id: id,
                reason_code: v5::PublishAck2Reason::Success,
                ..
            })) if id == packet_id
        ));
        assert!(matches!(
            &sent[4].1,
            MqttPacket::V5(v5::Packet::SubscribeAck(v5::SubscribeAck { packet_id: id, status, .. }))
                if *id == packet_id && status == &vec![SubscribeAckReason::GrantedQos1]
        ));
        assert!(matches!(
            &sent[5].1,
            MqttPacket::V5(v5::Packet::UnsubscribeAck(v5::UnsubscribeAck { packet_id: id, status, .. }))
                if *id == packet_id && status == &vec![UnsubscribeAckReason::Success]
        ));
        assert!(matches!(sent[6].1, MqttPacket::V5(v5::Packet::Auth(_))));
        assert!(matches!(
            sent[7].1,
            MqttPacket::V5(v5::Packet::Disconnect(v5::Disconnect {
                reason_code: v5::DisconnectReasonCode::NormalDisconnection,
                ..
            }))
        ));
    }

    #[tokio::test]
    async fn publish_applies_v5_topic_aliases() {
        let aliases = Arc::new(ServerTopicAliases::new(1));
        let mut link = SessionLink::new(ProtocolVersion::MQTT5, FakeMqttLink::default());

        link.publish(
            SendTarget::Control,
            publish("alias/topic"),
            Some(NonZeroU32::new(30).unwrap()),
            Some(&aliases),
        )
        .await
        .unwrap();
        link.publish(
            SendTarget::Control,
            publish("alias/topic"),
            Some(NonZeroU32::new(45).unwrap()),
            Some(&aliases),
        )
        .await
        .unwrap();

        let sent = &link.inner().sent;
        let MqttPacket::V5(v5::Packet::Publish(first)) = &sent[0].1 else {
            panic!("expected first v5 publish")
        };
        assert_eq!(first.topic, ByteString::from_static("alias/topic"));
        assert_eq!(first.properties.as_ref().unwrap().message_expiry_interval, NonZeroU32::new(30));
        assert_eq!(first.properties.as_ref().unwrap().topic_alias, NonZeroU16::new(1));

        let MqttPacket::V5(v5::Packet::Publish(second)) = &sent[1].1 else {
            panic!("expected second v5 publish")
        };
        assert_eq!(second.topic, ByteString::default());
        assert_eq!(second.properties.as_ref().unwrap().message_expiry_interval, NonZeroU32::new(45));
        assert_eq!(second.properties.as_ref().unwrap().topic_alias, NonZeroU16::new(1));
    }

    #[tokio::test]
    async fn version_mismatches_fail_without_sending() {
        let mut send_link = SessionLink::new(ProtocolVersion::MQTT3, FakeMqttLink::default());
        let send_error =
            send_link.send(SendTarget::Control, Packet::V5(v5::Packet::PingResponse)).await.unwrap_err();
        assert!(send_error.to_string().contains("cannot send MQTT v5 packet"));
        assert!(send_link.inner().sent.is_empty());

        let mut recv_fake = FakeMqttLink::default();
        recv_fake.push_packet(MqttPacket::V3(v3::Packet::PingRequest), ReplyPath::control());
        let mut recv_link = SessionLink::new(ProtocolVersion::MQTT5, recv_fake);
        let recv_error = recv_link.recv().await.unwrap_err();
        assert!(recv_error.to_string().contains("received MQTT v3 packet"));
    }

    fn packet_id(value: u16) -> NonZeroU16 {
        NonZeroU16::new(value).unwrap()
    }

    fn publish(topic: &'static str) -> Publish {
        CodecPublish {
            dup: false,
            retain: false,
            qos: QoS::AtLeastOnce,
            topic: ByteString::from_static(topic),
            packet_id: Some(packet_id(1)),
            payload: Bytes::from_static(b"payload"),
            properties: Some(PublishProperties::default()),
        }
        .into()
    }
}
