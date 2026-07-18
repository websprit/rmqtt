# Android SDK × RMQTT QUIC 0-RTT 完整流程验证

- 验证日期：2026-07-19
- RMQTT 分支：`support-0RTT`
- Android 设备：Pixel 9 Pro XL，Android 17，arm64-v8a
- Android Demo 自动化模式：`quic_features`

## 结论

当前 Android SDK 与 RMQTT 的 `simple-v1` 多 Stream 线协议兼容。RMQTT 启用 MQTT 5 预配置协商后，可以完成以下完整流程：

1. 首次 QUIC 1-RTT 连接并获取 Session Ticket；
2. 同一 SDK 实例主动断开并重连；
3. 客户端在握手完成前打开 Control Stream 并发送 MQTT CONNECT；
4. 服务端接受 0-RTT，客户端状态依次进入 `ATTEMPTED`、`ACCEPTED`；
5. CONNACK 后打开两条额外 QUIC Data Stream；
6. 两条 Stream 分别完成 SUBSCRIBE/SUBACK；
7. 两条 Stream 分别完成 QoS 1 PUBLISH/PUBACK；
8. 主动关闭两条 Data Stream；
9. 关闭后通过默认 Data Stream 再次完成普通 QoS 1 PUBLISH/PUBACK。

连续三次独立 clientId 自动回归均通过：

```text
04:35:05 clientId=rmqtt-loopback-e2e-0719    result=PASS outcome=ACCEPTED
04:35:45 clientId=rmqtt-loopback-e2e-0719-r2 result=PASS outcome=ACCEPTED
04:35:49 clientId=rmqtt-loopback-e2e-0719-r3 result=PASS outcome=ACCEPTED
```

三次完整摘要和第三次关键运行日志保存在 [android-sdk-rmqtt-quic-0rtt-2026-07-19.log](./evidence/android-sdk-rmqtt-quic-0rtt-2026-07-19.log)。

## 原始兼容缺口

RMQTT 的 MQTT 5 严格模式要求 CONNECT User Property 精确包含：

```text
rmqtt-quic-multistream=simple-v1
```

当前 Android FlowSDK 构造 MQTT 5 CONNECT 时传入空 properties，因此不会发送该属性。两端其它关键行为一致：

- SDK 只在成功 CONNACK 后开放显式 Data Stream API；
- Data Stream 不增加私有 stream header，直接承载原始 MQTT Control Packet；
- SUBACK、PUBACK 及 QoS ACK 链返回发起事务的同一条 Stream；
- Stream ID、Packet Identifier、inflight 和 session 状态保持连接级统一管理。

## RMQTT 兼容配置

默认策略仍为 `strict`，不会改变现有 MQTT 5 客户端的协商语义。只在已确认客户端线协议兼容的专用 listener 上配置：

```toml
[listener.quic.external.multistream]
mode = "simple"
negotiation = "preconfigured"
max_data_streams = 8
stream_open_rate = 32
stream_idle_timeout = "60s"
connection_mailbox_packets = 256
connection_buffer_bytes = "1MB"
```

完整 0-RTT 测试 listener 还需要：

```toml
listener.quic.external.allow_anonymous = true
listener.quic.external.zero_rtt.mode = "handshake_gated"
listener.quic.external.zero_rtt.credential_profile = "anonymous"
```

`preconfigured` 表示 listener 配置本身就是双方对 `simple-v1` 的预先约定。Broker 激活多 Stream 后仍在 CONNACK 返回 `rmqtt-quic-multistream=simple-v1`，未来 SDK 开始解析该属性时无需改变服务端响应。

## 自动化证据

第三次回归的关键日志：

```text
首次连接：
keysAvailable=0 earlyControlStreamOpened=0
quic_handshake_done totalMs=29
connack_received totalMs=31

0-RTT 重连：
lastTakeMaxEarlyData=4294967295
lastTakeQuicParamsLen=123
keysAvailable=1 earlyControlStreamOpened=1
quic zero-rtt status=2        # ATTEMPTED
quic zero-rtt status=3        # ACCEPTED
connack_received totalMs=30

多 Stream：
open streamA rc=0 streamId=4 streamB rc=0 streamId=8
两个 SUBACK code=0
两个 PUBACK code=0
关闭两条 Stream 后普通 publish callback code=0
```

这些耗时来自同一 Pixel 的 loopback 环境，只用于确认状态机和 Early Data 确实发生，不能作为公网或 Wi-Fi 性能结论。

## Rust 回归

实现后执行并通过：

```text
cargo test -p rmqtt-net --all-features --test quic_0rtt
10 passed

cargo test -p rmqtt-net --all-features --test quic_multistream_activation
5 passed

cargo test -p rmqtt --all-features v5::tests
6 passed

cargo test -p rmqtt-conf multistream
2 passed

cargo test -p rmqttd config_builder_maps_multistream_listener_config
1 passed
```

## 测试网络说明

手机和 Mac 当时位于不同子网。ICMP 可达，但路由设备丢弃了手机到 Mac 的 UDP/9443；客户端日志显示已发送 QUIC datagram，而 Mac 上的 RMQTT 没有收到。因此最终将同一 `simple_quic` RMQTT 源码交叉编译为 Android arm64 可执行文件，在 Pixel 上通过 `127-0-0-1.sslip.io:9443` 运行，以排除外部网络 ACL 干扰并验证真实 QUIC、TLS Ticket、0-RTT 与多 Stream 协议流程。
