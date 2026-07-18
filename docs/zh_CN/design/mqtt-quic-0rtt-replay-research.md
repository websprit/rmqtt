# MQTT over QUIC 0-RTT Replay Research

取证日期：2026-07-17

范围说明：以下仅整理一手规范与官方库文档，不给出仓库特定设计决策。

## 0. 版本说明

- RFC 8446 是 TLS 1.3 的最终规范（2018-08），RFC 9000 / RFC 9001 是 QUIC 的最终规范（2021-05）。
- MQTT 3.1.1 与 MQTT 5.0 都使用 OASIS 官方标准文档；5.0 的最终标准页比 committee spec 更稳定，下面已统一引用 final OASIS 页面。
- Quinn 与 rustls 的库文档会随 patch 版本刷新；本次研究按 2026-07-17 的官方 docs.rs 页面和源码说明整理，**不把具体 patch 当成 API 稳定承诺**。

## 1. 结论摘要

推论：TLS 1.3 / QUIC 的 0-RTT 早期数据天生允许“跨连接重放”，所以 **任何会改变 MQTT broker 持久状态、订阅状态、认证状态或会触发副作用的 MQTT 字节流，都应视为 replay-sensitive**。最保守的做法，是把 0-RTT 限制到“即使被重复执行也不会造成状态损坏”的内容；如果不能证明这一点，就不要放进 0-RTT。

## 2. TLS 1.3 的重放模型

- RFC 8446 明确说 0-RTT 数据没有 forward secrecy，而且 **没有跨连接的非重放保证**；同一连接内不会被服务器处理两次，但跨连接可以被重放。RFC 8446 还区分了两类威胁：直接复制 0-RTT flight 的网络攻击，以及利用客户端重试 / 多机房 / 多区域部署造成的重复处理。[RFC 8446, §8](https://datatracker.ietf.org/doc/html/rfc8446#section-8)
- RFC 8446 §8.1 给出的最简单防御是 **single-use ticket**：每个 session ticket 只允许使用一次，未知 ticket 直接回退到 full handshake。[RFC 8446, §8.1](https://datatracker.ietf.org/doc/html/rfc8446#section-8.1)
- RFC 8446 §8.2 允许 **ClientHello recording**：记录从 ClientHello 派生的唯一值，并在一个时间窗口内拒绝重复；服务器可以只记录窗口内的 ClientHello，而不是无限期保留全部状态。[RFC 8446, §8.2](https://datatracker.ietf.org/doc/html/rfc8446#section-8.2)
- RFC 8446 §8.3 的 **freshness checks** 允许服务器基于 ticket age / expected arrival time 估算“这次 0-RTT 是否足够新”，从而在不保留无限状态的前提下缩小重放窗口。[RFC 8446, §8.3](https://datatracker.ietf.org/doc/html/rfc8446#section-8.3)
- 集群场景下，RFC 8446 明确提醒：如果 ticket / replay 状态没有跨 zone 共享，同一个 0-RTT handshake 可能在每个 zone 被接受一次；更强的做法是让单一 storage zone 对某个 ticket 具有权威性。[RFC 8446, §8.2](https://datatracker.ietf.org/doc/html/rfc8446#section-8.2)

## 3. QUIC 层面的限制

- RFC 9001 说 QUIC 中的 0-RTT 也同样 vulnerable to replay；端点必须实现并使用 TLS 1.3 的 replay protections，但这些保护本身不完美，因此还需要 application protocol 自己做风险控制。[RFC 9001, §9.2](https://datatracker.ietf.org/doc/html/rfc9001#section-9.2)
- RFC 9001 还明确：**QUIC 的协议状态本身不是 replay 问题，真正的问题是 application protocol carrying semantics**。`STREAM`、`RESET_STREAM`、`STOP_SENDING`、`CONNECTION_CLOSE` 这些帧因为携带应用数据而被视为潜在 unsafe；应用协议必须定义 0-RTT 可接受的使用方式，否则 0-RTT 只能承载不带应用语义的 QUIC 帧。[RFC 9001, §5.6](https://datatracker.ietf.org/doc/html/rfc9001#section-5.6)
- RFC 9000 说明，0-RTT 依赖于上一条连接中协商出的 transport parameters、ALPN、TLS state，以及应用协议所需的额外信息；这些信息都要和 session ticket 一起保存。若 server 接受 0-RTT，则不能降低会被客户端 0-RTT 数据违反的 transport limits；如果恢复的参数无法支持，就必须拒绝 0-RTT。[RFC 9000, §4.6.1-4.6.3](https://datatracker.ietf.org/doc/html/rfc9000#section-4.6.1)
- RFC 9000 还明确列出：如果 0-RTT 被拒绝，客户端必须重置依赖于这些假设的 stream/application state；也就是说，0-RTT 接受与否会直接影响上层状态处理。[RFC 9000, §4.6.2](https://datatracker.ietf.org/doc/html/rfc9000#section-4.6.2)
- QUIC 使用 `0xffffffff` 作为“接受 QUIC 0-RTT”的 sentinel；不是任意早期数据长度都能复用这个字段。[RFC 9001, §4.6.1](https://datatracker.ietf.org/doc/html/rfc9001#section-4.6.1)

## 4. Quinn 0.11 / rustls 0.23 的官方信号

- Quinn 的 `Connecting::into_0rtt()` 文档直接警告：outgoing 0-RTT vulnerable to replay attacks，**不应触发非幂等操作**；incoming 的 0.5-RTT 可能发生在 TLS client authentication 之前，因此也不应承载依赖 client auth 的数据。[Quinn 0.11.9 docs](https://docs.rs/quinn/0.11.9/quinn/struct.Connecting.html)
- rustls `ServerConfig::max_early_data_size` 默认值是 `0`，也就是默认禁用 early data。[rustls 0.23.40 docs](https://docs.rs/rustls/0.23.40/rustls/server/struct.ServerConfig.html)
- rustls 的 QUIC 支持要求 `max_early_data_size` 只能是 `0` 或 `0xffffffff`，否则会报错；这说明 QUIC 0-RTT 在 rustls 中是显式配置、不是隐式可用。[rustls 0.23.40 QUIC source](https://docs.rs/rustls/0.23.40/src/rustls/quic.rs.html)
- rustls `ClientConnection::is_early_data_accepted()` 能告诉客户端 server 是否会处理 early data；如果发送了 early data 但最终返回 `false`，调用方可能需要重发。[rustls 0.23.40 QUIC client docs](https://docs.rs/rustls/0.23.40/rustls/quic/struct.ClientConnection.html)
- rustls 路线图明确写了：**TLS clients should use session tickets at most once for resumption**，否则可能通过 ticket reuse 被跨连接跟踪。[rustls ROADMAP](https://github.com/rustls/rustls/blob/main/ROADMAP.md)

## 5. MQTT 3.1.1 / 5.0 中 replay-sensitive 的字段和包

### 5.1 CONNECT 相关字段

- MQTT 3.1.1 和 5.0 都把 `ClientId` / `Client Identifier` 作为会话状态索引；3.1.1 还明确说客户端和服务器用它来识别保存的 session state。[MQTT 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html) / [MQTT 5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)
- 3.1.1 的 `Clean Session` 和 5.0 的 `Clean Start` + `Session Expiry Interval` 都直接控制“是否恢复旧会话、是否丢弃旧订阅、是否保留缓冲消息”。也就是说，重放一个 CONNECT 不是无害的，它可能改变 broker 对 session 的继承关系。[MQTT 3.1.1 Clean Session](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html) / [MQTT 5.0 Clean Start](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html) / [MQTT 5.0 Session Expiry](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)
- 3.1.1 的 CONNECT payload 顺序是 `Client Identifier`, `Will Topic`, `Will Message`, `User Name`, `Password`；5.0 的 payload 则是 `Client Identifier`, `Will Properties`, `Will Topic`, `Will Payload`, `User Name`, `Password`。[MQTT 3.1.1 CONNECT payload](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html) / [MQTT 5.0 CONNECT payload](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)
- `Will` 相关字段是 replay-sensitive：CONNECT 中的 Will 会在异常断开后由 server 发布，3.1.1 里会把 Will Message 作为 session state 存储；5.0 也保留这套语义，并补充了 Will Delay / Will Retain / Will Properties。[MQTT 3.1.1 Will](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html) / [MQTT 5.0 Will](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)
- `User Name` / `Password` / 5.0 的 `Authentication Method` / `Authentication Data` 都属于认证流程的一部分；5.0 还允许 AUTH 交换发生在 CONNECT 与 CONNACK 之间，所以重放这些字段会影响认证结果或重认证流程。[MQTT 5.0 Enhanced Authentication](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)

### 5.2 数据面 / 控制面包

- `PUBLISH` 是最明显的 replay-sensitive 包。MQTT 5.0 仍然把 QoS 1 / QoS 2、`DUP`、`PUBACK` / `PUBREC` / `PUBREL` / `PUBCOMP` 明确定义为可见状态机；重复投递会改变 broker 或 subscriber 看到的消息次数。推论：`QoS 0` 虽然没有协议层 ack/重传语义，但对应用层命令来说依然可能是有副作用的，只是协议不替你消重。[MQTT 5.0 PUBLISH / QoS](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)
- MQTT 5.0 还明确说 `Message Expiry Interval` 只是消息生命周期，不是 replay protection；`Retain` / `Will Retain` 也只是改变消息是否保留，不会让重放变安全。[MQTT 5.0 Message Expiry](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)
- `SUBSCRIBE` / `UNSUBSCRIBE` 是 replay-sensitive，因为它们直接修改订阅状态；MQTT 5.0 允许对已有 Subscription 重建或拆除，同样会改变后续消息路由。[MQTT 5.0 SUBSCRIBE/UNSUBSCRIBE](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)
- `AUTH` / re-authentication 是 replay-sensitive，因为它们属于连接认证状态机，不是普通数据流。
- 5.0 明确说 `Topic Alias` mapping **不得从一个 Network Connection 带到另一个**；这意味着任何依赖既有 alias 状态的早期数据都不应被当成跨连接安全。[MQTT 5.0 Topic Alias](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)

### 5.3 3.1.1 与 5.0 的共同点

- 3.1.1 的 `Clean Session` 里，server 要保留客户端订阅和未完成的 QoS 1/2 消息；`Will Message` 在非正常断开时发布。5.0 把这些语义拆成 `Clean Start` + `Session Expiry Interval` + Will 相关属性，但 replay 风险本质没有变。[MQTT 3.1.1 Session State / Will](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html) / [MQTT 5.0 Session Expiry / Will](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)
- 5.0 还明确：如果 `ClientID` 已经连接，server 会对旧连接发 `DISCONNECT`（session takeover 语义）。因此，重放 CONNECT 可能导致已有会话被踢下线，这不是“无害重复”。[MQTT 5.0 session takeover](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)

## 6. 集群与部署上的结论

推论：只要一个 ticket / ClientHello / replay key 在多台 broker 或多 zone 间不是强一致共享，就必须按“可能被每个节点各接受一次”来估算重放面。
- 因此，**0-RTT 的 replay 防线不能只放在 TLS 层**；应用层必须额外限定哪些 MQTT 包和字段可以在 early data 中出现。[RFC 9001, §9.2](https://datatracker.ietf.org/doc/html/rfc9001#section-9.2)
- `session ticket`、`transport parameters`、`application config` 都是 0-RTT accept/reject 判定的一部分；它们必须被当作 opaque / auth-bound state 保存，而不是 application semantics 的载体。[RFC 9000, §4.6.3](https://datatracker.ietf.org/doc/html/rfc9000#section-4.6.3)

## 7. 可复用 takeaway

如果后续要给 MQTT over QUIC 设计 0-RTT 策略，研究基线已经很清楚：

1. TLS/QUIC 只提供“尽量限制重放”的工具，不提供应用级安全保证。
2. 任何会改变 MQTT session、subscription、authentication、will、或 message delivery 次数的包，都应视为 replay-sensitive。
3. 集群部署必须把 replay state 做成跨节点一致，或者直接禁止这些语义进入 0-RTT。
