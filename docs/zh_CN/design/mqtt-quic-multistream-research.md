# MQTT over QUIC 多 Stream 研究备忘

研究时间点：2026-07-18

## 结论先行

- 我没有在 IETF / OASIS 的正式标准轨道上找到已发布的 `MQTT over QUIC multi-stream` 标准或成熟草案。
- 当前能确认的 OASIS 官方公开材料，只有一份 `MQTT Over QUIC — Single Stream Mode Version 1.0` 的委员会说明草案；它明确写明自己只定义单 stream 模式，并把 multistream 交给后续单独文档。
- 从协议约束上看，MQTT 如果跑在 QUIC multistream 上，最大的边界不是“能不能并发”，而是：
  - QUIC 每条 stream 内有序、可靠，但不同 stream 之间没有全局有序关系。
  - MQTT 连接建立和认证顺序非常强，尤其是 CONNECT / CONNACK / AUTH / 0-RTT / Receive Maximum 这几个点。
  - QoS 1/2 的 packet identifier、重传、会话状态、Topic Alias 都有“同一网络连接 / 同一 session”边界，不能直接跨 stream 复用。

## 一手依据

### 1. QUIC 的 stream、顺序、流控和 0-RTT 约束

- `stream` 是连接内“有序字节流”，可以同时存在多个；这意味着 QUIC 可以并发，但并发只发生在 stream 之间，不是把单条 stream 变成乱序通道。来源：RFC 9000 `§2` / `§2.1`。
- stream ID 明确编码了方向和发起方：
  - client-initiated 是偶数；
  - server-initiated 是奇数；
  - 低位还区分 bidirectional / unidirectional。来源：RFC 9000 `§2.1`。
- QUIC 要求应用看到的是“ordered byte stream”；收到乱序数据时，端点必须在不超过 advertised flow control limit 的前提下缓存。来源：RFC 9000 `§2.2`。
- QUIC 同时存在 stream-level 和 connection-level flow control；发送方不能超过 peer 给出的限制。来源：RFC 9000 `§4.1`。
- QUIC 的可并发 stream 数量还受 transport parameters 和 `MAX_STREAMS` 控制；初始额度由 `initial_max_streams_bidi` / `initial_max_streams_uni` 给出，后续只能用 `MAX_STREAMS` 增加，超过对端给出的 stream limit 会触发流限制错误。来源：RFC 9000 `§4.6`、`§18.2`、`§19.11`。
- `RESET_STREAM` 只终止一个方向，对双向 stream 的另一方向没有影响；未终止方向的 flow-control 状态必须继续维护到终态。来源：RFC 9000 `§4.4`。
- QUIC 使用 connection ID 支持路径变化和 migration。来源：RFC 9000 `§5.1`、`§9`。
- 0-RTT 不是“无条件安全的早发数据”：
  - QUIC/TLS 允许 0-RTT，但应用数据可能被 replay。
  - RFC 9001 指出 0-RTT 的形成依赖客户端记住的 TLS state、QUIC transport parameters、已选应用协议和应用配置；如果没有定义可接受的 0-RTT profile，0-RTT 不能承载应用数据。
  - RFC 9000 规定 0-RTT packet 只能使用 ticket 记住的 transport parameters；握手或 1-RTT frame 提高的新额度只能用于 1-RTT。由此可以安全地把 remembered bidi limit 固定为 1，并在握手/应用激活后通过 `MAX_STREAMS` 放开数据流。
  - 一旦 0-RTT 被拒绝，客户端此前假设的连接特性、应用配置、绑定在 stream 上的应用状态都可能不成立，必须重置所有 stream 状态。来源：RFC 9001 `§5.6`、`§9.2`。

- Quinn 0.11 的 `Connection::set_max_concurrent_bi_streams` / `set_max_concurrent_uni_streams` 可以在连接建立后修改允许 peer 并发打开的远端 stream 数；官方文档同时提醒较大的额度会提高最低和最坏内存消耗。来源：Quinn 0.11 `Connection` API。

### 2. MQTT 3.1.1 / 5.0 的连接顺序、packet identifier、Receive Maximum、Topic Alias、AUTH、session 约束

- MQTT 5.0 规定：网络连接建立后，客户端发出的第一个 packet 必须是 CONNECT。来源：OASIS MQTT 5.0 `MQTT-3.1.0-1`。
- MQTT 5.0 规定：服务器在发送任何 packet 之前，必须先发送 CONNACK，AUTH 例外。来源：OASIS MQTT 5.0 `MQTT-3.2.0-1`。
- MQTT 5.0 允许 AUTH 在 CONNECT 之后、CONNACK 之前出现；如果 CONNECT 被拒绝，服务器不得处理 CONNECT 之后的数据，AUTH 除外。来源：OASIS MQTT 5.0 `MQTT-3.1.2-30`、`MQTT-3.1.4-6`。
- MQTT 3.1.1 对顺序要求更宽松：客户端可以在发出 CONNECT 后立即继续发 packet，不必等 CONNACK；但如果服务器拒绝 CONNECT，则不会处理 CONNECT 之后的数据。来源：OASIS MQTT 3.1.1 `MQTT-3.1.4-5` / `MQTT-3.1.4-6`。
- MQTT 3.1.1 同样要求服务器第一条回应必须是 CONNACK。来源：OASIS MQTT 3.1.1 `MQTT-3.2.0-1`。
- Packet Identifier 不是任意并发标签，而是受会话内状态机约束的有限资源：
  - 在 MQTT 5.0 中，PUBLISH / SUBSCRIBE / UNSUBSCRIBE 的 Packet Identifier 对 client 和 server 分别构成一个统一集合；
  - 同一个时刻不能被多个命令复用；
  - QoS 1 的 Packet Identifier 在收到 PUBACK 后才能重用；
  - QoS 2 需要等到 PUBCOMP，或收到带失败码的 PUBREC 后才能重用。来源：OASIS MQTT 5.0 `2.2.1 Packet Identifier`。
- MQTT 3.1.1 的 packet identifier 规则与此同构：
  - 重发必须保留原 Packet Identifier；
  - QoS 1 在收到 PUBACK 后可重用；
  - QoS 2 在收到 PUBCOMP 后可重用；
  - CleanSession = 0 的重连要求使用原 Packet Identifier 重发未确认的 PUBLISH / PUBREL。来源：OASIS MQTT 3.1.1 `§2.3.1`、`§4.4`。
- MQTT 5.0 Receive Maximum 直接限制“未确认 in-flight 的 QoS 1/2 PUBLISH 数量”：
  - client / server 都不得超过 peer 声明的 Receive Maximum；
  - 收到超限时应断开，并返回 `Receive Maximum exceeded`；
  - 只有 PUBLISH 受这个并发上限约束，不能因此阻塞其它 packet。来源：OASIS MQTT 5.0 `§3.1.2.11.3`、`§3.2.2.3.3`、`§4.9`。
- MQTT 5.0 Topic Alias 的作用域只在当前 network connection 内：
  - alias 不能是 0；
  - sender 不能超过 peer 声明的 Topic Alias Maximum；
  - receiver 不能把一个连接上的 alias 映射带到另一个连接。来源：OASIS MQTT 5.0 `§3.1.2.11.5`、`§3.2.2.3.8`、`§3.3.2.3.4`。
- MQTT 5.0 的 session state 是 `ClientID` 维度的持久状态；Clean Start / Session Expiry 决定是否延续 session。来源：OASIS MQTT 5.0 `§3.1.2.11.1`、`§3.2.2.3.1`、`§4.1`。
- MQTT 3.1.1 的 CleanSession 语义同样说明 session 是连接可恢复的状态，而不是“每条 QUIC stream 各自拥有一份”。来源：OASIS MQTT 3.1.1 `§3.1.2.4`、`§4.4`。

### 3. 现有官方工作：只有单 stream 草案，multistream 仍是未标准化方向

- OASIS 官方 MQTT 仓库当前公开树里可确认的 QUIC 贡献，是 `MQTT Over QUIC — Single Stream Mode Version 1.0`。该文档写明：
  - 只定义 single stream mode；
  - 一个双向 QUIC stream 承载所有 MQTT control packets；
  - 文档本身“不定义 multistream operation”，而是把 Simple Multistream / Advanced Multistream 交给单独文档。
  来源：OASIS MQTT repo 快照 `oasis-tcs/mqtt@43280f255b94cf4710c90dd453f59781be97ca91`。
- 该单 stream 草案的范围说明很关键：
  - 兼容 MQTT 3.1.1 / 5.0；
  - 只替换 TCP 传输层；
  - 明确不覆盖 multistream、server-initiated streams、unreliable datagram、flow-level session persistence。
  这意味着 multistream 在该官方草案中仍然是“后续文档 / 后续标准化方向”，不是已定稿的规范。
  来源：同上，`contributions/EMQX/mqtt-over-quic-cn/mqtt_over_quic_single_stream_CN_1.md`。
- EMQX 官方项目文档也明确写了两点：
  - MQTT over QUIC “not yet the standard protocol for MQTT”；
  - EMQX 正在推动其在 OASIS 中标准化。
  这说明当前 multistream 更接近“官方项目实现 + 标准化推进中”，而不是已完成 IETF/OASIS 标准。
  来源：EMQX Enterprise Docs `MQTT over QUIC` introduction page。
- EMQX 官方文档还给出了现阶段实现边界：
  - session state 目前不支持；
  - 若 data stream 被异常关闭，QoS 1 / QoS 2 message state 不保留。
  这对 multistream 的 session ownership 和 stream failure 讨论非常重要。
  来源：EMQX Enterprise Docs `MQTT over QUIC` introduction page。

### 4. 正式论文证据

- 存在正式论文研究 MQTT over QUIC 的性能和可行性，例如：
  - F. Fernández, M. Zverev, P. Garrido, J. R. Juárez, J. Bilbao, R. Agüero, “And QUIC meets IoT: performance assessment of MQTT over QUIC”, WiMob 2020, DOI `10.1109/WiMob50308.2020.9253384`.
  这类论文说明该方向已有研究基础，但它们不是标准文本。
  来源：IEEE Xplore / WiMob 2020。

## 对多 Stream 设计的直接含义

- 不能把“多个 QUIC stream”理解成“MQTT packet 可以任意乱序送”。QUIC 只保证每条 stream 内有序，跨 stream 没有全局顺序。
- 不能把“0-RTT 可以发数据”理解成“连 CONNECT / 认证 / session 恢复都可以无条件并发”。0-RTT 被拒绝时，绑定在 stream 上的状态会被整体推翻。
- 不能把“packet identifier 可以并发复用”理解成“不同 stream 各自一套独立 ID 空间”。MQTT 的 packet identifier、Receive Maximum、Topic Alias、session state 都是按 connection / session 维度约束的。
- 如果要做 multistream，最稳妥的推断是：
  - 需要显式区分 control stream 和 data stream；
  - session / auth / CONNECT / CONNACK / AUTH / subscription control 必须有严格的单点顺序锚；
  - QoS state machine 不能依赖 stream 关闭之外的隐式可靠性。

## 参考链接

- RFC 9000 QUIC Transport: https://www.rfc-editor.org/rfc/rfc9000.html
- RFC 9001 QUIC-TLS: https://www.rfc-editor.org/rfc/rfc9001.html
- Quinn 0.11 Connection API: https://docs.rs/quinn/0.11.9/quinn/struct.Connection.html
- MQTT 5.0 OASIS PDF: https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.pdf
- MQTT 3.1.1 OASIS PDF: https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.pdf
- OASIS MQTT repo single-stream note: https://raw.githubusercontent.com/oasis-tcs/mqtt/43280f255b94cf4710c90dd453f59781be97ca91/contributions/EMQX/mqtt-over-quic-cn/mqtt_over_quic_single_stream_CN_1.md
- EMQX MQTT over QUIC introduction: https://docs.emqx.com/en/emqx/latest/mqtt-over-quic/introduction.html
- EMQX MQTT over QUIC features: https://docs.emqx.com/en/emqx/latest/mqtt-over-quic/features-mqtt-over-quic.html
- IEEE WiMob 2020 paper: https://ieeexplore.ieee.org/document/9253384/

## 可复用结论

截至 2026-07-18，`MQTT over QUIC multistream` 还不能当成已标准化协议对待；它更像是“官方项目实现 + OASIS 内的单 stream 委员会草案 + 论文验证 + 后续 multistream 设计讨论”。如果要做实现，必须按 QUIC 的 per-stream 有序/流控/0-RTT 规则，以及 MQTT 的 CONNECT/CONNACK/AUTH、packet identifier、Receive Maximum、Topic Alias、session state 规则来设计。
