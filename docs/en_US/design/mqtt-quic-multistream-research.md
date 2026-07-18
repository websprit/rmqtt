# MQTT over QUIC Multistream Research Memo

Research date: 2026-07-18

## Conclusions First

- I did not find a published `MQTT over QUIC multi-stream` standard or mature draft on the formal IETF / OASIS standards track.
- The currently confirmable official OASIS public material is only a committee note draft named `MQTT Over QUIC - Single Stream Mode Version 1.0`. It explicitly says it defines only single-stream mode and leaves multistream for a separate later document.
- From the protocol constraints, the largest boundary for running MQTT over QUIC multistream is not "whether concurrency is possible", but:
  - QUIC provides ordered and reliable delivery within each stream, but no global ordering across different streams.
  - MQTT connection establishment and authentication ordering is strong, especially around CONNECT / CONNACK / AUTH / 0-RTT / Receive Maximum.
  - QoS 1/2 packet identifiers, retransmission, session state, and Topic Alias all have a "same network connection / same session" boundary and cannot be directly reused across streams as independent state.

## Primary Evidence

### 1. QUIC Stream, Ordering, Flow Control, and 0-RTT Constraints

- A `stream` is an "ordered byte stream" inside a connection, and multiple streams can exist at the same time. This means QUIC can run concurrently, but concurrency happens between streams; it does not turn a single stream into an out-of-order channel. Source: RFC 9000 `Section 2` / `Section 2.1`.
- The stream ID explicitly encodes direction and initiator:
  - client-initiated streams are even-numbered;
  - server-initiated streams are odd-numbered;
  - the low bits also distinguish bidirectional / unidirectional streams. Source: RFC 9000 `Section 2.1`.
- QUIC requires applications to see an "ordered byte stream". When out-of-order data arrives, the endpoint must buffer it without exceeding the advertised flow-control limit. Source: RFC 9000 `Section 2.2`.
- QUIC has both stream-level and connection-level flow control. The sender cannot exceed the limits provided by its peer. Source: RFC 9000 `Section 4.1`.
- The number of concurrent QUIC streams is also controlled by transport parameters and `MAX_STREAMS`. Initial credit is provided by `initial_max_streams_bidi` / `initial_max_streams_uni`; later credit can only be increased with `MAX_STREAMS`. Exceeding the peer's stream limit triggers a stream-limit error. Source: RFC 9000 `Section 4.6`, `Section 18.2`, `Section 19.11`.
- `RESET_STREAM` only terminates one direction. It does not affect the other direction of a bidirectional stream. The unterminated direction's flow-control state must continue to be maintained until a terminal state. Source: RFC 9000 `Section 4.4`.
- QUIC uses connection IDs to support path changes and migration. Source: RFC 9000 `Section 5.1`, `Section 9`.
- 0-RTT is not "unconditionally safe early data":
  - QUIC/TLS permits 0-RTT, but application data can be replayed.
  - RFC 9001 states that 0-RTT depends on TLS state, QUIC transport parameters, the selected application protocol, and application configuration remembered by the client. If an acceptable 0-RTT profile is not defined, 0-RTT cannot carry application data.
  - RFC 9000 states that 0-RTT packets can only use transport parameters remembered from the ticket. New credit raised by handshake or 1-RTT frames can only be used by 1-RTT. This allows a design that safely fixes remembered bidi credit to 1 and opens data streams later through `MAX_STREAMS` after handshake/application activation.
  - Once 0-RTT is rejected, previously assumed connection properties, application configuration, and stream-bound application state may all be invalid and must be reset. Source: RFC 9001 `Section 5.6`, `Section 9.2`.

- Quinn 0.11 `Connection::set_max_concurrent_bi_streams` / `set_max_concurrent_uni_streams` can modify the number of remote streams the peer may open after connection establishment. The official documentation also warns that larger limits increase minimum and worst-case memory consumption. Source: Quinn 0.11 `Connection` API.

### 2. MQTT 3.1.1 / 5.0 Connection Ordering, Packet Identifier, Receive Maximum, Topic Alias, AUTH, and Session Constraints

- MQTT 5.0 requires the first packet sent by the client after network connection establishment to be CONNECT. Source: OASIS MQTT 5.0 `MQTT-3.1.0-1`.
- MQTT 5.0 requires the server to send CONNACK before sending any other packet, except AUTH. Source: OASIS MQTT 5.0 `MQTT-3.2.0-1`.
- MQTT 5.0 allows AUTH after CONNECT and before CONNACK. If CONNECT is rejected, the server must not process data after CONNECT, except AUTH. Source: OASIS MQTT 5.0 `MQTT-3.1.2-30`, `MQTT-3.1.4-6`.
- MQTT 3.1.1 has a looser ordering requirement: the client can continue sending packets immediately after CONNECT without waiting for CONNACK. However, if the server rejects CONNECT, it will not process data after CONNECT. Source: OASIS MQTT 3.1.1 `MQTT-3.1.4-5` / `MQTT-3.1.4-6`.
- MQTT 3.1.1 also requires the server's first response to be CONNACK. Source: OASIS MQTT 3.1.1 `MQTT-3.2.0-1`.
- Packet Identifier is not an arbitrary concurrency label; it is a limited resource constrained by the session state machine:
  - In MQTT 5.0, Packet Identifiers for PUBLISH / SUBSCRIBE / UNSUBSCRIBE form one unified set for the client and one unified set for the server.
  - The same Packet Identifier cannot be reused by multiple commands at the same time.
  - A QoS 1 Packet Identifier can be reused only after PUBACK is received.
  - QoS 2 must wait until PUBCOMP, or until a PUBREC with a failure code is received. Source: OASIS MQTT 5.0 `2.2.1 Packet Identifier`.
- MQTT 3.1.1 packet identifier rules are isomorphic:
  - retransmissions must keep the original Packet Identifier;
  - QoS 1 can reuse the identifier after PUBACK;
  - QoS 2 can reuse it after PUBCOMP;
  - reconnect with CleanSession = 0 requires retransmitting unacknowledged PUBLISH / PUBREL packets with the original Packet Identifier. Source: OASIS MQTT 3.1.1 `Section 2.3.1`, `Section 4.4`.
- MQTT 5.0 Receive Maximum directly limits "unacknowledged in-flight QoS 1/2 PUBLISH packets":
  - both client and server must not exceed the peer's Receive Maximum;
  - on overrun, the receiver should disconnect and return `Receive Maximum exceeded`;
  - only PUBLISH is constrained by this concurrency limit, so it must not block other packet types. Source: OASIS MQTT 5.0 `Section 3.1.2.11.3`, `Section 3.2.2.3.3`, `Section 4.9`.
- MQTT 5.0 Topic Alias scope is only the current network connection:
  - alias cannot be 0;
  - the sender cannot exceed the peer's declared Topic Alias Maximum;
  - the receiver cannot carry alias mappings from one connection to another. Source: OASIS MQTT 5.0 `Section 3.1.2.11.5`, `Section 3.2.2.3.8`, `Section 3.3.2.3.4`.
- MQTT 5.0 session state is persistent state keyed by `ClientID`; Clean Start / Session Expiry decide whether the session continues. Source: OASIS MQTT 5.0 `Section 3.1.2.11.1`, `Section 3.2.2.3.1`, `Section 4.1`.
- MQTT 3.1.1 CleanSession semantics likewise show that a session is recoverable connection state, not "one independent copy per QUIC stream". Source: OASIS MQTT 3.1.1 `Section 3.1.2.4`, `Section 4.4`.

### 3. Existing Official Work: Only a Single-Stream Draft; Multistream Is Still Not Standardized

- The confirmable QUIC contribution in the public tree of the official OASIS MQTT repository is currently `MQTT Over QUIC - Single Stream Mode Version 1.0`. That document states that it:
  - defines only single-stream mode;
  - carries all MQTT control packets over one bidirectional QUIC stream;
  - does "not define multistream operation", and leaves Simple Multistream / Advanced Multistream for separate documents.
  Source: OASIS MQTT repository snapshot `oasis-tcs/mqtt@43280f255b94cf4710c90dd453f59781be97ca91`.
- The scope statement of that single-stream draft is important:
  - it is compatible with MQTT 3.1.1 / 5.0;
  - it only replaces the TCP transport layer;
  - it explicitly does not cover multistream, server-initiated streams, unreliable datagram, or flow-level session persistence.
  This means multistream is still a "future document / future standardization direction" in that official draft, not a finalized specification.
  Source: same snapshot, `contributions/EMQX/mqtt-over-quic-cn/mqtt_over_quic_single_stream_CN_1.md`.
- EMQX official project documentation also states two points:
  - MQTT over QUIC is "not yet the standard protocol for MQTT";
  - EMQX is promoting its standardization in OASIS.
  This indicates that current multistream is closer to "official project implementation plus ongoing standardization" than to a completed IETF/OASIS standard.
  Source: EMQX Enterprise Docs `MQTT over QUIC` introduction page.
- EMQX official documentation also gives current implementation boundaries:
  - session state is currently not supported;
  - if a data stream is abnormally closed, QoS 1 / QoS 2 message state is not retained.
  This is important evidence for the multistream discussion around session ownership and stream failure.
  Source: EMQX Enterprise Docs `MQTT over QUIC` introduction page.

### 4. Formal Paper Evidence

- Formal papers exist that study MQTT over QUIC performance and feasibility, for example:
  - F. Fernandez, M. Zverev, P. Garrido, J. R. Juarez, J. Bilbao, R. Aguero, "And QUIC meets IoT: performance assessment of MQTT over QUIC", WiMob 2020, DOI `10.1109/WiMob50308.2020.9253384`.
  These papers show that the direction has a research foundation, but they are not standards texts.
  Source: IEEE Xplore / WiMob 2020.

## Direct Implications for a Multistream Design

- Do not interpret "multiple QUIC streams" as "MQTT packets can be delivered in arbitrary disorder". QUIC only guarantees ordering within each stream; it provides no global ordering across streams.
- Do not interpret "0-RTT can send data" as "CONNECT / authentication / session resume can all be concurrent without conditions". When 0-RTT is rejected, stream-bound state is invalidated as a whole.
- Do not interpret "packet identifiers can be reused concurrently" as "each stream has its own independent ID space". MQTT packet identifiers, Receive Maximum, Topic Alias, and session state are constrained at the connection / session level.
- If multistream is implemented, the safest inference is:
  - explicitly distinguish control stream and data stream;
  - keep strict single-point ordering for session / auth / CONNECT / CONNACK / AUTH / subscription control;
  - do not make the QoS state machine depend on implicit reliability beyond stream closure.

## Reference Links

- RFC 9000 QUIC Transport: https://www.rfc-editor.org/rfc/rfc9000.html
- RFC 9001 QUIC-TLS: https://www.rfc-editor.org/rfc/rfc9001.html
- Quinn 0.11 Connection API: https://docs.rs/quinn/0.11.9/quinn/struct.Connection.html
- MQTT 5.0 OASIS PDF: https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.pdf
- MQTT 3.1.1 OASIS PDF: https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.pdf
- OASIS MQTT repo single-stream note: https://raw.githubusercontent.com/oasis-tcs/mqtt/43280f255b94cf4710c90dd453f59781be97ca91/contributions/EMQX/mqtt-over-quic-cn/mqtt_over_quic_single_stream_CN_1.md
- EMQX MQTT over QUIC introduction: https://docs.emqx.com/en/emqx/latest/mqtt-over-quic/introduction.html
- EMQX MQTT over QUIC features: https://docs.emqx.com/en/emqx/latest/mqtt-over-quic/features-mqtt-over-quic.html
- IEEE WiMob 2020 paper: https://ieeexplore.ieee.org/document/9253384/

## Reusable Conclusion

As of 2026-07-18, `MQTT over QUIC multistream` cannot be treated as a standardized protocol. It is closer to "official project implementation + OASIS single-stream committee draft + paper validation + later multistream design discussion". An implementation must be designed around QUIC's per-stream ordering / flow-control / 0-RTT rules and MQTT's CONNECT/CONNACK/AUTH, packet identifier, Receive Maximum, Topic Alias, and session-state rules.
