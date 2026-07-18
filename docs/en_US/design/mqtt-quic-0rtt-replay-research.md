# MQTT over QUIC 0-RTT Replay Research

Evidence date: 2026-07-17

Scope note: This document only summarizes primary specifications and official library documentation. It does not make repository-specific design decisions.

## 0. Version Notes

- RFC 8446 is the final TLS 1.3 specification (2018-08). RFC 9000 / RFC 9001 are the final QUIC specifications (2021-05).
- MQTT 3.1.1 and MQTT 5.0 both use the official OASIS standard documents. The MQTT 5.0 final standard page is more stable than the committee-spec page, so the references below use the final OASIS page consistently.
- Quinn and rustls library documentation can change with patch releases. This research is based on the official docs.rs pages and source notes as of 2026-07-17, and **does not treat a specific patch version as an API stability guarantee**.

## 1. Conclusion Summary

Inference: TLS 1.3 / QUIC 0-RTT early data inherently allows "cross-connection replay", so **any MQTT byte stream that can change broker persistent state, subscription state, authentication state, or trigger side effects should be considered replay-sensitive**. The most conservative approach is to limit 0-RTT to content that cannot corrupt state even if executed repeatedly. If that cannot be proven, it should not be placed in 0-RTT.

## 2. TLS 1.3 Replay Model

- RFC 8446 explicitly states that 0-RTT data lacks forward secrecy and has **no cross-connection anti-replay guarantee**. It will not be processed twice within the same connection, but it can be replayed across connections. RFC 8446 also distinguishes two threat classes: network attackers that directly copy a 0-RTT flight, and repeated processing caused by client retry / multi-datacenter / multi-region deployments. [RFC 8446, Section 8](https://datatracker.ietf.org/doc/html/rfc8446#section-8)
- The simplest defense in RFC 8446 Section 8.1 is a **single-use ticket**: each session ticket can be used only once, and unknown tickets fall back directly to a full handshake. [RFC 8446, Section 8.1](https://datatracker.ietf.org/doc/html/rfc8446#section-8.1)
- RFC 8446 Section 8.2 allows **ClientHello recording**: record a unique value derived from ClientHello and reject duplicates within a time window. Servers can record only ClientHellos in the window instead of retaining all state indefinitely. [RFC 8446, Section 8.2](https://datatracker.ietf.org/doc/html/rfc8446#section-8.2)
- RFC 8446 Section 8.3 **freshness checks** allow a server to estimate whether a given 0-RTT attempt is fresh enough based on ticket age / expected arrival time, reducing the replay window without retaining unbounded state. [RFC 8446, Section 8.3](https://datatracker.ietf.org/doc/html/rfc8446#section-8.3)
- In clustered deployments, RFC 8446 explicitly warns that if ticket / replay state is not shared across zones, the same 0-RTT handshake might be accepted once per zone. A stronger approach is to make a single storage zone authoritative for a given ticket. [RFC 8446, Section 8.2](https://datatracker.ietf.org/doc/html/rfc8446#section-8.2)

## 3. QUIC-Layer Constraints

- RFC 9001 states that 0-RTT in QUIC is also vulnerable to replay. Endpoints must implement and use the TLS 1.3 replay protections, but those protections are imperfect, so the application protocol must also control risk. [RFC 9001, Section 9.2](https://datatracker.ietf.org/doc/html/rfc9001#section-9.2)
- RFC 9001 also states that **QUIC protocol state itself is not the replay problem; the real issue is the semantics carried by the application protocol**. Frames such as `STREAM`, `RESET_STREAM`, `STOP_SENDING`, and `CONNECTION_CLOSE` are considered potentially unsafe because they carry application data. The application protocol must define acceptable 0-RTT usage; otherwise 0-RTT can only carry QUIC frames without application semantics. [RFC 9001, Section 5.6](https://datatracker.ietf.org/doc/html/rfc9001#section-5.6)
- RFC 9000 explains that 0-RTT depends on transport parameters, ALPN, TLS state, and additional application-protocol information negotiated on the previous connection. These values must be saved with the session ticket. If the server accepts 0-RTT, it cannot lower transport limits that would be violated by the client's 0-RTT data. If the resumed parameters cannot support the data, 0-RTT must be rejected. [RFC 9000, Sections 4.6.1-4.6.3](https://datatracker.ietf.org/doc/html/rfc9000#section-4.6.1)
- RFC 9000 also states that if 0-RTT is rejected, the client must reset stream/application state that depended on those assumptions. In other words, 0-RTT acceptance directly affects upper-layer state handling. [RFC 9000, Section 4.6.2](https://datatracker.ietf.org/doc/html/rfc9000#section-4.6.2)
- QUIC uses `0xffffffff` as the sentinel for accepting QUIC 0-RTT. This field is not a reusable arbitrary early-data length. [RFC 9001, Section 4.6.1](https://datatracker.ietf.org/doc/html/rfc9001#section-4.6.1)

## 4. Official Signals from Quinn 0.11 / rustls 0.23

- Quinn's `Connecting::into_0rtt()` documentation directly warns that outgoing 0-RTT is vulnerable to replay attacks and **should not trigger non-idempotent operations**. Incoming 0.5-RTT can happen before TLS client authentication, so it also should not carry data that depends on client auth. [Quinn 0.11.9 docs](https://docs.rs/quinn/0.11.9/quinn/struct.Connecting.html)
- The default value of rustls `ServerConfig::max_early_data_size` is `0`, which disables early data by default. [rustls 0.23.40 docs](https://docs.rs/rustls/0.23.40/rustls/server/struct.ServerConfig.html)
- rustls QUIC support requires `max_early_data_size` to be either `0` or `0xffffffff`; any other value is an error. This means QUIC 0-RTT is explicitly configured in rustls and is not implicitly available. [rustls 0.23.40 QUIC source](https://docs.rs/rustls/0.23.40/src/rustls/quic.rs.html)
- rustls `ClientConnection::is_early_data_accepted()` tells the client whether the server will process early data. If early data was sent but this returns `false`, the caller may need to retransmit. [rustls 0.23.40 QUIC client docs](https://docs.rs/rustls/0.23.40/rustls/quic/struct.ClientConnection.html)
- The rustls roadmap explicitly states that **TLS clients should use session tickets at most once for resumption**; otherwise ticket reuse can enable cross-connection tracking. [rustls ROADMAP](https://github.com/rustls/rustls/blob/main/ROADMAP.md)

## 5. Replay-Sensitive Fields and Packets in MQTT 3.1.1 / 5.0

### 5.1 CONNECT-Related Fields

- MQTT 3.1.1 and 5.0 both use `ClientId` / `Client Identifier` as the session-state index. MQTT 3.1.1 also explicitly says the client and server use it to identify saved session state. [MQTT 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html) / [MQTT 5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)
- MQTT 3.1.1 `Clean Session` and MQTT 5.0 `Clean Start` + `Session Expiry Interval` directly control whether old sessions are restored, old subscriptions are discarded, and buffered messages are retained. Replaying a CONNECT is not harmless; it can change how the broker inherits session state. [MQTT 3.1.1 Clean Session](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html) / [MQTT 5.0 Clean Start](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html) / [MQTT 5.0 Session Expiry](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)
- The MQTT 3.1.1 CONNECT payload order is `Client Identifier`, `Will Topic`, `Will Message`, `User Name`, `Password`; the MQTT 5.0 payload order is `Client Identifier`, `Will Properties`, `Will Topic`, `Will Payload`, `User Name`, `Password`. [MQTT 3.1.1 CONNECT payload](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html) / [MQTT 5.0 CONNECT payload](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)
- `Will` fields are replay-sensitive: a Will in CONNECT is published by the server after abnormal disconnect; MQTT 3.1.1 stores the Will Message as session state; MQTT 5.0 keeps these semantics and adds Will Delay / Will Retain / Will Properties. [MQTT 3.1.1 Will](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html) / [MQTT 5.0 Will](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)
- `User Name` / `Password` / MQTT 5.0 `Authentication Method` / `Authentication Data` are part of the authentication flow. MQTT 5.0 also allows AUTH exchanges between CONNECT and CONNACK, so replaying these fields can affect authentication results or re-authentication flow. [MQTT 5.0 Enhanced Authentication](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)

### 5.2 Data-Plane / Control-Plane Packets

- `PUBLISH` is the most obvious replay-sensitive packet. MQTT 5.0 still defines QoS 1 / QoS 2, `DUP`, `PUBACK` / `PUBREC` / `PUBREL` / `PUBCOMP` as visible state machines. Duplicate delivery changes the number of messages observed by the broker or subscribers. Inference: `QoS 0` has no protocol-level ack/retransmission semantics, but it can still be side-effectful for application commands; the protocol simply does not deduplicate it for you. [MQTT 5.0 PUBLISH / QoS](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)
- MQTT 5.0 also explicitly states that `Message Expiry Interval` is only message lifetime, not replay protection. `Retain` / `Will Retain` only change whether a message is retained; they do not make replay safe. [MQTT 5.0 Message Expiry](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)
- `SUBSCRIBE` / `UNSUBSCRIBE` are replay-sensitive because they directly modify subscription state. MQTT 5.0 allows an existing Subscription to be rebuilt or removed, which also changes future message routing. [MQTT 5.0 SUBSCRIBE/UNSUBSCRIBE](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)
- `AUTH` / re-authentication is replay-sensitive because it belongs to the connection authentication state machine, not an ordinary data stream.
- MQTT 5.0 explicitly states that `Topic Alias` mappings **must not be carried from one Network Connection to another**. This means any early data that depends on existing alias state should not be considered cross-connection safe. [MQTT 5.0 Topic Alias](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)

### 5.3 Common Properties of 3.1.1 and 5.0

- In MQTT 3.1.1 `Clean Session`, the server retains client subscriptions and incomplete QoS 1/2 messages; `Will Message` is published on abnormal disconnect. MQTT 5.0 splits these semantics into `Clean Start` + `Session Expiry Interval` + Will properties, but the replay risk is fundamentally unchanged. [MQTT 3.1.1 Session State / Will](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html) / [MQTT 5.0 Session Expiry / Will](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)
- MQTT 5.0 also explicitly states that if `ClientID` is already connected, the server sends `DISCONNECT` to the old connection (session takeover semantics). Therefore, replaying CONNECT can kick an existing session offline. This is not a "harmless duplicate". [MQTT 5.0 session takeover](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)

## 6. Cluster and Deployment Conclusions

Inference: As long as a ticket / ClientHello / replay key is not strongly consistently shared across brokers or zones, the replay surface must be estimated as "accepted once per node".

- Therefore, **the replay defense for 0-RTT cannot live only at the TLS layer**. The application layer must additionally limit which MQTT packets and fields can appear in early data. [RFC 9001, Section 9.2](https://datatracker.ietf.org/doc/html/rfc9001#section-9.2)
- `session ticket`, `transport parameters`, and `application config` are all part of the 0-RTT accept/reject decision. They must be stored as opaque / auth-bound state, not as carriers of application semantics. [RFC 9000, Section 4.6.3](https://datatracker.ietf.org/doc/html/rfc9000#section-4.6.3)

## 7. Reusable Takeaways

If MQTT over QUIC later needs a 0-RTT strategy, the research baseline is clear:

1. TLS/QUIC only provide tools to limit replay as much as possible; they do not provide application-level safety guarantees.
2. Any packet that changes MQTT session, subscription, authentication, Will, or message delivery count should be considered replay-sensitive.
3. Cluster deployments must make replay state consistent across nodes, or directly prohibit these semantics from entering 0-RTT.
