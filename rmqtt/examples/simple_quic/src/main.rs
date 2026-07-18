//! Example: MQTT server with a QUIC (UDP) transport listener on port 9443.
//! Demonstrates TLS certificates and explicitly enables replay-sensitive QUIC 0-RTT for the
//! companion `simple_quic_client` example.

use std::env;

use rmqtt::{context::ServerContext, net::Builder, server::MqttServer, Result};
use simple_logger::SimpleLogger;

#[tokio::main]
async fn main() -> Result<()> {
    SimpleLogger::new().with_level(log::LevelFilter::Info).init()?;

    let scx = ServerContext::new().build().await;
    let tls_key = env::var("RMQTT_QUIC_KEY").unwrap_or_else(|_| "./rmqtt-bin/rmqtt.key".into());
    let tls_cert = env::var("RMQTT_QUIC_CERT").unwrap_or_else(|_| "./rmqtt-bin/rmqtt.pem".into());

    MqttServer::new(scx)
        .listener(
            Builder::new()
                .name("external/quic")
                .laddr(([0, 0, 0, 0], 9443).into())
                .tls_key(Some(tls_key))
                .tls_cert(Some(tls_cert))
                .allow_anonymous(true)
                .enable_quic_0rtt(true)
                .quic_0rtt_credential_profile("anonymous")
                .multistream_mode("simple")
                .multistream_negotiation("preconfigured")
                .bind_quic()?,
        )
        .build()
        .run()
        .await?;
    Ok(())
}
