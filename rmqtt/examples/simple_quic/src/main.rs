//! Example: MQTT server with a QUIC (UDP) transport listener on port 9443.
//! Demonstrates TLS certificates and explicitly enables replay-sensitive QUIC 0-RTT for the
//! companion `simple_quic_client` example.

use rmqtt::{context::ServerContext, net::Builder, server::MqttServer, Result};
use simple_logger::SimpleLogger;

#[tokio::main]
async fn main() -> Result<()> {
    SimpleLogger::new().with_level(log::LevelFilter::Info).init()?;

    let scx = ServerContext::new().build().await;

    MqttServer::new(scx)
        .listener(
            Builder::new()
                .name("external/quic")
                .laddr(([0, 0, 0, 0], 9443).into())
                .tls_key(Some("./rmqtt-bin/rmqtt.key"))
                .tls_cert(Some("./rmqtt-bin/rmqtt.pem"))
                .enable_quic_0rtt(true)
                .bind_quic()?,
        )
        .build()
        .run()
        .await?;
    Ok(())
}
