//! MQTT transaction-to-flow routing ledger.

#![deny(missing_docs)]

use std::collections::HashMap;
use std::fmt;
use std::num::NonZeroU16;

use rmqtt_net::{FlowId, ReplyPath};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
/// Side that allocated an MQTT packet identifier.
pub enum PacketIssuer {
    /// Packet identifier allocated by the connected MQTT client.
    Client,
    /// Packet identifier allocated by the broker.
    Server,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// MQTT transaction family associated with a packet identifier.
pub enum TransactionFamily {
    /// QoS 1 PUBLISH transaction.
    PublishQos1,
    /// QoS 2 PUBLISH transaction.
    PublishQos2,
    /// SUBSCRIBE transaction.
    Subscribe,
    /// UNSUBSCRIBE transaction.
    Unsubscribe,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Expected next acknowledgement in an MQTT transaction.
pub enum TransactionStage {
    /// QoS 1 PUBLISH is awaiting PUBACK.
    PublishQos1AwaitPuback,
    /// Outbound QoS 2 PUBLISH is awaiting PUBREC.
    PublishQos2AwaitPubrec,
    /// Inbound QoS 2 PUBLISH is awaiting PUBREL.
    PublishQos2AwaitPubrel,
    /// Outbound QoS 2 PUBREL is awaiting PUBCOMP.
    PublishQos2AwaitPubcomp,
    /// SUBSCRIBE is awaiting SUBACK.
    SubscribeAwaitSuback,
    /// UNSUBSCRIBE is awaiting UNSUBACK.
    UnsubscribeAwaitUnsuback,
}

impl TransactionFamily {
    /// Returns whether `stage` is valid for this transaction family.
    #[inline]
    pub const fn accepts(self, stage: TransactionStage) -> bool {
        matches!(
            (self, stage),
            (Self::PublishQos1, TransactionStage::PublishQos1AwaitPuback)
                | (Self::PublishQos2, TransactionStage::PublishQos2AwaitPubrec)
                | (Self::PublishQos2, TransactionStage::PublishQos2AwaitPubrel)
                | (Self::PublishQos2, TransactionStage::PublishQos2AwaitPubcomp)
                | (Self::Subscribe, TransactionStage::SubscribeAwaitSuback)
                | (Self::Unsubscribe, TransactionStage::UnsubscribeAwaitUnsuback)
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
/// Issuer-scoped key for an active MQTT transaction route.
pub struct PacketRouteKey {
    issuer: PacketIssuer,
    packet_id: NonZeroU16,
}

impl PacketRouteKey {
    /// Creates a route key from an issuer and a non-zero MQTT packet identifier.
    #[inline]
    pub const fn new(issuer: PacketIssuer, packet_id: NonZeroU16) -> Self {
        Self { issuer, packet_id }
    }

    /// Creates a route key, returning `None` when `packet_id` is zero.
    #[cfg(test)]
    #[inline]
    pub fn try_new(issuer: PacketIssuer, packet_id: u16) -> Option<Self> {
        NonZeroU16::new(packet_id).map(|packet_id| Self::new(issuer, packet_id))
    }

    /// Returns the non-zero MQTT packet identifier.
    #[inline]
    pub const fn packet_id(self) -> NonZeroU16 {
        self.packet_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Active route and protocol state for an MQTT transaction.
pub struct PacketRouteEntry {
    family: TransactionFamily,
    stage: TransactionStage,
    path: ReplyPath,
}

impl PacketRouteEntry {
    /// Creates a route entry for a transaction family, stage, and reply path.
    #[inline]
    pub const fn new(family: TransactionFamily, stage: TransactionStage, path: ReplyPath) -> Self {
        Self { family, stage, path }
    }

    /// Returns the MQTT transaction family.
    #[inline]
    pub const fn family(self) -> TransactionFamily {
        self.family
    }

    /// Returns the acknowledgement stage currently expected.
    #[inline]
    pub const fn stage(self) -> TransactionStage {
        self.stage
    }

    /// Returns the exact flow and generation assigned to the transaction.
    #[inline]
    pub const fn path(self) -> ReplyPath {
        self.path
    }

    /// Returns the QUIC flow identifier assigned to the transaction.
    #[inline]
    pub fn flow_id(self) -> FlowId {
        self.path.flow_id()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Validation failure produced while updating the MQTT route ledger.
pub enum RouteError {
    /// A non-duplicate packet attempted to reuse an active route key.
    Conflict {
        /// Route key that was already active.
        key: PacketRouteKey,
        /// Existing route that owns the key.
        existing: PacketRouteEntry,
    },
    /// No active route exists for the supplied key.
    NotFound {
        /// Route key that was not present.
        key: PacketRouteKey,
    },
    /// A packet arrived on a different flow or flow generation than the active route.
    WrongFlow {
        /// Route key being validated.
        key: PacketRouteKey,
        /// Reply path recorded for the transaction.
        expected: ReplyPath,
        /// Reply path on which the packet arrived.
        actual: ReplyPath,
    },
    /// The packet type belongs to a different transaction family than the active route.
    WrongFamily {
        /// Route key being validated.
        key: PacketRouteKey,
        /// Transaction family recorded for the route.
        expected: TransactionFamily,
        /// Transaction family implied by the packet.
        actual: TransactionFamily,
    },
    /// The packet is invalid for the active transaction stage.
    WrongStage {
        /// Route key being validated.
        key: PacketRouteKey,
        /// Transaction stage recorded for the route.
        expected: TransactionStage,
        /// Transaction stage implied by the packet.
        actual: TransactionStage,
    },
    /// A transaction stage is not valid for its declared family.
    WrongFamilyStage {
        /// Declared transaction family.
        family: TransactionFamily,
        /// Stage rejected for the transaction family.
        stage: TransactionStage,
    },
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for RouteError {}

#[derive(Debug, Default)]
/// Ledger that binds active MQTT transactions to exact QUIC reply paths.
pub struct PacketRouteLedger {
    entries: HashMap<PacketRouteKey, PacketRouteEntry>,
}

impl PacketRouteLedger {
    /// Creates an empty route ledger.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of active transaction routes.
    #[cfg(test)]
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Inserts a route when the key and family-stage combination are unused and valid.
    pub fn insert(
        &mut self,
        key: PacketRouteKey,
        family: TransactionFamily,
        stage: TransactionStage,
        path: ReplyPath,
    ) -> Result<(), RouteError> {
        validate_family_stage(family, stage)?;

        if let Some(existing) = self.entries.get(&key).copied() {
            return Err(RouteError::Conflict { key, existing });
        }

        self.entries.insert(key, PacketRouteEntry::new(family, stage, path));
        Ok(())
    }

    /// Inserts a new route or validates a protocol-level duplicate against the active route.
    ///
    /// Returns `true` when a new route was inserted and `false` when an existing route was a
    /// valid duplicate on the same flow and transaction stage.
    pub fn insert_or_validate_duplicate(
        &mut self,
        key: PacketRouteKey,
        family: TransactionFamily,
        stage: TransactionStage,
        path: ReplyPath,
        duplicate: bool,
    ) -> Result<bool, RouteError> {
        validate_family_stage(family, stage)?;
        if let Some(existing) = self.entries.get(&key).copied() {
            if !duplicate {
                return Err(RouteError::Conflict { key, existing });
            }
            self.validate_entry(key, family, stage, path)?;
            return Ok(false);
        }

        self.entries.insert(key, PacketRouteEntry::new(family, stage, path));
        Ok(true)
    }

    #[inline]
    /// Returns the active route for `key`, if one exists.
    pub fn get(&self, key: PacketRouteKey) -> Option<PacketRouteEntry> {
        self.entries.get(&key).copied()
    }

    /// Validates that an active route matches the supplied family, stage, and exact path.
    pub fn validate(
        &self,
        key: PacketRouteKey,
        family: TransactionFamily,
        stage: TransactionStage,
        path: ReplyPath,
    ) -> Result<PacketRouteEntry, RouteError> {
        validate_family_stage(family, stage)?;
        self.validate_entry(key, family, stage, path)
    }

    /// Advances a matching route to `next_stage` without changing its reply path.
    pub fn transition(
        &mut self,
        key: PacketRouteKey,
        family: TransactionFamily,
        expected_stage: TransactionStage,
        next_stage: TransactionStage,
        path: ReplyPath,
    ) -> Result<PacketRouteEntry, RouteError> {
        validate_family_stage(family, expected_stage)?;
        validate_family_stage(family, next_stage)?;
        self.validate_entry(key, family, expected_stage, path)?;

        let next = PacketRouteEntry::new(family, next_stage, path);
        self.entries.insert(key, next);
        Ok(next)
    }

    /// Validates and removes a completed transaction route.
    pub fn complete(
        &mut self,
        key: PacketRouteKey,
        family: TransactionFamily,
        expected_stage: TransactionStage,
        path: ReplyPath,
    ) -> Result<PacketRouteEntry, RouteError> {
        validate_family_stage(family, expected_stage)?;
        self.validate_entry(key, family, expected_stage, path)?;
        self.entries.remove(&key).ok_or(RouteError::NotFound { key })
    }

    /// Removes and returns the active route for `key` without protocol validation.
    #[inline]
    pub fn remove(&mut self, key: PacketRouteKey) -> Option<PacketRouteEntry> {
        self.entries.remove(&key)
    }

    /// Returns whether any active route is assigned to `flow_id`, regardless of generation.
    pub fn has_flow_entries(&self, flow_id: FlowId) -> bool {
        self.entries.values().any(|entry| entry.flow_id() == flow_id)
    }

    /// Returns whether any active route is assigned to the exact reply path.
    #[cfg(test)]
    pub fn has_path_entries(&self, path: ReplyPath) -> bool {
        self.entries.values().any(|entry| entry.path == path)
    }

    /// Removes all routes assigned to `flow_id` and returns the number removed.
    #[cfg(test)]
    pub fn remove_flow(&mut self, flow_id: FlowId) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| entry.flow_id() != flow_id);
        before - self.entries.len()
    }

    /// Removes all routes assigned to the exact reply path and returns the number removed.
    #[cfg(test)]
    pub fn remove_path(&mut self, path: ReplyPath) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| entry.path != path);
        before - self.entries.len()
    }

    fn validate_entry(
        &self,
        key: PacketRouteKey,
        family: TransactionFamily,
        stage: TransactionStage,
        path: ReplyPath,
    ) -> Result<PacketRouteEntry, RouteError> {
        let entry = self.entries.get(&key).copied().ok_or(RouteError::NotFound { key })?;

        if entry.path != path {
            return Err(RouteError::WrongFlow { key, expected: entry.path, actual: path });
        }

        if entry.family != family {
            return Err(RouteError::WrongFamily { key, expected: entry.family, actual: family });
        }

        if entry.stage != stage {
            return Err(RouteError::WrongStage { key, expected: entry.stage, actual: stage });
        }

        Ok(entry)
    }
}

#[inline]
fn validate_family_stage(family: TransactionFamily, stage: TransactionStage) -> Result<(), RouteError> {
    if family.accepts(stage) {
        Ok(())
    } else {
        Err(RouteError::WrongFamilyStage { family, stage })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmqtt_net::FlowKind;

    fn key(issuer: PacketIssuer, packet_id: u16) -> PacketRouteKey {
        PacketRouteKey::try_new(issuer, packet_id).expect("non-zero packet id")
    }

    fn path(flow_id: u64, generation: u64) -> ReplyPath {
        ReplyPath::new(FlowId::new(flow_id), FlowKind::Data, generation)
    }

    #[test]
    fn same_numeric_packet_id_is_scoped_by_issuer() {
        let mut ledger = PacketRouteLedger::new();
        let client_key = key(PacketIssuer::Client, 7);
        let server_key = key(PacketIssuer::Server, 7);
        let client_path = path(11, 1);
        let server_path = path(12, 1);

        ledger
            .insert(
                client_key,
                TransactionFamily::PublishQos1,
                TransactionStage::PublishQos1AwaitPuback,
                client_path,
            )
            .unwrap();
        ledger
            .insert(
                server_key,
                TransactionFamily::Subscribe,
                TransactionStage::SubscribeAwaitSuback,
                server_path,
            )
            .unwrap();

        assert_eq!(ledger.len(), 2);
        assert_eq!(ledger.get(client_key).unwrap().path(), client_path);
        assert_eq!(ledger.get(server_key).unwrap().path(), server_path);
    }

    #[test]
    fn same_issuer_cannot_reuse_packet_id_until_removed() {
        let mut ledger = PacketRouteLedger::new();
        let route_key = key(PacketIssuer::Client, 9);

        ledger
            .insert(
                route_key,
                TransactionFamily::PublishQos1,
                TransactionStage::PublishQos1AwaitPuback,
                path(21, 1),
            )
            .unwrap();

        let error = ledger
            .insert(
                route_key,
                TransactionFamily::Subscribe,
                TransactionStage::SubscribeAwaitSuback,
                path(22, 1),
            )
            .unwrap_err();

        assert!(matches!(error, RouteError::Conflict { key, .. } if key == route_key));
    }

    #[test]
    fn qos2_duplicate_must_match_the_active_flow_and_stage() {
        let mut ledger = PacketRouteLedger::new();
        let route_key = key(PacketIssuer::Client, 22);
        let route_path = path(2, 7);
        let wrong_path = path(3, 7);

        assert!(ledger
            .insert_or_validate_duplicate(
                route_key,
                TransactionFamily::PublishQos2,
                TransactionStage::PublishQos2AwaitPubrel,
                route_path,
                false,
            )
            .unwrap());
        assert!(!ledger
            .insert_or_validate_duplicate(
                route_key,
                TransactionFamily::PublishQos2,
                TransactionStage::PublishQos2AwaitPubrel,
                route_path,
                true,
            )
            .unwrap());
        assert!(matches!(
            ledger.insert_or_validate_duplicate(
                route_key,
                TransactionFamily::PublishQos2,
                TransactionStage::PublishQos2AwaitPubrel,
                wrong_path,
                true,
            ),
            Err(RouteError::WrongFlow { .. })
        ));
        assert!(matches!(
            ledger.insert_or_validate_duplicate(
                route_key,
                TransactionFamily::PublishQos2,
                TransactionStage::PublishQos2AwaitPubrel,
                route_path,
                false,
            ),
            Err(RouteError::Conflict { .. })
        ));
    }

    #[test]
    fn outbound_qos1_retry_reuses_the_existing_route() {
        let mut ledger = PacketRouteLedger::new();
        let route_key = key(PacketIssuer::Server, 23);
        let route_path = path(4, 9);

        assert!(ledger
            .insert_or_validate_duplicate(
                route_key,
                TransactionFamily::PublishQos1,
                TransactionStage::PublishQos1AwaitPuback,
                route_path,
                false,
            )
            .unwrap());
        assert!(!ledger
            .insert_or_validate_duplicate(
                route_key,
                TransactionFamily::PublishQos1,
                TransactionStage::PublishQos1AwaitPuback,
                route_path,
                true,
            )
            .unwrap());
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger.get(route_key).unwrap().path(), route_path);
    }

    #[test]
    fn transition_validates_flow_family_and_stage_before_mutating() {
        let mut ledger = PacketRouteLedger::new();
        let route_key = key(PacketIssuer::Server, 10);
        let original_path = path(31, 1);

        ledger
            .insert(
                route_key,
                TransactionFamily::PublishQos2,
                TransactionStage::PublishQos2AwaitPubrec,
                original_path,
            )
            .unwrap();

        assert_eq!(
            ledger
                .transition(
                    route_key,
                    TransactionFamily::PublishQos2,
                    TransactionStage::PublishQos2AwaitPubrec,
                    TransactionStage::PublishQos2AwaitPubrel,
                    path(32, 1),
                )
                .unwrap_err(),
            RouteError::WrongFlow { key: route_key, expected: original_path, actual: path(32, 1) }
        );
        assert_eq!(ledger.get(route_key).unwrap().stage(), TransactionStage::PublishQos2AwaitPubrec);

        assert_eq!(
            ledger
                .transition(
                    route_key,
                    TransactionFamily::PublishQos1,
                    TransactionStage::PublishQos1AwaitPuback,
                    TransactionStage::PublishQos1AwaitPuback,
                    original_path,
                )
                .unwrap_err(),
            RouteError::WrongFamily {
                key: route_key,
                expected: TransactionFamily::PublishQos2,
                actual: TransactionFamily::PublishQos1,
            }
        );
        assert_eq!(ledger.get(route_key).unwrap().stage(), TransactionStage::PublishQos2AwaitPubrec);

        let next = ledger
            .transition(
                route_key,
                TransactionFamily::PublishQos2,
                TransactionStage::PublishQos2AwaitPubrec,
                TransactionStage::PublishQos2AwaitPubrel,
                original_path,
            )
            .unwrap();

        assert_eq!(next.stage(), TransactionStage::PublishQos2AwaitPubrel);
        assert_eq!(ledger.get(route_key).unwrap().stage(), TransactionStage::PublishQos2AwaitPubrel);
    }

    #[test]
    fn completion_validates_then_removes_entry() {
        let mut ledger = PacketRouteLedger::new();
        let route_key = key(PacketIssuer::Client, 11);
        let route_path = path(41, 1);

        ledger
            .insert(
                route_key,
                TransactionFamily::Unsubscribe,
                TransactionStage::UnsubscribeAwaitUnsuback,
                route_path,
            )
            .unwrap();

        assert_eq!(
            ledger
                .complete(
                    route_key,
                    TransactionFamily::Unsubscribe,
                    TransactionStage::SubscribeAwaitSuback,
                    route_path,
                )
                .unwrap_err(),
            RouteError::WrongFamilyStage {
                family: TransactionFamily::Unsubscribe,
                stage: TransactionStage::SubscribeAwaitSuback,
            }
        );
        assert!(ledger.get(route_key).is_some());

        let completed = ledger
            .complete(
                route_key,
                TransactionFamily::Unsubscribe,
                TransactionStage::UnsubscribeAwaitUnsuback,
                route_path,
            )
            .unwrap();

        assert_eq!(completed.path(), route_path);
        assert!(ledger.get(route_key).is_none());
        assert_eq!(
            ledger.complete(
                route_key,
                TransactionFamily::Unsubscribe,
                TransactionStage::UnsubscribeAwaitUnsuback,
                route_path,
            ),
            Err(RouteError::NotFound { key: route_key })
        );
    }

    #[test]
    fn flow_queries_and_removal_support_flow_and_generation_cleanup() {
        let mut ledger = PacketRouteLedger::new();
        let first = key(PacketIssuer::Client, 1);
        let second = key(PacketIssuer::Server, 1);
        let third = key(PacketIssuer::Client, 2);

        ledger
            .insert(
                first,
                TransactionFamily::PublishQos1,
                TransactionStage::PublishQos1AwaitPuback,
                path(51, 1),
            )
            .unwrap();
        ledger
            .insert(
                second,
                TransactionFamily::PublishQos2,
                TransactionStage::PublishQos2AwaitPubcomp,
                path(51, 2),
            )
            .unwrap();
        ledger
            .insert(third, TransactionFamily::Subscribe, TransactionStage::SubscribeAwaitSuback, path(52, 1))
            .unwrap();

        assert!(ledger.has_path_entries(path(51, 1)));
        assert!(ledger.has_flow_entries(FlowId::new(51)));
        assert_eq!(ledger.remove_path(path(51, 1)), 1);
        assert!(!ledger.has_path_entries(path(51, 1)));
        assert!(ledger.has_path_entries(path(51, 2)));
        assert_eq!(ledger.remove_flow(FlowId::new(51)), 1);
        assert!(!ledger.has_flow_entries(FlowId::new(51)));
        assert!(ledger.has_flow_entries(FlowId::new(52)));
        assert_eq!(ledger.len(), 1);
    }
}
