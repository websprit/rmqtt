#![cfg(feature = "tls")]
#![deny(missing_docs)]

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rustls::server::StoresServerSessions;

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
/// Stable fingerprint of settings that must match before a QUIC ticket can be resumed.
pub struct ZeroRttProfileFingerprint([u8; 32]);

impl ZeroRttProfileFingerprint {
    /// Builds a fingerprint from an already-derived 32-byte value.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Derives a fingerprint from every transport and authentication setting that affects 0-RTT safety.
    pub fn new<I, A, M>(
        alpn_protocols: I,
        initial_max_bidi_streams: u64,
        initial_max_uni_streams: u64,
        pre_finished_read_budget: u64,
        credential_auth_policy_epoch: u64,
        multistream_mode: M,
    ) -> Self
    where
        I: IntoIterator<Item = A>,
        A: AsRef<[u8]>,
        M: AsRef<str>,
    {
        let mut hasher = StableHasher::new();
        hasher.update_tagged_bytes(1, b"rmqtt-net/quic-0rtt-profile/v1");
        for alpn in alpn_protocols {
            hasher.update_tagged_bytes(2, alpn.as_ref());
        }
        hasher.update_tagged_u64(3, initial_max_bidi_streams);
        hasher.update_tagged_u64(4, initial_max_uni_streams);
        hasher.update_tagged_u64(5, pre_finished_read_budget);
        hasher.update_tagged_u64(6, credential_auth_policy_epoch);
        hasher.update_tagged_bytes(7, multistream_mode.as_ref().as_bytes());
        Self(hasher.finish())
    }

    /// Derives the standard MQTT-over-QUIC profile with one bidirectional control stream.
    pub fn mqtt_quic<I, A, M>(
        alpn_protocols: I,
        pre_finished_read_budget: u64,
        credential_auth_policy_epoch: u64,
        multistream_mode: M,
    ) -> Self
    where
        I: IntoIterator<Item = A>,
        A: AsRef<[u8]>,
        M: AsRef<str>,
    {
        Self::new(
            alpn_protocols,
            1,
            0,
            pre_finished_read_budget,
            credential_auth_policy_epoch,
            multistream_mode,
        )
    }

    /// Returns the fingerprint bytes used to namespace session-ticket keys.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ZeroRttProfileFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ZeroRttProfileFingerprint").field(&self.0).finish()
    }
}

#[derive(Debug)]
/// Bounded, profile-scoped TLS session store whose tickets are consumed atomically.
///
/// `take` removes a ticket under the store mutex, so concurrent resumptions cannot
/// successfully consume the same ticket more than once. A poisoned mutex is treated
/// as a cache miss to preserve replay safety.
pub struct ReplaySafeServerSessionStore {
    capacity: usize,
    ttl: Duration,
    profile: ZeroRttProfileFingerprint,
    inner: Mutex<Inner>,
}

impl ReplaySafeServerSessionStore {
    /// Creates a replay-safe session store with the supplied capacity, lifetime, and profile.
    pub fn new(capacity: usize, ttl: Duration, profile: ZeroRttProfileFingerprint) -> Arc<Self> {
        Arc::new(Self { capacity, ttl, profile, inner: Mutex::new(Inner::default()) })
    }

    fn wrapped_key(&self, key: &[u8]) -> Vec<u8> {
        let mut wrapped = Vec::with_capacity(self.profile.0.len() + key.len());
        wrapped.extend_from_slice(&self.profile.0);
        wrapped.extend_from_slice(key);
        wrapped
    }
}

impl StoresServerSessions for ReplaySafeServerSessionStore {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        if self.capacity == 0 {
            return false;
        }

        let now = Instant::now();
        let wrapped_key = self.wrapped_key(&key);
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        inner.purge_expired(now);

        let generation = inner.next_generation;
        inner.next_generation = inner.next_generation.wrapping_add(1);
        inner.order.push_back((wrapped_key.clone(), generation));
        let expires_at = match now.checked_add(self.ttl) {
            Some(expires_at) => expires_at,
            None => now,
        };
        inner.sessions.insert(wrapped_key, Entry { value, expires_at, generation });
        inner.evict_to_capacity(self.capacity);
        inner.maybe_compact_order(self.capacity);
        true
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let now = Instant::now();
        let wrapped_key = self.wrapped_key(key);
        let Ok(mut inner) = self.inner.lock() else {
            return None;
        };
        inner.purge_expired(now);
        inner.sessions.get(&wrapped_key).map(|entry| entry.value.clone())
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        let now = Instant::now();
        let wrapped_key = self.wrapped_key(key);
        let Ok(mut inner) = self.inner.lock() else {
            return None;
        };
        inner.purge_expired(now);
        let value = inner.sessions.remove(&wrapped_key).map(|entry| entry.value);
        inner.maybe_compact_order(self.capacity);
        value
    }

    fn can_cache(&self) -> bool {
        true
    }
}

#[derive(Debug, Default)]
struct Inner {
    sessions: HashMap<Vec<u8>, Entry>,
    order: VecDeque<(Vec<u8>, u64)>,
    next_generation: u64,
}

impl Inner {
    fn purge_expired(&mut self, now: Instant) {
        self.sessions.retain(|_, entry| !entry.is_expired(now));
    }

    fn evict_to_capacity(&mut self, capacity: usize) {
        while self.sessions.len() > capacity {
            match self.order.pop_front() {
                Some((key, generation)) => {
                    if self.sessions.get(&key).is_some_and(|entry| entry.generation == generation) {
                        self.sessions.remove(&key);
                    }
                }
                None => break,
            }
        }
    }

    fn maybe_compact_order(&mut self, capacity: usize) {
        let tombstone_budget = capacity.saturating_mul(2).max(64);
        if self.order.len() <= self.sessions.len().saturating_add(tombstone_budget) {
            return;
        }
        self.order.retain(|(key, generation)| {
            self.sessions.get(key).is_some_and(|entry| entry.generation == *generation)
        });
    }
}

#[derive(Debug)]
struct Entry {
    value: Vec<u8>,
    expires_at: Instant,
    generation: u64,
}

impl Entry {
    fn is_expired(&self, now: Instant) -> bool {
        self.expires_at <= now
    }
}

struct StableHasher {
    lanes: [u64; 4],
}

impl StableHasher {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    fn new() -> Self {
        Self {
            lanes: [
                Self::FNV_OFFSET,
                Self::FNV_OFFSET ^ 0x9e3779b97f4a7c15,
                Self::FNV_OFFSET ^ 0xc2b2ae3d27d4eb4f,
                Self::FNV_OFFSET ^ 0x165667b19e3779f9,
            ],
        }
    }

    fn update_tagged_bytes(&mut self, tag: u8, value: &[u8]) {
        self.update(&[tag]);
        self.update(&(value.len() as u64).to_le_bytes());
        self.update(value);
    }

    fn update_tagged_u64(&mut self, tag: u8, value: u64) {
        self.update(&[tag]);
        self.update(&value.to_le_bytes());
    }

    fn update(&mut self, bytes: &[u8]) {
        for lane in &mut self.lanes {
            for byte in bytes {
                *lane ^= u64::from(*byte);
                *lane = lane.wrapping_mul(Self::FNV_PRIME);
            }
            *lane ^= bytes.len() as u64;
            *lane = lane.wrapping_mul(Self::FNV_PRIME);
        }
    }

    fn finish(self) -> [u8; 32] {
        let mut bytes = [0; 32];
        for (index, lane) in self.lanes.into_iter().enumerate() {
            bytes[index * 8..(index + 1) * 8].copy_from_slice(&lane.to_le_bytes());
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::thread;

    fn profile(id: u8) -> ZeroRttProfileFingerprint {
        ZeroRttProfileFingerprint::from_bytes([id; 32])
    }

    #[test]
    fn fingerprint_is_derived_from_quic_zero_rtt_profile_inputs() {
        let base =
            ZeroRttProfileFingerprint::mqtt_quic([b"mqtt".as_slice(), b"mqttv5"], 64 * 1024, 7, "disabled");

        assert_eq!(
            base,
            ZeroRttProfileFingerprint::new([b"mqtt".as_slice(), b"mqttv5"], 1, 0, 64 * 1024, 7, "disabled",)
        );
        assert_ne!(
            base,
            ZeroRttProfileFingerprint::new([b"mqtt".as_slice(), b"mqttv5"], 2, 0, 64 * 1024, 7, "disabled",)
        );
        assert_ne!(
            base,
            ZeroRttProfileFingerprint::mqtt_quic([b"mqtt".as_slice(), b"mqttv5"], 64 * 1024, 8, "disabled",)
        );
        assert_ne!(
            base,
            ZeroRttProfileFingerprint::mqtt_quic([b"mqtt".as_slice(), b"mqttv5"], 32 * 1024, 7, "disabled",)
        );
        assert_ne!(
            base,
            ZeroRttProfileFingerprint::mqtt_quic([b"mqtt".as_slice(), b"mqttv5"], 64 * 1024, 7, "simple",)
        );
    }

    #[test]
    fn take_is_single_use_under_concurrency() {
        let store = ReplaySafeServerSessionStore::new(8, Duration::from_secs(60), profile(1));
        assert!(store.put(b"ticket".to_vec(), b"secret".to_vec()));

        let barrier = Arc::new(Barrier::new(8));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                barrier.wait();
                store.take(b"ticket")
            }));
        }

        let values: Vec<_> = threads.into_iter().map(|thread| thread.join().unwrap()).collect();
        assert_eq!(values.iter().filter(|value| value.is_some()).count(), 1);
        assert_eq!(values.into_iter().flatten().collect::<Vec<_>>(), vec![b"secret".to_vec()]);
        assert_eq!(store.take(b"ticket"), None);
    }

    #[test]
    fn expired_entries_are_misses() {
        let store = ReplaySafeServerSessionStore::new(8, Duration::ZERO, profile(1));
        assert!(store.put(b"ticket".to_vec(), b"secret".to_vec()));

        assert_eq!(store.get(b"ticket"), None);
        assert_eq!(store.take(b"ticket"), None);
    }

    #[test]
    fn capacity_zero_and_eviction_are_safe() {
        let disabled = ReplaySafeServerSessionStore::new(0, Duration::from_secs(60), profile(1));
        assert!(!disabled.put(b"ticket".to_vec(), b"secret".to_vec()));
        assert_eq!(disabled.get(b"ticket"), None);

        let store = ReplaySafeServerSessionStore::new(2, Duration::from_secs(60), profile(1));
        assert!(store.put(b"first".to_vec(), b"1".to_vec()));
        assert!(store.put(b"second".to_vec(), b"2".to_vec()));
        assert!(store.put(b"third".to_vec(), b"3".to_vec()));

        assert_eq!(store.get(b"first"), None);
        assert_eq!(store.get(b"second"), Some(b"2".to_vec()));
        assert_eq!(store.get(b"third"), Some(b"3".to_vec()));
    }

    #[test]
    fn profile_fingerprint_mismatch_is_a_miss() {
        let first = ReplaySafeServerSessionStore::new(8, Duration::from_secs(60), profile(1));
        let second = ReplaySafeServerSessionStore::new(8, Duration::from_secs(60), profile(2));

        assert!(first.put(b"ticket".to_vec(), b"secret".to_vec()));
        assert_eq!(first.get(b"ticket"), Some(b"secret".to_vec()));
        assert_eq!(second.get(b"ticket"), None);
        assert_eq!(second.take(b"ticket"), None);
    }

    #[test]
    fn consumed_ticket_tombstones_are_compacted() {
        let store = ReplaySafeServerSessionStore::new(2, Duration::from_secs(60), profile(1));

        for index in 0_u32..10_000 {
            let key = index.to_le_bytes().to_vec();
            assert!(store.put(key.clone(), b"secret".to_vec()));
            assert_eq!(store.take(&key), Some(b"secret".to_vec()));
        }

        let inner = store.inner.lock().unwrap();
        assert!(inner.sessions.is_empty());
        assert!(inner.order.len() <= 64, "consumed ticket tombstones must remain bounded");
    }

    #[test]
    fn ttl_overflow_expires_instead_of_becoming_unbounded() {
        let store = ReplaySafeServerSessionStore::new(1, Duration::MAX, profile(1));
        assert!(store.put(b"ticket".to_vec(), b"secret".to_vec()));

        assert_eq!(store.take(b"ticket"), None);
    }

    #[test]
    fn poisoned_store_fails_closed() {
        let store = ReplaySafeServerSessionStore::new(1, Duration::from_secs(60), profile(1));
        let poison_store = Arc::clone(&store);

        let result = thread::spawn(move || {
            let _inner = match poison_store.inner.lock() {
                Ok(inner) => inner,
                Err(_) => panic!("test must acquire unpoisoned session-store lock"),
            };
            panic!("poison session store");
        })
        .join();

        assert!(result.is_err());
        assert!(!store.put(b"ticket".to_vec(), b"secret".to_vec()));
        assert_eq!(store.get(b"ticket"), None);
        assert_eq!(store.take(b"ticket"), None);
    }
}
