use std::collections::BTreeMap;

use crate::topic::Topic as TopicFilter;
use rmqtt_net::{FlowId, ReplyPath};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BindingState {
    PendingAck,
    Active,
}

#[derive(Debug, Default)]
pub(crate) struct SubscriptionBindingStore {
    bindings: BTreeMap<TopicFilter, Binding>,
}

#[derive(Clone, Debug)]
struct Binding {
    path: ReplyPath,
    state: BindingState,
}

impl SubscriptionBindingStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn begin(&mut self, topic_filter: TopicFilter, path: ReplyPath) {
        self.bindings.insert(topic_filter, Binding { path, state: BindingState::PendingAck });
    }

    pub(crate) fn activate(&mut self, topic_filter: &TopicFilter) -> bool {
        let Some(binding) = self.bindings.get_mut(topic_filter) else {
            return false;
        };

        binding.state = BindingState::Active;
        true
    }

    pub(crate) fn unsubscribe(&mut self, topic_filter: &TopicFilter) -> bool {
        self.bindings.remove(topic_filter).is_some()
    }

    pub(crate) fn remove_flow(&mut self, flow_id: FlowId) -> usize {
        let before = self.bindings.len();
        self.bindings.retain(|_, binding| binding.path.flow_id() != flow_id);
        before - self.bindings.len()
    }

    pub(crate) fn route(&self, topic: &str) -> Option<ReplyPath> {
        self.bindings
            .iter()
            .filter(|(filter, binding)| {
                binding.state == BindingState::Active
                    && binding.path.flow_id() != FlowId::CONTROL
                    && filter.matches_str(topic)
            })
            .min_by_key(|(filter, binding)| {
                (binding.path.flow_id().get(), binding.path.generation(), filter.to_string())
            })
            .map(|(_, binding)| binding.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmqtt_net::FlowKind;

    fn data_path(flow: u64) -> ReplyPath {
        ReplyPath::new(FlowId::new(flow), FlowKind::Data, 0)
    }

    fn parsed(filter: &str) -> TopicFilter {
        filter.parse().unwrap()
    }

    #[test]
    fn activates_suback_committed_binding_and_routes_lowest_data_flow() {
        let mut store = SubscriptionBindingStore::new();
        store.begin(parsed("sensors/#"), data_path(7));
        store.begin(parsed("sensors/+/temp"), data_path(3));

        assert_eq!(store.route("sensors/a/temp"), None);
        assert!(store.activate(&parsed("sensors/#")));
        assert_eq!(store.route("sensors/a/temp"), Some(data_path(7)));
        assert!(store.activate(&parsed("sensors/+/temp")));
        assert_eq!(store.route("sensors/a/temp"), Some(data_path(3)));
    }

    #[test]
    fn control_only_matching_binding_does_not_route() {
        let mut store = SubscriptionBindingStore::new();
        store.begin(parsed("sensors/#"), ReplyPath::CONTROL);
        store.activate(&parsed("sensors/#"));

        assert_eq!(store.route("sensors/a/temp"), None);
    }

    #[test]
    fn resubscribe_replaces_prior_path() {
        let mut store = SubscriptionBindingStore::new();
        store.begin(parsed("sensors/#"), data_path(8));
        store.activate(&parsed("sensors/#"));
        store.begin(parsed("sensors/#"), data_path(4));
        store.activate(&parsed("sensors/#"));

        assert_eq!(store.route("sensors/a/temp"), Some(data_path(4)));
    }

    #[test]
    fn unsubscribe_and_remove_flow_delete_bindings() {
        let mut store = SubscriptionBindingStore::new();
        store.begin(parsed("sensors/#"), data_path(8));
        store.begin(parsed("devices/#"), data_path(4));
        store.activate(&parsed("sensors/#"));
        store.activate(&parsed("devices/#"));

        assert!(store.unsubscribe(&parsed("sensors/#")));
        assert_eq!(store.route("sensors/a/temp"), None);
        assert_eq!(store.route("devices/a"), Some(data_path(4)));
        assert_eq!(store.remove_flow(FlowId::new(4)), 1);
        assert_eq!(store.route("devices/a"), None);
    }

    #[test]
    fn restored_subscriptions_are_absent_until_begin_is_called() {
        let store = SubscriptionBindingStore::new();

        assert_eq!(store.route("sensors/a/temp"), None);
    }
}
