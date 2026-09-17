//! Coalescing of identical in-flight requests.
//!
//! When several clients ask the same question at once — a common shape on a
//! busy network, where one blocked ad domain is queried by every device in the
//! house — only the first goes upstream and the rest wait for its answer.
//! This is the `pending_requests` setting.

use std::collections::HashMap;
use std::sync::Arc;

use hickory_proto::op::Message;
use parking_lot::Mutex;
use tokio::sync::watch;

use crate::cache::Key;

/// What identifies "the same request".
///
/// The cache key plus the client subnet: two clients in different subnets can
/// legitimately get different answers, so their requests must not be merged.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct PendingKey {
    /// The question.
    pub key: Key,
    /// The EDNS Client Subnet, when one is being sent.
    pub subnet: Option<(std::net::IpAddr, u8)>,
}

/// One in-flight request other callers may be waiting on.
struct Slot {
    /// Flipped once the answer, or its absence, is published.
    tx: watch::Sender<bool>,
    /// The answer, or `None` when the leader failed.
    answer: Mutex<Option<Message>>,
}

/// The set of in-flight requests.
#[derive(Default)]
pub struct Pending {
    /// The requests currently being resolved.
    inflight: Mutex<HashMap<PendingKey, Arc<Slot>>>,
}

/// The leader's handle on a slot.
///
/// Dropping it without calling [`Leader::finish`] publishes a failure, so a
/// panic or an early return cannot leave the followers waiting forever.
pub struct Leader<'a> {
    /// Where to remove the slot from when done.
    pending: &'a Pending,
    /// The key being resolved.
    key: PendingKey,
    /// The slot the followers are watching.
    slot: Arc<Slot>,
    /// Whether the answer has been published.
    done: bool,
}

impl Leader<'_> {
    /// Publishes the answer to everyone waiting.
    pub fn finish(mut self, answer: Option<&Message>) {
        *self.slot.answer.lock() = answer.cloned();
        self.done = true;
        self.pending.inflight.lock().remove(&self.key);
        let _ = self.slot.tx.send(true);
    }
}

impl Drop for Leader<'_> {
    fn drop(&mut self) {
        if self.done {
            return;
        }

        self.pending.inflight.lock().remove(&self.key);
        let _ = self.slot.tx.send(true);
    }
}

/// What [`Pending::enter`] found.
pub enum Entry<'a> {
    /// Nobody else is asking: resolve, then publish.
    Lead(Leader<'a>),
    /// Somebody else is already asking; await this instead.
    Follow(Waiter),
}

/// A follower's handle, awaiting the leader's answer.
pub struct Waiter {
    /// The slot being watched.
    slot: Arc<Slot>,
    /// The change notification.
    rx: watch::Receiver<bool>,
}

impl Waiter {
    /// Waits for the leader and returns its answer, if it got one.
    pub async fn wait(mut self) -> Option<Message> {
        // A send error means the leader is gone and the slot is final.
        let _ = self.rx.wait_for(|done| *done).await;

        self.slot.answer.lock().clone()
    }
}

impl Pending {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Joins or starts the resolution of `key`.
    pub fn enter(&self, key: PendingKey) -> Entry<'_> {
        let mut map = self.inflight.lock();
        if let Some(slot) = map.get(&key) {
            let rx = slot.tx.subscribe();

            return Entry::Follow(Waiter {
                slot: slot.clone(),
                rx,
            });
        }

        let (tx, _rx) = watch::channel(false);
        let slot = Arc::new(Slot {
            tx,
            answer: Mutex::new(None),
        });
        map.insert(key.clone(), slot.clone());

        Entry::Lead(Leader {
            pending: self,
            key,
            slot,
            done: false,
        })
    }

    /// How many requests are in flight, for tests and diagnostics.
    pub fn len(&self) -> usize {
        self.inflight.lock().len()
    }

    /// Reports whether nothing is in flight.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, RecordType};

    fn key(name: &str) -> PendingKey {
        let mut m = Message::query();
        m.add_query(Query::query(Name::from_utf8(name).unwrap(), RecordType::A));

        PendingKey {
            key: Key::from_request(&m).unwrap(),
            subnet: None,
        }
    }

    fn answer(name: &str) -> Message {
        let mut m = Message::query();
        m.add_query(Query::query(Name::from_utf8(name).unwrap(), RecordType::A));
        m.metadata.id = 0x2222;

        m
    }

    #[tokio::test]
    async fn the_first_caller_leads_and_the_second_follows() {
        let p = Pending::new();

        let Entry::Lead(leader) = p.enter(key("example.com.")) else {
            panic!("the first caller should lead");
        };
        let Entry::Follow(waiter) = p.enter(key("example.com.")) else {
            panic!("the second caller should follow");
        };

        let task = tokio::spawn(async move { waiter.wait().await });
        leader.finish(Some(&answer("example.com.")));

        let got = task
            .await
            .unwrap()
            .expect("the follower should get the answer");
        assert_eq!(got.metadata.id, 0x2222);
        assert!(p.is_empty(), "the slot is released once published");
    }

    #[tokio::test]
    async fn different_questions_do_not_merge() {
        let p = Pending::new();
        let a = p.enter(key("a.example."));
        let b = p.enter(key("b.example."));

        assert!(matches!(a, Entry::Lead(_)));
        assert!(matches!(b, Entry::Lead(_)), "a different name leads too");
    }

    #[tokio::test]
    async fn different_subnets_do_not_merge() {
        // Two clients in different subnets can legitimately get different
        // answers, so merging them would hand one the other's result.
        let p = Pending::new();
        let mut k1 = key("example.com.");
        k1.subnet = Some(("192.0.2.0".parse().unwrap(), 24));
        let mut k2 = key("example.com.");
        k2.subnet = Some(("198.51.100.0".parse().unwrap(), 24));

        assert!(matches!(p.enter(k1), Entry::Lead(_)));
        assert!(matches!(p.enter(k2), Entry::Lead(_)));
    }

    #[tokio::test]
    async fn a_leader_that_fails_releases_its_followers() {
        let p = Pending::new();
        let Entry::Lead(leader) = p.enter(key("example.com.")) else {
            panic!("expected to lead");
        };
        let Entry::Follow(waiter) = p.enter(key("example.com.")) else {
            panic!("expected to follow");
        };

        let task = tokio::spawn(async move { waiter.wait().await });
        leader.finish(None);

        assert!(task.await.unwrap().is_none());
    }

    #[tokio::test]
    async fn dropping_a_leader_does_not_strand_followers() {
        let p = Pending::new();
        let leader = p.enter(key("example.com."));
        let Entry::Follow(waiter) = p.enter(key("example.com.")) else {
            panic!("expected to follow");
        };

        let task = tokio::spawn(async move { waiter.wait().await });
        drop(leader);

        assert!(task.await.unwrap().is_none());
        assert!(p.is_empty());
    }
}
