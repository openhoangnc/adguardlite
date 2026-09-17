//! Background refreshes of cache entries.
//!
//! A cache entry that is about to expire, or that has just been served stale
//! under `cache_optimistic`, is fetched again out of band so the client that
//! asks next does not have to wait for an upstream exchange.
//!
//! A refresh goes straight to [`Resolver::forward`] and never through
//! [`crate::server::Server::handle`].  The query log, the statistics, the
//! rate limiter and `max_goroutines` all belong to the client that asked a
//! question, and a refresh has no client: routing one through the server
//! would count every popular name twice in `/control/stats` and write a
//! second line to `querylog.json` that no device ever asked for.

use std::sync::Arc;

use hickory_proto::op::Message;
use tokio::sync::{Semaphore, mpsc};

use crate::cache::Key;
use crate::resolver::{ClientInfo, Resolver};

/// How many refreshes may be waiting at once.
///
/// Deliberately small.  A refresh that has queued for a long time is fetching
/// an answer to a question nobody is still asking, and the queue existing at
/// all is only worth it while it stays short.
const QUEUE: usize = 1024;

/// How many refreshes may be in flight at once.
const CONCURRENT: usize = 32;

/// One entry to fetch again.
pub struct Job {
    /// The request to repeat.
    pub(crate) req: Message,
    /// The question's name, lowercased and without the trailing dot.
    pub(crate) host: String,
    /// The client the entry was stored for, which decides the subnet sent.
    pub(crate) client: ClientInfo,
    /// The entry being refreshed.
    pub(crate) key: Key,
}

/// The end a resolver hands its refresh jobs to.
pub type Sender = mpsc::Sender<Job>;

/// The end [`run`] drains.
pub type Receiver = mpsc::Receiver<Job>;

/// Builds the queue joining a resolver to its refresh worker.
pub fn channel() -> (Sender, Receiver) {
    mpsc::channel(QUEUE)
}

/// Runs refreshes until the queue is closed.
///
/// Spawned by the binary rather than by the resolver, because it needs the
/// `Arc` the binary already holds.
pub async fn run(resolver: Arc<Resolver>, mut rx: Receiver) {
    let limit = Arc::new(Semaphore::new(CONCURRENT));

    while let Some(job) = rx.recv().await {
        let Ok(permit) = limit.clone().acquire_owned().await else {
            // The semaphore is only closed when this is shutting down.
            return;
        };
        let r = resolver.clone();

        tokio::spawn(async move {
            let _permit = permit;

            // The global settings, not a client's: everything `forward`
            // consults here -- the subnet, the DNSSEC bit, the TTL bounds,
            // DNS64 -- is global.
            //
            // The upstreams are the exception, and they come from the key
            // rather than from the settings: the entry being refreshed was
            // stored against a particular set of resolvers, and refreshing it
            // from the global ones would overwrite it with an answer those
            // resolvers never gave.
            let settings = r.settings();
            let upstreams = job.key.upstreams.clone();
            r.forward(
                &job.req,
                &job.host,
                &settings,
                &job.client,
                Some(job.key.clone()),
                upstreams.as_ref(),
            )
            .await;

            // Whether or not it worked.  A failed refresh that kept its claim
            // would stop the entry from ever being refreshed again.
            r.cache.end_refresh(&job.key);
        });
    }
}
