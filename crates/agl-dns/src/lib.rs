//! The DNS server: wire handling, caching, upstream resolution.

pub mod addr;
pub mod cache;
pub mod client;
pub mod doq;
pub mod msg;
pub mod pool;
pub mod ratelimit;
pub mod resolver;
pub mod rewrite;
pub mod server;
pub mod tls;
