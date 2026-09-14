//! The DNS server: wire handling, caching, upstream resolution.

pub mod addr;
pub mod cache;
pub mod client;
pub mod clients;
pub mod ddr;
pub mod dns64;
pub mod doq;
pub mod edns;
pub mod hashprefix;
pub mod msg;
pub mod pending;
pub mod pool;
pub mod ratelimit;
pub mod resolver;
pub mod rewrite;
pub mod server;
pub mod tls;
