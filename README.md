# adguardlite

A Rust reimplementation of the [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome)
backend, built as a **drop-in replacement** for the Go binary of release
`v0.107.79`: same config file, same on-disk data, same HTTP API, same Docker
contract — with a smaller binary, lower memory use and higher throughput.

See [PLAN.md](PLAN.md) for the compatibility contract and the implementation plan.

## Status

| Area | State |
|---|---|
| Config (`AdGuardHome.yaml`, schema 34) | byte-identical round-trip vs Go |
| Filtering engine | 4189/4189 verdicts match Go on the real 179k-rule list |
| DNS server | in progress |
| Query log / statistics | in progress |
| HTTP API + web UI | in progress |
| Docker image | in progress |

## Build

```bash
cargo build --profile dist
```

## Test

```bash
cargo test --workspace
```
