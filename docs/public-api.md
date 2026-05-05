# Public API

[README](../README.md) · [Architecture](architecture.md) · [Addon model](addon-model.md) · [简体中文](public-api.zh-CN.md)

This document defines the asyncio-socks-server 1.x compatibility surface.
Stable imports live at the package root. Submodules remain importable.

## Compatibility Policy

The package root is stable:

```python
from asyncio_socks_server import Server, Addon, Address, connect
```

Within the 1.x series:

- Root exports keep their names and broad behavior.
- Addon hook signatures remain compatible.
- `Flow` byte counters and address fields keep their meaning.
- CLI flags remain backward-compatible.

Modules under `asyncio_socks_server.core`,
`asyncio_socks_server.server`, `asyncio_socks_server.client`, and
`asyncio_socks_server.addons` are importable. Root exports are the compatibility contract.

## Root Exports

| Name | Category | Purpose |
|------|----------|---------|
| `Server` | Server | SOCKS5 server entry point |
| `connect` | Client | Open a TCP connection through a SOCKS5 proxy |
| `Addon` | Addon base | Base class for optional async hooks |
| `ChainRouter` | Addon | Route TCP CONNECT through a downstream SOCKS5 proxy |
| `UdpOverTcpEntry` | Addon | Tunnel UDP ASSOCIATE traffic through a TCP exit service |
| `UdpOverTcpExitServer` | Server | Exit service for UDP-over-TCP chaining |
| `FlowStats` | Addon | In-memory flow statistics collector |
| `StatsServer` | Addon | Compatibility HTTP wrapper around FlowStats |
| `TrafficCounter` | Addon | Aggregate closed-flow byte counters |
| `FileAuth` | Addon | Username/password auth from JSON |
| `IPFilter` | Addon | Source IP allow/block rules |
| `Logger` | Addon | Connection and data logging |
| `Address` | Type | Host/port pair |
| `Flow` | Type | Per-connection context and byte counters |
| `Direction` | Type | Data direction enum |
| `Connection` | Type | Reader/writer pair returned by connection hooks |
| `UdpRelayBase` | Type | Base interface for custom UDP relay addons |

## Server Contract

```python
server = Server(
    host="::",
    port=1080,
    addons=[],
    auth=None,
    log_level="INFO",
    shutdown_timeout=30.0,
)
server.run()
```

`Server.run()` owns the event loop and installs SIGINT/SIGTERM handlers. Internal coroutines are not part of the stable public API.

Shutdown stops accepting new clients, waits for active client tasks, then calls
addon `on_stop`. If `shutdown_timeout` is `None`, shutdown waits indefinitely
for active clients. Otherwise unfinished tasks are cancelled after the timeout.

## Addon Contract

All addon hooks are optional async methods. The hook models are:

| Model | Hooks | Return contract |
|-------|-------|-----------------|
| Competitive | `on_auth`, `on_connect`, `on_udp_associate` | `None` abstains; non-`None` wins |
| Pipeline | `on_data` | `bytes` continues; `None` drops the chunk |
| Observational | `on_start`, `on_stop`, `on_flow_close`, `on_error` | Return value ignored |

Exceptions in competitive hooks reject the current SOCKS operation. Exceptions in `on_flow_close` and `on_error` are suppressed.

## Flow Semantics

`Flow` is shared across hooks for one TCP CONNECT or UDP ASSOCIATE lifecycle.

```python
Flow(
    id=1,
    src=Address("127.0.0.1", 54321),
    dst=Address("example.com", 443),
    protocol="tcp",
    started_at=...,
    bytes_up=0,
    bytes_down=0,
)
```

Byte counters are maintained by the relay path, not by addons:

- `bytes_up`: client to target, after TCP data pipeline processing
- `bytes_down`: target to client
- UDP counters count SOCKS5 UDP payload bytes, not UDP header bytes

Addons should treat `Flow` as readable context. Mutating byte counters or
addresses is unsupported.

## Stats API

`FlowStats` is the stats infrastructure. It has no network side effects and
exposes plain Python methods:

| Method | Meaning |
|--------|---------|
| `snapshot()` | Aggregate counters and active flow snapshots |
| `flows()` | Active flows and recent closed flow snapshots |
| `active_flows()` | Active flow snapshots |
| `recent_closed_flows()` | Retained closed flow snapshots |
| `errors()` | Error counters observed through `on_error` |

Use `FlowStats` to build an application-specific HTTP API, metrics exporter, or
logging pipeline. Put it early in the addon list so it can observe flow starts
before another competitive addon wins.

`StatsServer` remains available as a small compatibility wrapper. It exposes a
stdlib HTTP server backed by `FlowStats`:

| Endpoint | Meaning |
|----------|---------|
| `GET /health` | Liveness response |
| `GET /stats` | `FlowStats.snapshot()` |
| `GET /flows` | `FlowStats.flows()` |

## CLI Contract

```shell
asyncio_socks_server --host :: --port 1080 --auth user:pass --log-level INFO
```

CLI mode starts a direct SOCKS5 server with optional single-user auth. Addons and advanced routing are configured from Python.
