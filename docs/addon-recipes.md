# Addon Recipes

[README](../README.md) · [Architecture](architecture.md) · [Addon model](addon-model.md) · [Public API](public-api.md) · [简体中文](addon-recipes.zh-CN.md)

Use this page when choosing which addons to combine. Addons are opt-in and run
in the order listed in `Server(addons=[...])`.

## Direct SOCKS5 Server

No addons are required for a plain SOCKS5 server:

```python
from asyncio_socks_server import Server

Server(host="::", port=1080).run()
```

CLI mode is equivalent to this direct shape plus optional single-user auth.

## Runtime Counters

Use `FlowStats` for counters and `StatsAPI` only if you want an HTTP endpoint:

```python
from asyncio_socks_server import FlowStats, Server, StatsAPI

stats = FlowStats()
server = Server(
    addons=[
        stats,
        StatsAPI(stats=stats, host="127.0.0.1", port=9900),
    ],
)
server.run()
```

Endpoints:

| Endpoint | Use |
|----------|-----|
| `GET /health` | Liveness |
| `GET /stats` | Totals, rates, errors, active flows |
| `GET /flows` | Active and recent closed flows |
| `GET /errors` | Error counters |

`FlowStats` should appear before competitive routing addons if you need flow
start visibility.

## Usage Audit

Use `FlowAudit` for closed-flow usage grouped by source host and target host:

```python
from asyncio_socks_server import FlowAudit, Server, StatsAPI

audit = FlowAudit()
server = Server(
    addons=[
        audit,
        StatsAPI(audit=audit, host="127.0.0.1", port=9900),
    ],
)
server.run()
```

Endpoints:

| Endpoint | Use |
|----------|-----|
| `GET /audit?top=25&device=` | Current in-memory audit window |
| `POST /audit/refresh?top=25&device=` | Same snapshot, useful for control-plane refresh flows |

The audit window is in-memory and resets when the process restarts. Add a
custom sink if you need durable records.

## Runtime Counters Plus Audit

This is the normal observability stack:

```python
from asyncio_socks_server import FlowAudit, FlowStats, Server, StatsAPI

audit = FlowAudit()
stats = FlowStats()
server = Server(
    addons=[
        audit,
        stats,
        StatsAPI(stats=stats, audit=audit, host="127.0.0.1", port=9900),
    ],
)
server.run()
```

`StatsAPI` is a presentation layer. It does not collect stats or audit data by
itself unless it owns an internal `FlowStats`; pass explicit `FlowStats` and
`FlowAudit` instances when other code also needs direct Python access.

## TCP Chain Proxy

Use `ChainRouter` when this server should forward TCP CONNECT traffic through a
downstream SOCKS5 server:

```python
from asyncio_socks_server import ChainRouter, Server

Server(addons=[ChainRouter("10.0.0.5:1080")]).run()
```

Each node only knows its next hop:

```python
Server(addons=[ChainRouter("B:1080")])  # A
Server(addons=[ChainRouter("C:1080")])  # B
Server()                                # C
```

## UDP Over TCP Chain

Use `UdpOverTcpEntry` at the SOCKS-facing node and
`UdpOverTcpExitServer` at the exit:

```python
from asyncio_socks_server import Server, UdpOverTcpEntry, UdpOverTcpExitServer

entry = Server(addons=[UdpOverTcpEntry("exit-host:9020")])
exit_server = UdpOverTcpExitServer(host="::", port=9020)
```

Middle chain nodes see TCP bytes.

## Auth, Source Policy, And Logs

Use these independently or together:

```python
from asyncio_socks_server import FileAuth, IPFilter, Logger, Server

server = Server(
    auth=("_fallback_disabled_", "_fallback_disabled_"),
    addons=[
        FileAuth("/etc/asyncio-socks-users.json"),
        IPFilter(allowed=["10.0.0.0/24"]),
        Logger(),
    ],
)
server.run()
```

`FileAuth` is consulted only when server auth is enabled; the `auth` tuple
forces username/password negotiation and remains a valid fallback credential, so
set it deliberately. `IPFilter` accepts either `allowed` or `blocked`, not both.
`Logger` observes traffic without changing routing.

## Compatibility Names

`StatsServer` is a backward-compatible name for `StatsAPI`. New code should use
`StatsAPI` because it describes the role more precisely.
