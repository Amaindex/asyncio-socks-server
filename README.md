# asyncio-socks-server

[![Tests](https://github.com/Amaindex/asyncio-socks-server/actions/workflows/tests.yml/badge.svg)](https://github.com/Amaindex/asyncio-socks-server/actions/workflows/tests.yml)
[![Docker](https://github.com/Amaindex/asyncio-socks-server/actions/workflows/docker.yml/badge.svg)](https://github.com/Amaindex/asyncio-socks-server/actions/workflows/docker.yml)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

SOCKS5 server with async Python addon hooks.

[Docs](#docs) · [Architecture](docs/architecture.md) · [Addon recipes](docs/addon-recipes.md) · [Addon model](docs/addon-model.md) · [Public API](docs/public-api.md) · [简体中文](README.zh-CN.md)

## Install

```shell
pip install asyncio-socks-server
```

Docker images are versioned:

```shell
docker run --rm -p 1080:1080 amaindex/asyncio-socks-server:1.3.0
```

## Run

```shell
asyncio_socks_server
asyncio_socks_server --host 127.0.0.1 --port 9050
asyncio_socks_server --auth user:pass
```

CLI flags:

| Flag | Default | Meaning |
|------|---------|---------|
| `--host` | `::` | Bind address |
| `--port` | `1080` | Bind port |
| `--auth` | None | `username:password` |
| `--log-level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

## Use from Python

```python
from asyncio_socks_server import Server

Server(host="::", port=1080).run()
```

Addons are optional. Add only the behavior you need:

| Goal | Addons |
|------|--------|
| Runtime counters and active flows | `FlowStats` + `StatsAPI` |
| Closed-flow usage audit | `FlowAudit` + `StatsAPI` |
| TCP chain proxying | `ChainRouter` |
| UDP chain proxying | `UdpOverTcpEntry` + `UdpOverTcpExitServer` |
| Auth, source policy, logs | `FileAuth`, `IPFilter`, `Logger` |

Runtime counters and audit API:

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

Addon order is execution order. Built-in addons are opt-in; adding `StatsAPI`
is what starts an HTTP listener.

`FlowStats` has no network side effects. Use its `snapshot()` and `flows()`
methods directly, or pair it with `StatsAPI` for a small local HTTP API.
`FlowAudit` records closed-flow usage in memory and can be exposed through
`StatsAPI` for Kafra-like usage audit summaries.

For task-oriented examples, see [Addon recipes](docs/addon-recipes.md).

## Model

The core handles SOCKS5 parsing, relay, and hook dispatch. Addons handle policy.

Hook dispatch has three models:

| Model | Hooks | Contract |
|-------|-------|----------|
| Competitive | `on_auth`, `on_connect`, `on_udp_associate` | First non-`None` result wins |
| Pipeline | `on_data` | Output from one addon becomes input to the next |
| Observational | `on_start`, `on_stop`, `on_flow_close`, `on_error` | All applicable addons run |

Built-ins:

- `ChainRouter` for TCP chain proxying
- `UdpOverTcpEntry` and `UdpOverTcpExitServer` for UDP chain proxying
- `FlowStats` for in-memory flow statistics
- `FlowAudit` for closed-flow usage audit summaries
- `StatsAPI` as an opt-in HTTP API around `FlowStats`
- `StatsServer` as a backward-compatible name for `StatsAPI`
- `TrafficCounter`, `FileAuth`, `IPFilter`, `Logger`

## Architecture sketch

```text
Client ── SOCKS5 ──▶ Server ──▶ Target
                     │
                     ├─ auth / route hooks
                     ├─ data pipeline hooks
                     └─ flow close hooks

ChainRouter:
Client ──▶ A ──▶ B ──▶ C ──▶ Target
```

## Chain proxying

Each node only knows its next hop:

```python
# A ─▶ B ─▶ C ─▶ target
Server(addons=[ChainRouter("B:1080")])  # A
Server(addons=[ChainRouter("C:1080")])  # B
Server()                                # C
```

UDP chain proxying uses TCP between proxy nodes:

```python
from asyncio_socks_server import Server, UdpOverTcpEntry, UdpOverTcpExitServer

entry = Server(addons=[UdpOverTcpEntry("exit-host:9020")])
exit_server = UdpOverTcpExitServer(host="::", port=9020)
```

## Client

```python
from asyncio_socks_server import Address, connect

conn = await connect(
    proxy_addr=Address("127.0.0.1", 1080),
    target_addr=Address("93.184.216.34", 443),
)
conn.writer.write(b"hello")
await conn.writer.drain()
data = await conn.reader.read(4096)
```

## API surface

Stable imports live at the package root:

```python
from asyncio_socks_server import (
    Addon,
    Address,
    ChainRouter,
    Flow,
    FlowAudit,
    FlowStats,
    Server,
    StatsAPI,
    StatsServer,
    UdpOverTcpEntry,
    UdpOverTcpExitServer,
    connect,
)
```

Root exports are the 1.x compatibility contract. Submodules remain importable.

## Docs

| Document | Scope |
|----------|-------|
| [Architecture](docs/architecture.md) | Core flow, relay design, UDP-over-TCP, Flow context |
| [Addon recipes](docs/addon-recipes.md) | Goal-oriented addon combinations |
| [Addon model](docs/addon-model.md) | Hook contracts, dispatch semantics, built-in addons |
| [Public API](docs/public-api.md) | 1.x compatibility surface |

## Development

```shell
git clone https://github.com/Amaindex/asyncio-socks-server.git
cd asyncio-socks-server
uv sync
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest
uv build
```

## Release

GitHub Actions tests Python 3.12 and 3.13, builds the Python package, and builds Docker images.

Create a GitHub Release from a tag such as `v1.3.0`. The release workflow publishes the Python package. The Docker workflow publishes semver image tags.

## License

MIT
