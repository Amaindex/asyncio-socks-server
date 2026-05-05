# Addon Model

[README](../README.md) · [Architecture](architecture.md) · [Addon recipes](addon-recipes.md) · [Public API](public-api.md) · [简体中文](addon-model.zh-CN.md)

Addons are Python classes with optional async methods. The server calls them at defined points in the SOCKS5 flow.

This document explains dispatch semantics. If you already know what you want to
build, start with [Addon recipes](addon-recipes.md).

## Execution Models

A single dispatch rule is not enough:

- Authentication and routing need first-match-wins.
- Data processing needs output-to-input chaining.
- Lifecycle events need all applicable addons to run.

The manager uses three models:

| Model | Semantics | When to use | Hooks |
|-------|-----------|-------------|-------|
| Competitive | First non-`None` wins, rest skipped | Mutually exclusive decisions | `on_auth`, `on_connect`, `on_udp_associate` |
| Pipeline | Sequential, output→input chaining | Data transformation chains | `on_data` |
| Observational | All called where applicable; flow-close/error exceptions are caught | Logging, monitoring, cleanup | `on_start`, `on_stop`, `on_flow_close`, `on_error` |

## Hook API

All methods are optional — unimplemented hooks have no effect.

```python
class Addon:
    # Lifecycle (observational)
    async def on_start(self) -> None:
        """Server started."""

    async def on_stop(self) -> None:
        """Server stopped. Flush buffers, write stats."""

    # Authentication (competitive)
    async def on_auth(self, username: str, password: str) -> bool | None:
        """True = allow, False = deny, None = abstain."""

    # Connection interception (competitive)
    async def on_connect(self, flow: Flow) -> Connection | None:
        """Return Connection to intercept, None to abstain, raise to deny."""

    async def on_udp_associate(self, flow: Flow) -> UdpRelayBase | None:
        """Return UdpRelayBase to intercept, None to abstain."""

    # Data transformation (pipeline)
    async def on_data(self, direction: Direction, data: bytes, flow: Flow) -> bytes | None:
        """Return bytes to write, None to drop this chunk, raise to abort."""

    # Teardown (observational)
    async def on_flow_close(self, flow: Flow) -> None:
        """Connection closed. Final stats available in flow."""

    async def on_error(self, error: Exception) -> None:
        """Error occurred. For logging/monitoring only."""
```

### Return Value Contract

Competitive and pipeline hooks use different `None` semantics:

| Hook kind | Return | Meaning |
|-----------|--------|---------|
| Competitive | `None` | Abstain — let the next addon or default behavior decide |
| Competitive | non-`None` | Win — use the returned value as the result |
| Pipeline `on_data` | `bytes` | Write these bytes and pass them to the next addon |
| Pipeline `on_data` | `None` | Drop this chunk and stop the pipeline |
| Any | raise exception | Deny/reject/abort the current operation |

Addons can share a list without coordinating if they use different hooks.

## Competitive Dispatch

First non-`None` wins. Remaining addons are skipped.

```
on_auth("admin", "secret"):
  FileAuth  → True        ← wins, stops here
  IPFilter  → (not called)
  Logger    → (not called)
```

```
on_auth("unknown", "pass"):
  FileAuth  → False       ← explicit deny
  IPFilter  → (not called)
```

```
on_auth("guest", "pass"):
  FileAuth  → None        ← abstain (user not in file)
  IPFilter  → None        ← abstain (IP not relevant for auth)
  → kernel uses default: no auth required → allow
```

Raising an exception rejects the operation. The client receives a SOCKS5 error reply.

## Pipeline Dispatch

Sequential, output-chained. Returning `None` breaks the pipeline (data is dropped, subsequent addons are not called).

```
on_data(up, b"hello", flow):
  UpperAddon    → b"HELLO"     ← transform
  TrafficLogger → b"HELLO"     ← pass through by returning input unchanged
  AppendNull    → b"HELLO\x00" ← transform
  → write b"HELLO\x00" to target
```

```
on_data(down, response, flow):
  DropAddon     → None         ← drops data, pipeline breaks
  UpperAddon    → (not called)
  → nothing written to client
```

Pipeline order is addon list order.

## Observational Dispatch

All addons called. Exceptions caught and not propagated.

```
on_flow_close(flow):
  TrafficCounter  → aggregates bytes (may raise on write error)
  Logger          → logs connection stats
  → all called, any exceptions logged but suppressed
```

This keeps teardown and monitoring isolated from individual addon failures.

## Built-in Addons

| Addon | Primary role | Starts network listeners |
|-------|--------------|--------------------------|
| `ChainRouter` | TCP next-hop routing | No |
| `UdpOverTcpEntry` | UDP-over-TCP entry routing | No |
| `UdpOverTcpExitServer` | UDP-over-TCP exit service | Yes, as a separate server |
| `FlowStats` | Runtime counters and active flow snapshots | No |
| `FlowAudit` | Closed-flow usage audit window | No |
| `StatsAPI` | Optional HTTP presentation for stats and audit | Yes, only when added |
| `StatsServer` | Backward-compatible name for `StatsAPI` | Yes, only when added |
| `TrafficCounter` | Minimal closed-flow byte totals | No |
| `FileAuth` | Username/password auth from JSON | No |
| `IPFilter` | Source IP allow/block policy | No |
| `Logger` | Connection and data logging | No |

All built-in addons are opt-in. CLI mode starts a direct SOCKS5 server; addon
composition is configured from Python.

### ChainRouter — TCP Chain Proxying

```python
class ChainRouter(Addon):
    def __init__(self, next_hop: str): ...

    async def on_connect(self, flow):
        conn = await client.connect(self.next_hop, flow.dst)
        return conn
```

`ChainRouter` returns a `Connection` to the next-hop SOCKS5 server. The server relays through the returned connection.

Each node only knows its next hop:

```
User → [A: ChainRouter("B:1080")] → [B: ChainRouter("C:1080")] → [C: direct] → Target
```

### UdpOverTcpEntry — UDP Chain Proxying

UDP chain proxying reuses the same competitive hook (`on_udp_associate`), but returns a bridge that encapsulates UDP datagrams as TCP frames instead of a `Connection`.

```
Client UDP → Entry addon (encapsulate) → TCP chain → Exit server (decapsulate) → UDP → Target
```

Middle nodes see TCP bytes.

### TrafficCounter — Stats Aggregation

```python
class TrafficCounter(Addon):
    async def on_connect(self, flow):
        self.connections += 1

    async def on_flow_close(self, flow):
        self.bytes_up += flow.bytes_up
        self.bytes_down += flow.bytes_down
```

`TrafficCounter` aggregates in `on_flow_close`. `Flow` already has cumulative byte counters, and UDP does not pass through `on_data`.

### FlowStats — Flow Statistics Infrastructure

```python
from asyncio_socks_server import FlowStats, Server

stats = FlowStats()
server = Server(addons=[stats])
```

`FlowStats` has no network side effects. It records flow lifecycle data through
addon hooks and exposes Python methods for application-specific presentation:

| Method | Content |
|--------|---------|
| `snapshot()` | Aggregate counters, rates, errors, and active flows |
| `flows()` | Active flows and recent closed flow snapshots |
| `errors()` | Error counters and recent errors |

Use `FlowStats` as infrastructure for your own HTTP API, Prometheus exporter,
file audit stream, or control-plane integration.

### FlowAudit — Usage Audit Infrastructure

```python
from asyncio_socks_server import FlowAudit, Server

audit = FlowAudit()
server = Server(addons=[audit])
```

`FlowAudit` has no network side effects. It records closed flows in memory and
aggregates usage by source host and target host:

| Method | Content |
|--------|---------|
| `snapshot()` | Kafra-like audit summary with period, records, totals, devices, and traffic |
| `reset()` | Clear the in-memory audit window |

The audit window resets when the process restarts. Use an application-specific
sink if you need durable long-term audit storage.

### StatsAPI — Opt-in HTTP API

```python
from asyncio_socks_server import FlowAudit, FlowStats, Server, StatsAPI

audit = FlowAudit()
stats = FlowStats()
api = StatsAPI(stats=stats, audit=audit, host="127.0.0.1", port=9900)
server = Server(addons=[audit, stats, api])
```

`StatsAPI` is a simple stdlib HTTP wrapper around `FlowStats` and optional
`FlowAudit`. It starts a listener only when explicitly added to the addon list:

| Endpoint | Content |
|----------|---------|
| `GET /health` | Liveness response |
| `GET /stats` | `FlowStats.snapshot()` |
| `GET /flows` | `FlowStats.flows()` |
| `GET /errors` | `FlowStats.errors()` |
| `GET /audit?top=25&device=` | `FlowAudit.snapshot()` |
| `POST /audit/refresh?top=25&device=` | Current `FlowAudit.snapshot()` for Kafra-like refresh flows |

When constructed without a `FlowStats` instance, `StatsAPI` creates and owns one:

```python
server = Server(addons=[StatsAPI(host="127.0.0.1", port=9900)])
```

`StatsServer` remains as a backward-compatible name for `StatsAPI`.

Put `FlowStats` or owning `StatsAPI` early in the addon list. It observes flow starts through competitive hooks. An earlier winning addon can prevent it from seeing a start event. `on_flow_close` still receives the final Flow snapshot.

### FileAuth — Multi-user Auth

Reads a JSON file mapping usernames to passwords. Caches after first load.
`FileAuth` is consulted only when the server negotiates username/password auth,
so configure `Server(auth=...)` when using it.

### IPFilter — Source IP Access Control

```python
IPFilter(allowed=["10.0.0.0/24"])
# or
IPFilter(blocked=["10.0.0.5"])
```

Reads `flow.src.host` in `on_connect`. Denied connections receive SOCKS5 `CONNECTION_NOT_ALLOWED` reply.

### Logger — Connection Logging

Logs connection details and flow stats. It does not change proxy behavior.

## Custom Addon Patterns

### Selective Content Inspection

```python
class ContentFilter(Addon):
    async def on_connect(self, flow):
        if flow.dst.port != 80:
            return  # only inspect HTTP

    async def on_data(self, direction, data, flow):
        if direction == Direction.UP and b"forbidden-keyword" in data:
            raise Exception("blocked content")
        return data  # pass through
```

### Per-connection Rate Limiting

```python
class RateLimiter(Addon):
    def __init__(self, max_bytes=1024 * 1024):  # 1MB per connection
        self.max_bytes = max_bytes

    async def on_data(self, direction, data, flow):
        if flow.bytes_up + flow.bytes_down > self.max_bytes:
            raise Exception("rate limit exceeded")
        return data
```

### Dynamic Next-hop Routing

```python
class DynamicRouter(Addon):
    def __init__(self):
        self.routes = {}  # domain pattern → next hop

    async def on_connect(self, flow):
        for pattern, hop in self.routes.items():
            if pattern in flow.dst.host:
                return await client.connect(hop, flow.dst)
```

## Dispatch Internals

`AddonManager` skips unimplemented hooks by checking `type(addon).method is not Addon.method`. This avoids creating coroutines for base-class methods that do nothing — significant when processing thousands of chunks through `on_data`.

Addon list order is execution order. There is no priority system or dependency resolution — if order matters, arrange the list accordingly.

For hook signature and Flow compatibility, see
[`public-api.md`](public-api.md).
