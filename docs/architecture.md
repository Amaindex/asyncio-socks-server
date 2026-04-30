# Architecture

[README](../README.md) · [Addon model](addon-model.md) · [Public API](public-api.md) · [简体中文](architecture.zh-CN.md)

The core handles protocol parsing, relay, and hook dispatch. Addons handle policy and routing. Chain proxying, traffic counting, and access control are addon behavior.

## System Overview

```text
SOCKS5 Client          Server                          Remote
─────────────          ──────                          ──────

auth negotiation ────▶ parse_method_selection
                       parse_username_password
                       dispatch_auth (competitive)
                       │
CONNECT/UDP request ─▶ parse_request → create Flow
                       dispatch_connect / dispatch_udp_associate
                       ├─ no addon ─────────────────▶ direct connect
                       └─ ChainRouter ──────────────▶ client.connect(next_hop)
                       │
bidirectional relay ─▶ dispatch_data (pipeline) per chunk
                       flow.bytes_up/down per chunk or datagram
                       │
connection close ────▶ dispatch_flow_close (observational)
                       log stats from Flow
```

Chain proxying uses the same path. `dispatch_connect` returns a `Connection` to the next-hop SOCKS5 server instead of a direct TCP connection.

## Request Lifecycle

Every request has three stages:

| Stage | Entry | Core Action | Output |
|-------|-------|-------------|--------|
| Handshake | SOCKS5 client | Parse method selection + auth + request, create Flow | Flow with src/dst/protocol |
| Relay | Flow + addon decision | Bidirectional data pump with addon pipeline, Flow tracks bytes | Data forwarded, bytes counted |
| Teardown | Connection close | Log stats, dispatch `on_flow_close` | Addons get final stats |

TCP and UDP share the hook lifecycle. TCP uses paired `_copy()` coroutines. UDP uses a shared socket and routing table.

### TCP Relay Data Flow

```text
Client          Server                                  Target
──────          ──────                                  ──────

  │               │                                       │
  │── handshake ─▶│                                       │
  │               │  parse + auth + Flow                  │
  │               │                                       │
  │               │  dispatch_connect(flow)               │
  │               │  ├─ no addon ──▶ direct               │
  │               │  └─ ChainRouter ──▶ next hop          │
  │               │                                       │
  │── data ──────▶│── _copy(client→target)───────────────▶│
  │               │  dispatch_data(up, data, flow)        │
  │               │  flow.bytes_up += len(data)           │
  │               │                                       │
  │◀─ response ───│◀── _copy(target→client)               │
  │               │  dispatch_data(down, data)            │
  │               │  flow.bytes_down += len(data)         │
  │               │                                       │
  │── close ─────▶│── dispatch_flow_close(flow)──────────▶│
  │               │  log: ↑1.2KB ↓45.6KB                  │
  │               │                                       │
```

### UDP Relay Architecture

Some SOCKS5 implementations create one outbound UDP socket per client source port. Long-running servers can accumulate sockets.

This implementation uses one outbound socket and a bidirectional routing table:

```text
Outbound:
Client datagram ──▶ shared_socket.sendto(payload, target)
                      route_map[("93.184.216.34", 443)] = ("10.0.0.1", 54321)
                      flow.bytes_up += len(payload)

Inbound:
shared_socket.recvfrom() ──▶ lookup route_map ──▶ sendto(client, response)
                               flow.bytes_down += len(response)
```

Routes expire by TTL.

## UDP-over-TCP Chaining

UDP chain proxying does not use UDP between proxy nodes. Inter-node transport is TCP.

Entry nodes encapsulate UDP datagrams as TCP frames. Exit nodes decapsulate them back to UDP.

```text
Request:
Client UDP ──▶ UdpOverTcpEntry ──▶ middle nodes ──▶ Exit server ──▶ raw UDP ──▶ Target
                encapsulate          (TCP bytes)      decapsulate
                UDP → TCP                             TCP → UDP

Response:
Target ──▶ raw UDP ──▶ Exit server ──▶ middle nodes ──▶ UdpOverTcpEntry ──▶ Client UDP
                         encapsulate       (TCP bytes)      decapsulate
                         UDP → TCP                         TCP → UDP
```

Frame format (4-byte length prefix + SOCKS5 encoded address + payload):

```text
┌──────────┬──────────────────┬─────────┐
│ Length   │ Encoded Address  │ Payload │
│ 4 bytes  │ variable         │ N bytes │
└──────────┴──────────────────┴─────────┘
```

Properties:

- Middle nodes only forward TCP CONNECT traffic.
- `on_data` sees TCP bytes in both TCP and UDP-over-TCP cases.
- UDP semantics remain at the client-entry and exit-target edges.
- No per-hop UDP ASSOCIATE state is needed.

## Flow Context

`Flow` is the per-connection context passed through hooks.

```python
@dataclass
class Flow:
    id: int               # Monotonically increasing
    src: Address          # Client address
    dst: Address          # Target address
    protocol: Literal["tcp", "udp"]
    started_at: float     # time.monotonic()
    bytes_up: int = 0     # Client → target (TCP: post-addon; UDP: raw payload)
    bytes_down: int = 0   # Target → client
```

Without `Flow`, data hooks have no connection identity. Byte counters also become easy to duplicate across relay and addon code.

With `Flow`:

- Bytes are counted once in relay code.
- Hooks receive the same object for the connection lifecycle.
- `on_flow_close` receives the final counters.

Lifecycle:

```
on_connect / on_udp_associate(flow)     → addon registers connection, gets identity
on_data(direction, data, flow)          → addon knows whose data, can read running stats
  └─ relay updates flow.bytes_* directly
on_flow_close(flow)                     → addon gets final snapshot, can log/aggregate
```

## IPv6 Dual-Stack

Server listens on `::` with one `AF_INET6` socket (`IPV6_V6ONLY=0`), handling IPv4 and IPv6.

Client connection uses Happy Eyeballs-style fallback. It resolves IPv6 and IPv4 candidates, starts one candidate, then staggers subsequent candidates every 250ms.

UDP relay normalizes IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) in routing tables.

## Async Hooks

The data path uses `StreamReader` and `StreamWriter`. It is already async:
`await reader.read()` -> process -> `await writer.drain()`.

Async hooks allow:

- `ChainRouter.on_connect` to `await client.connect()` directly.
- `on_auth` to use async I/O.
- No sync-to-async bridge in the relay path.

The extra `await` is outside the main cost path.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| SOCKS version | SOCKS5 | Covers CONNECT and UDP ASSOCIATE |
| Runtime deps | Zero | Stdlib only |
| Addon model | Class-based, async | One class with multiple hooks gives natural state management; async matches the data path |
| Config method | Python scripts | Addons are regular Python objects |
| Hot reload | Not in kernel | Use an external watcher if needed |
| Resource limits | Not in kernel | Use system-level limits |

## Topic Docs

| Doc | Content |
|-----|---------|
| [`addon-model.md`](addon-model.md) | Hook API, execution models, built-in addons, chain proxying |
| [`public-api.md`](public-api.md) | 1.x compatibility surface, root exports, hook contracts |
