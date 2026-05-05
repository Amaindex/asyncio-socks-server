# 架构与数据流

[README](../README.zh-CN.md) · [Addon recipes](addon-recipes.zh-CN.md) · [Addon 模型](addon-model.zh-CN.md) · [公共 API](public-api.zh-CN.md) · [English](architecture.md)

核心处理协议解析、中继和 hook 调度。Addon 处理策略和路由。链式代理、流量统计、访问控制都是 addon 行为。

## 系统总览

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

链式代理使用同一条路径。区别是 `dispatch_connect` 返回到下一跳 SOCKS5 server 的 `Connection`，而不是直连 TCP 连接。

## 请求生命周期

每个请求经过三个阶段：

| 阶段 | 入口 | 核心动作 | 输出 |
|------|------|----------|------|
| 握手 | SOCKS5 客户端 | 解析方法选择 + 认证 + 请求，创建 Flow | 含 src/dst/protocol 的 Flow |
| 中继 | Flow + addon 决策 | 双向数据泵 + addon 管道，Flow 追踪字节 | 数据转发，字节计数 |
| 拆解 | 连接关闭 | 记录统计，派发 `on_flow_close` | Addon 获得最终统计 |

TCP 和 UDP 共享 hook 生命周期。TCP 使用配对的 `_copy()` 协程。UDP 使用共享 socket 和路由表。

### TCP 中继数据流

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

### UDP Relay 架构

一些 SOCKS5 实现为每个客户端源端口创建独立的出向 UDP socket。长时间运行时容易积累 socket。

本实现使用一个出向 socket 和双向路由表：

```text
Outbound:
Client datagram ──▶ shared_socket.sendto(payload, target)
                      route_map[("93.184.216.34", 443)] = ("10.0.0.1", 54321)
                      flow.bytes_up += len(payload)

Inbound:
shared_socket.recvfrom() ──▶ lookup route_map ──▶ sendto(client, response)
                               flow.bytes_down += len(response)
```

路由通过 TTL 过期淘汰。

## UDP-over-TCP 链式

UDP 链式代理不在代理节点之间使用 UDP。节点间传输走 TCP。

入口节点把 UDP datagram 封装为 TCP frame。出口节点拆封后发出 UDP。

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

性质：

- 中间节点只转发 TCP CONNECT 流量。
- `on_data` 在 TCP 和 UDP-over-TCP 场景下都只看到 TCP bytes。
- UDP 语义只存在于 client-entry 和 exit-target 两段。
- 不需要逐跳维护 UDP ASSOCIATE 状态。

## Flow Context

`Flow` 是贯穿 hooks 的每连接上下文。

```python
@dataclass
class Flow:
    id: int               # 全局递增 ID
    src: Address          # 客户端地址
    dst: Address          # 目标地址
    protocol: Literal["tcp", "udp"]
    started_at: float     # time.monotonic()
    bytes_up: int = 0     # 客户端→目标（TCP: post-addon; UDP: 原始载荷）
    bytes_down: int = 0   # 目标→客户端
```

没有 `Flow` 时，data hook 没有连接身份。字节计数也容易在 relay 和 addon 中重复。

有了 `Flow`：

- 字节只在 relay 中计数一次。
- hook 在连接生命周期内收到同一个对象。
- `on_flow_close` 收到最终计数。

生命周期：

```text
on_connect / on_udp_associate(flow)     → addon registers connection, gets identity
on_data(direction, data, flow)          → addon knows whose data, can read live stats
  └─ relay updates flow.bytes_* directly
on_flow_close(flow)                     → addon gets final snapshot, can log/aggregate
```

## IPv6 双栈

服务端用一个 `AF_INET6` socket（`IPV6_V6ONLY=0`）监听 `::`，同时处理 IPv4 和 IPv6。

客户端连接使用 Happy Eyeballs 风格 fallback。解析 IPv6 和 IPv4 候选，启动一个候选，然后每 250ms 启动后续候选。快速失败不会终止后续候选。

UDP relay 在路由表中归一化 IPv4-mapped IPv6 地址（`::ffff:x.x.x.x`）。

## Async Hooks

数据路径使用 `StreamReader` 和 `StreamWriter`。它本来就是 async：`await reader.read()` -> 处理 -> `await writer.drain()`。

Async hooks 允许：

- `ChainRouter.on_connect` 直接 `await client.connect()`。
- `on_auth` 使用 async I/O。
- relay 路径不需要 sync-to-async 桥接。

额外一次 `await` 相比网络 I/O 不构成主要成本。

## 设计决策

| 决策 | 选择 | 理由 |
|------|------|------|
| SOCKS 版本 | SOCKS5 | 覆盖 CONNECT 和 UDP ASSOCIATE |
| 运行时依赖 | 零 | 仅标准库 |
| Addon 模型 | 类式 + async | 一个类实现多个 hook，状态管理自然；async 匹配数据路径 |
| 配置方式 | Python 脚本 | Addon 是普通 Python 对象 |
| 热加载 | 内核不支持 | 需要时使用外部 watcher |
| 资源限制 | 内核不处理 | 使用系统级限制 |

## 专题文档

| 文档 | 内容 |
|------|------|
| [`addon-model.md`](addon-model.md) | Hook API、执行模型、内置 addon、链式代理 |
| [`public-api.zh-CN.md`](public-api.zh-CN.md) | 1.x 兼容面、包根导出、hook 契约 |
