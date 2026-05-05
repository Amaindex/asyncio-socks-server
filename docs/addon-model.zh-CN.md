# Addon 模型

[README](../README.zh-CN.md) · [架构](architecture.zh-CN.md) · [Addon recipes](addon-recipes.zh-CN.md) · [公共 API](public-api.zh-CN.md) · [English](addon-model.md)

Addon 是包含可选 async 方法的 Python 类。Server 在 SOCKS5 流程的固定位置调用它们。

本文解释派发语义。如果你已经知道自己想搭建什么，先看
[Addon recipes](addon-recipes.zh-CN.md)。

## 执行模型

单一派发规则不够：

- 认证和路由需要第一个结果胜出。
- 数据处理需要输出到输入的链式传递。
- 生命周期事件需要调用所有适用 addon。

Manager 使用三种模型：

| 模型 | 语义 | 何时使用 | Hook |
|------|------|----------|------|
| 竞争型 | 第一个非 `None` 胜出，后续跳过 | 互斥决策 | `on_auth`、`on_connect`、`on_udp_associate` |
| 管道型 | 顺序执行，输出→输入链式传递 | 数据转换链 | `on_data` |
| 观察型 | 按场景全部调用；flow-close/error 异常被捕获 | 日志、监控、清理 | `on_start`、`on_stop`、`on_flow_close`、`on_error` |

## Hook API

所有方法可选——未实现的 hook 不影响流程。

```python
class Addon:
    # 生命周期（观察型）
    async def on_start(self) -> None:
        """服务器启动。"""

    async def on_stop(self) -> None:
        """服务器停止。刷新缓冲、写入统计。"""

    # 认证（竞争型）
    async def on_auth(self, username: str, password: str) -> bool | None:
        """True = 放行，False = 拒绝，None = 不干预。"""

    # 连接拦截（竞争型）
    async def on_connect(self, flow: Flow) -> Connection | None:
        """返回 Connection 拦截，None 不干预，抛异常拒绝。"""

    async def on_udp_associate(self, flow: Flow) -> UdpRelayBase | None:
        """返回 UdpRelayBase 拦截，None 不干预。"""

    # 数据转换（管道型）
    async def on_data(self, direction: Direction, data: bytes, flow: Flow) -> bytes | None:
        """返回 bytes 写出，None 丢弃当前 chunk，抛异常中止。"""

    # 拆解（观察型）
    async def on_flow_close(self, flow: Flow) -> None:
        """连接关闭。最终统计在 flow 中。"""

    async def on_error(self, error: Exception) -> None:
        """发生异常。仅用于日志/监控。"""
```

### 返回值契约

竞争型和管道型 hook 的 `None` 语义不同：

| Hook 类型 | 返回 | 含义 |
|----------|------|------|
| 竞争型 | `None` | 弃权——让下一个 addon 或默认行为决定 |
| 竞争型 | 非 `None` | 胜出——将返回值作为结果 |
| 管道型 `on_data` | `bytes` | 写出这些字节，并继续传给下一个 addon |
| 管道型 `on_data` | `None` | 丢弃当前 chunk，并停止管道 |
| 任意 | 抛异常 | 拒绝/中止当前操作 |

如果 addon 使用不同 hook，可以共存而不需要互相协调。

## 竞争型派发

第一个非 `None` 胜出。剩余 addon 跳过。

```
on_auth("admin", "secret"):
  FileAuth  → True        ← 胜出，在此停止
  IPFilter  → （不调用）
  Logger    → （不调用）
```

```
on_auth("unknown", "pass"):
  FileAuth  → False       ← 显式拒绝
  IPFilter  → （不调用）
```

```
on_auth("guest", "pass"):
  FileAuth  → None        ← 不干预（用户不在文件中）
  IPFilter  → None        ← 不干预（IP 与认证无关）
  → 内核使用默认行为：无需认证 → 放行
```

抛异常会拒绝当前操作。客户端收到 SOCKS5 错误回复。

## 管道型派发

顺序执行，输出链式传递。返回 `None` 中断管道（数据丢弃，后续 addon 不调用）。

```
on_data(up, b"hello", flow):
  UpperAddon    → b"HELLO"     ← 转换
  TrafficLogger → b"HELLO"     ← 通过返回原输入来放行
  AppendNull    → b"HELLO\x00" ← 转换
  → 写入目标: b"HELLO\x00"
```

```
on_data(down, response, flow):
  DropAddon     → None         ← 丢弃数据，管道中断
  UpperAddon    → （不调用）
  → 不向客户端写入任何内容
```

管道顺序即 addon 列表顺序。

## 观察型派发

所有 addon 调用。异常被捕获不传播。

```
on_flow_close(flow):
  TrafficCounter  → 聚合字节（写入时可能抛异常）
  Logger          → 记录连接统计
  → 全部调用，任何异常被记录但被抑制
```

这把 teardown 和监控从单个 addon 的失败中隔离出来。

## 内置 Addon

| Addon | 主要角色 | 是否启动网络 listener |
|-------|----------|-----------------------|
| `ChainRouter` | TCP 下一跳路由 | 否 |
| `UdpOverTcpEntry` | UDP-over-TCP 入口路由 | 否 |
| `UdpOverTcpExitServer` | UDP-over-TCP 出口服务 | 是，作为独立 server |
| `FlowStats` | 运行计数和活跃 flow 快照 | 否 |
| `FlowAudit` | 已关闭 flow 的用量审计窗口 | 否 |
| `StatsAPI` | stats/audit 的可选 HTTP 展示层 | 是，只有加入 addon 列表才启动 |
| `StatsServer` | `StatsAPI` 的向后兼容名称 | 是，只有加入 addon 列表才启动 |
| `TrafficCounter` | 最小的已关闭 flow 字节汇总 | 否 |
| `FileAuth` | JSON 用户名/密码认证 | 否 |
| `IPFilter` | 来源 IP allow/block 策略 | 否 |
| `Logger` | 连接和数据日志 | 否 |

所有内置 addon 都是显式 opt-in。CLI 模式启动直连 SOCKS5 server；addon
组合通过 Python 配置。

### ChainRouter — TCP 链式代理

```python
class ChainRouter(Addon):
    def __init__(self, next_hop: str): ...

    async def on_connect(self, flow):
        conn = await client.connect(self.next_hop, flow.dst)
        return conn
```

`ChainRouter` 返回到下一跳 SOCKS5 server 的 `Connection`。Server 通过返回的连接中继。

每个节点只知道自己下一跳：

```
用户 → [A: ChainRouter("B:1080")] → [B: ChainRouter("C:1080")] → [C: 直连] → 目标
```

### UdpOverTcpEntry — UDP 链式代理

UDP 链式代理复用同一个竞争型 hook（`on_udp_associate`），但返回一个将 UDP 数据报封装为 TCP 帧的 bridge，而非 `Connection`。

```
客户端 UDP → 入口 addon（封装）→ TCP 链式 → 出口服务（拆封）→ UDP → 目标
```

中间节点只看到 TCP bytes。

### TrafficCounter — 统计聚合

```python
class TrafficCounter(Addon):
    async def on_connect(self, flow):
        self.connections += 1

    async def on_flow_close(self, flow):
        self.bytes_up += flow.bytes_up
        self.bytes_down += flow.bytes_down
```

`TrafficCounter` 在 `on_flow_close` 中聚合。`Flow` 已经有累计字节计数，且 UDP 不经过 `on_data`。

### FlowStats — Flow 统计基础设施

```python
from asyncio_socks_server import FlowStats, Server

stats = FlowStats()
server = Server(addons=[stats])
```

`FlowStats` 没有网络副作用。它通过 addon hooks 记录 flow 生命周期数据，
并暴露 Python 方法供应用自行决定展示方式：

| 方法 | 内容 |
|------|------|
| `snapshot()` | 聚合计数、速率、错误和活跃 flow |
| `flows()` | 活跃 flow 和最近关闭 flow 快照 |
| `errors()` | 错误计数和最近错误 |

用 `FlowStats` 搭建自己的 HTTP API、Prometheus exporter、文件审计流或控制面集成。

### FlowAudit — 用量审计基础设施

```python
from asyncio_socks_server import FlowAudit, Server

audit = FlowAudit()
server = Server(addons=[audit])
```

`FlowAudit` 没有网络副作用。它在内存中记录已关闭 flow，并按 source host
和 target host 聚合用量：

| 方法 | 内容 |
|------|------|
| `snapshot()` | 类似 Kafra audit 的摘要，包含 period、records、total、devices 和 traffic |
| `reset()` | 清空当前内存审计窗口 |

进程重启后审计窗口会重置。如果需要长期留痕，应在应用层接入持久化 sink。

### StatsAPI — 显式 opt-in HTTP API

```python
from asyncio_socks_server import FlowAudit, FlowStats, Server, StatsAPI

audit = FlowAudit()
stats = FlowStats()
api = StatsAPI(stats=stats, audit=audit, host="127.0.0.1", port=9900)
server = Server(addons=[audit, stats, api])
```

`StatsAPI` 是基于 `FlowStats` 和可选 `FlowAudit` 的简单标准库 HTTP
wrapper。只有显式加入 addon 列表时才会启动 listener：

| Endpoint | 内容 |
|----------|------|
| `GET /health` | 存活响应 |
| `GET /stats` | `FlowStats.snapshot()` |
| `GET /flows` | `FlowStats.flows()` |
| `GET /errors` | `FlowStats.errors()` |
| `GET /audit?top=25&device=` | `FlowAudit.snapshot()` |
| `POST /audit/refresh?top=25&device=` | 返回当前 `FlowAudit.snapshot()`，用于类似 Kafra 的刷新流程 |

如果不传入 `FlowStats`，`StatsAPI` 会自己创建并托管一个：

```python
server = Server(addons=[StatsAPI(host="127.0.0.1", port=9900)])
```

`StatsServer` 作为 `StatsAPI` 的向后兼容名称保留。

建议把 `FlowStats` 或托管自身 stats 的 `StatsAPI` 放在 addon 列表靠前位置。它通过竞争型 hook 观察 flow start。更早胜出的 addon 会让它看不到 start 事件。`on_flow_close` 仍会收到最终 Flow 快照。

### FileAuth — 多用户认证

从 JSON 文件读取用户名/密码映射。首次加载后缓存。只有 server 协商
username/password auth 时才会调用 `FileAuth`，因此使用它时需要配置
`Server(auth=...)`。

### IPFilter — 源 IP 访问控制

```python
IPFilter(allowed=["10.0.0.0/24"])
# 或
IPFilter(blocked=["10.0.0.5"])
```

在 `on_connect` 中读取 `flow.src.host`。被拒绝的连接收到 SOCKS5 `CONNECTION_NOT_ALLOWED` 回复。

### Logger — 连接日志

记录连接详情和流量统计。不改变代理行为。

## 自定义 Addon 模式

### 选择性内容检查

```python
class ContentFilter(Addon):
    async def on_connect(self, flow):
        if flow.dst.port != 80:
            return  # 只检查 HTTP

    async def on_data(self, direction, data, flow):
        if direction == Direction.UP and b"forbidden-keyword" in data:
            raise Exception("blocked content")
        return data  # 放行
```

### 每连接速率限制

```python
class RateLimiter(Addon):
    def __init__(self, max_bytes=1024 * 1024):  # 每连接 1MB
        self.max_bytes = max_bytes

    async def on_data(self, direction, data, flow):
        if flow.bytes_up + flow.bytes_down > self.max_bytes:
            raise Exception("rate limit exceeded")
        return data
```

### 动态下一跳路由

```python
class DynamicRouter(Addon):
    def __init__(self):
        self.routes = {}  # 域名模式 → 下一跳

    async def on_connect(self, flow):
        for pattern, hop in self.routes.items():
            if pattern in flow.dst.host:
                return await client.connect(hop, flow.dst)
```

## 派发内部机制

`AddonManager` 通过 `type(addon).method is not Addon.method` 检测子类是否重写了方法，跳过未重写的。这避免为基类的空方法创建协程——在处理数千个 chunk 经过 `on_data` 时影响显著。

Addon 列表顺序即执行顺序。没有优先级系统或依赖解析——如果顺序重要，自行安排列表。

Hook 签名和 Flow 语义的兼容性承诺见
[`public-api.zh-CN.md`](public-api.zh-CN.md)。
