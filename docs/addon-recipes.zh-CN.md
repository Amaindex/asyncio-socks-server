# Addon Recipes

[README](../README.zh-CN.md) · [架构](architecture.zh-CN.md) · [Addon 模型](addon-model.zh-CN.md) · [公共 API](public-api.zh-CN.md) · [English](addon-recipes.md)

当你需要选择 addon 组合时，从这里开始。Addon 都是显式 opt-in，并按
`Server(addons=[...])` 中的顺序执行。

## 直连 SOCKS5 Server

普通 SOCKS5 server 不需要任何 addon：

```python
from asyncio_socks_server import Server

Server(host="::", port=1080).run()
```

CLI 模式等价于这个直连形态，加上可选的单用户认证。

## 运行计数

用 `FlowStats` 收集计数；只有需要 HTTP endpoint 时才加 `StatsAPI`：

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

Endpoints：

| Endpoint | 用途 |
|----------|------|
| `GET /health` | 存活检查 |
| `GET /stats` | 总量、速率、错误、活跃 flows |
| `GET /flows` | 活跃和最近关闭 flows |
| `GET /errors` | 错误计数 |

如果需要看到 flow start，`FlowStats` 应放在竞争型路由 addon 之前。

## 用量审计

用 `FlowAudit` 按 source host 和 target host 聚合已关闭 flow 的用量：

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

Endpoints：

| Endpoint | 用途 |
|----------|------|
| `GET /audit?top=25&device=` | 当前内存审计窗口 |
| `POST /audit/refresh?top=25&device=` | 同一份 snapshot，便于控制面做刷新流程 |

审计窗口在内存中，进程重启后会清空。如果需要长期留痕，应增加自定义 sink。

## 运行计数加审计

这是常见的观测组合：

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

`StatsAPI` 是展示层。除非它自己托管内部 `FlowStats`，否则它不直接收集
stats 或 audit 数据。当其他代码也需要 Python API 时，显式传入
`FlowStats` 和 `FlowAudit` 实例。

## TCP 链式代理

当这个 server 需要把 TCP CONNECT 流量转发到下游 SOCKS5 server 时，使用
`ChainRouter`：

```python
from asyncio_socks_server import ChainRouter, Server

Server(addons=[ChainRouter("10.0.0.5:1080")]).run()
```

每个节点只知道自己的下一跳：

```python
Server(addons=[ChainRouter("B:1080")])  # A
Server(addons=[ChainRouter("C:1080")])  # B
Server()                                # C
```

## UDP Over TCP 链式代理

在面向 SOCKS 的入口节点使用 `UdpOverTcpEntry`，在出口节点使用
`UdpOverTcpExitServer`：

```python
from asyncio_socks_server import Server, UdpOverTcpEntry, UdpOverTcpExitServer

entry = Server(addons=[UdpOverTcpEntry("exit-host:9020")])
exit_server = UdpOverTcpExitServer(host="::", port=9020)
```

中间链路节点只看到 TCP bytes。

## 认证、来源策略和日志

这些 addon 可以独立使用，也可以组合：

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

只有启用 server auth 时，`FileAuth` 才会被调用；`auth` tuple 用于强制
username/password 协商，且它本身仍是有效的 fallback 凭证，因此需要明确设置。
`IPFilter` 接受 `allowed` 或 `blocked`，不要同时传入。`Logger` 只观察流量，
不改变路由。

## 兼容名称

`StatsServer` 是 `StatsAPI` 的向后兼容名称。新代码建议使用 `StatsAPI`，
因为这个名字更准确地表达它是展示层。
