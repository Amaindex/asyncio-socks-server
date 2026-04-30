# 公共 API

[README](../README.zh-CN.md) · [架构](architecture.zh-CN.md) · [Addon 模型](addon-model.zh-CN.md) · [English](public-api.md)

本文定义 asyncio-socks-server 1.x 的兼容性边界。稳定导入面是包根。子模块仍可导入。

## 兼容性策略

包根稳定：

```python
from asyncio_socks_server import Server, Addon, Address, connect
```

在 1.x 系列内：

- 包根导出的名称和主要行为保持兼容。
- Addon hook 签名保持兼容。
- `Flow` 的字节计数和地址字段语义保持稳定。
- CLI 参数保持向后兼容。

`asyncio_socks_server.core`、`asyncio_socks_server.server`、
`asyncio_socks_server.client`、`asyncio_socks_server.addons` 下的模块可以导入。兼容性契约以包根导出为准。

## 包根导出

| 名称 | 类别 | 用途 |
|------|------|------|
| `Server` | 服务端 | SOCKS5 server 入口 |
| `connect` | 客户端 | 通过 SOCKS5 proxy 打开 TCP 连接 |
| `Addon` | Addon 基类 | 可选 async hooks 的基类 |
| `ChainRouter` | Addon | 将 TCP CONNECT 路由到下游 SOCKS5 proxy |
| `UdpOverTcpEntry` | Addon | 将 UDP ASSOCIATE 流量封装到 TCP exit service |
| `UdpOverTcpExitServer` | 服务端 | UDP-over-TCP 链式代理的出口服务 |
| `StatsServer` | Addon | 低频 HTTP JSON stats API |
| `TrafficCounter` | Addon | 聚合已关闭 flow 的字节计数 |
| `FileAuth` | Addon | 从 JSON 文件读取用户名/密码 |
| `IPFilter` | Addon | 源 IP allow/block 规则 |
| `Logger` | Addon | 连接和数据日志 |
| `Address` | 类型 | host/port 二元组 |
| `Flow` | 类型 | 每连接上下文和字节计数 |
| `Direction` | 类型 | 数据方向枚举 |
| `Connection` | 类型 | connection hook 返回的 reader/writer |
| `UdpRelayBase` | 类型 | 自定义 UDP relay addon 的基础接口 |

## Server 契约

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

`Server.run()` 接管 event loop，并安装 SIGINT/SIGTERM handler。内部 coroutine 不属于稳定公共 API。

Shutdown 会先停止接收新客户端，等待活跃 client task，再调用 addon
`on_stop`。如果 `shutdown_timeout` 为 `None`，会无限等待活跃客户端；否则超时后
取消未完成 task。

## Addon 契约

所有 addon hook 都是可选 async 方法。Hook 模型如下：

| 模型 | Hooks | 返回值契约 |
|------|-------|------------|
| 竞争型 | `on_auth`, `on_connect`, `on_udp_associate` | `None` 表示弃权；非 `None` 获胜 |
| 管道型 | `on_data` | `bytes` 继续；`None` 丢弃当前 chunk |
| 观察型 | `on_start`, `on_stop`, `on_flow_close`, `on_error` | 返回值忽略 |

竞争型 hook 抛异常会拒绝当前 SOCKS 操作。`on_flow_close` 和 `on_error` 中的异常会被抑制。

## Flow 语义

`Flow` 在一次 TCP CONNECT 或 UDP ASSOCIATE 生命周期内被所有 hook 共享。

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

字节计数由 relay 路径维护，而不是由 addon 维护：

- `bytes_up`：client 到 target，TCP 场景下为经过 data pipeline 后的字节
- `bytes_down`：target 到 client
- UDP 计数统计 SOCKS5 UDP payload，不包含 UDP header

Addon 应把 `Flow` 视为可读上下文。修改字节计数或地址字段不受支持。

## Stats API

`StatsServer` 暴露一个标准库 HTTP server：

| Endpoint | 含义 |
|----------|------|
| `GET /health` | 存活检查 |
| `GET /stats` | 聚合计数和活跃 flow 快照 |
| `GET /flows` | 活跃 flow 和最近关闭 flow 快照 |

该 API 面向低频本地查看。建议把 `StatsServer` 放在 addon 列表靠前位置，这样它能在其他竞争型 addon 获胜前观察 flow start。

## CLI 契约

```shell
asyncio_socks_server --host :: --port 1080 --auth user:pass --log-level INFO
```

CLI 模式启动一个直连 SOCKS5 server，可选单用户认证。Addon 和高级路由通过 Python 配置。
