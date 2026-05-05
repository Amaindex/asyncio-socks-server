# asyncio-socks-server

[![Tests](https://github.com/Amaindex/asyncio-socks-server/actions/workflows/tests.yml/badge.svg)](https://github.com/Amaindex/asyncio-socks-server/actions/workflows/tests.yml)
[![Docker](https://github.com/Amaindex/asyncio-socks-server/actions/workflows/docker.yml/badge.svg)](https://github.com/Amaindex/asyncio-socks-server/actions/workflows/docker.yml)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

带 async Python addon hooks 的 SOCKS5 server。

[文档](#文档) · [架构](docs/architecture.zh-CN.md) · [Addon 模型](docs/addon-model.zh-CN.md) · [公共 API](docs/public-api.zh-CN.md) · [English](README.md)

## 安装

```shell
pip install asyncio-socks-server
```

Docker image 使用明确版本：

```shell
docker run --rm -p 1080:1080 amaindex/asyncio-socks-server:1.3.0
```

## 运行

```shell
asyncio_socks_server
asyncio_socks_server --host 127.0.0.1 --port 9050
asyncio_socks_server --auth user:pass
```

CLI 参数：

| 参数 | 默认值 | 含义 |
|------|--------|------|
| `--host` | `::` | 监听地址 |
| `--port` | `1080` | 监听端口 |
| `--auth` | 无 | `username:password` |
| `--log-level` | `INFO` | `DEBUG`、`INFO`、`WARNING`、`ERROR` |

## Python API

```python
from asyncio_socks_server import Server

Server(host="::", port=1080).run()
```

使用 addon：

```python
from asyncio_socks_server import ChainRouter, FlowAudit, FlowStats, Server, StatsAPI

audit = FlowAudit()
stats = FlowStats()
server = Server(
    addons=[
        audit,
        stats,
        StatsAPI(stats=stats, audit=audit, host="127.0.0.1", port=9900),
        ChainRouter("10.0.0.5:1080"),
    ],
)
server.run()
```

Addon 顺序就是执行顺序。内置 addon 都是显式 opt-in；只有加入
`StatsAPI` 才会启动 HTTP listener。

`FlowStats` 没有网络副作用。使用它的 `snapshot()` 和 `flows()` 方法，
可以自行搭建 HTTP API、metrics exporter 或日志管道，也可以搭配
`StatsAPI` 使用一个小型本地 HTTP API。
`FlowAudit` 在内存中记录已关闭 flow 的用量，可通过 `StatsAPI`
暴露类似 Kafra 的用量审计摘要。

## 模型

核心处理 SOCKS5 解析、中继和 hook 调度。策略由 addon 处理。

Hook 调度有三种模型：

| 模型 | Hooks | 契约 |
|------|-------|------|
| 竞争型 | `on_auth`、`on_connect`、`on_udp_associate` | 第一个非 `None` 结果获胜 |
| 管道型 | `on_data` | 前一个 addon 的输出成为下一个 addon 的输入 |
| 观察型 | `on_start`、`on_stop`、`on_flow_close`、`on_error` | 所有适用 addon 都会执行 |

内置 addon：

- `ChainRouter`：TCP 链式代理
- `UdpOverTcpEntry` 和 `UdpOverTcpExitServer`：UDP 链式代理
- `FlowStats`：内存 flow 统计
- `FlowAudit`：已关闭 flow 的用量审计摘要
- `StatsAPI`：基于 `FlowStats` 的显式 opt-in HTTP API
- `StatsServer`：`StatsAPI` 的向后兼容名称
- `TrafficCounter`、`FileAuth`、`IPFilter`、`Logger`

## 架构简图

```text
Client ── SOCKS5 ──▶ Server ──▶ Target
                     │
                     ├─ auth / route hooks
                     ├─ data pipeline hooks
                     └─ flow close hooks

ChainRouter:
Client ──▶ A ──▶ B ──▶ C ──▶ Target
```

## 链式代理

每个节点只知道自己的下一跳：

```python
# A ─▶ B ─▶ C ─▶ target
Server(addons=[ChainRouter("B:1080")])  # A
Server(addons=[ChainRouter("C:1080")])  # B
Server()                                # C
```

UDP 链式代理在代理节点之间使用 TCP：

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

## API 面

稳定导入面在包根：

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

包根导出是 1.x 兼容性契约。子模块仍可导入。

## 文档

| 文档 | 范围 |
|------|------|
| [架构](docs/architecture.zh-CN.md) | 核心流程、relay 设计、UDP-over-TCP、Flow context |
| [Addon 模型](docs/addon-model.zh-CN.md) | Hook 契约、调度语义、内置 addon |
| [公共 API](docs/public-api.zh-CN.md) | 1.x 兼容面 |

## 开发

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

## 发布

GitHub Actions 测试 Python 3.12 和 3.13，构建 Python package，并构建 Docker images。

从 `v1.1.0` 这样的 tag 创建 GitHub Release。Release workflow 发布 Python package。Docker workflow 发布 semver image tags。

## License

MIT
