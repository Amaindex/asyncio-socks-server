# asyncio-socks-server

[![Tests](https://github.com/Amaindex/asyncio-socks-server/actions/workflows/tests.yml/badge.svg)](https://github.com/Amaindex/asyncio-socks-server/actions/workflows/tests.yml)
[![Docker](https://github.com/Amaindex/asyncio-socks-server/actions/workflows/docker.yml/badge.svg)](https://github.com/Amaindex/asyncio-socks-server/actions/workflows/docker.yml)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> 带 async Python addon hooks 的 SOCKS5 server。

**[English](README.md)**

## Overview

asyncio-socks-server 是一个基于 async hook 的 SOCKS5 server。核心只处理协议解析、中继和 hook 调度。认证、路由、数据变换、日志和统计由 addon 处理。

设计：

- **三种 hook 模型**：竞争型、管道型、观察型
- **链式代理是 addon**：TCP 使用 `ChainRouter`，UDP 使用 UDP-over-TCP 入口和出口组件
- **无运行时依赖**：仅 Python 标准库

## Architecture

```text
SOCKS5 Client          Server                          Target / Next Hop
─────────────          ──────                          ──────────────────

TCP CONNECT ─────────▶ handshake
                       ├─ dispatch_auth (competitive)
                       └─ dispatch_connect (competitive)
                          ├─ no addon ───────────────▶ direct
                          └─ ChainRouter ────────────▶ next SOCKS5 hop

                       relay: dispatch_data (pipeline) per chunk
                       teardown: dispatch_flow_close (observational)

UDP ASSOCIATE ───────▶ handshake
                       └─ dispatch_udp_associate (competitive)
                          ├─ no addon ──▶ UdpRelay
                          └─ UdpOverTcpEntry ──▶ TCP frames ──▶ exit node
```

模块：**core**（协议）、**server**（握手/relay/生命周期）、**client**（SOCKS5 client）、**addons**（hooks 和内置 addon）。详见 [docs/architecture.zh-CN.md](docs/architecture.zh-CN.md)。

## Capabilities

- 8 个 async hook：认证、连接路由、数据处理、生命周期
- TCP 链式代理：`ChainRouter`
- UDP 链式代理：`UdpOverTcpEntry` 和 `UdpOverTcpExitServer`
- 每连接身份和字节计数：`Flow`
- 本地 JSON stats API：`StatsServer`
- 共享 socket UDP relay，TTL 清理路由
- IPv6 双栈监听，客户端 Happy Eyeballs 风格 fallback
- Python 标准库运行时

## API Status

1.x API 以包根导出为准：`Server`、`Addon`、`Address`、`Flow`、
`ChainRouter`、`StatsServer`、`connect` 及相关类型。

见 [docs/public-api.zh-CN.md](docs/public-api.zh-CN.md)。

## Quick Start

### CLI

```shell
asyncio_socks_server                              # 基础代理
asyncio_socks_server --auth user:pass --port 9050 # 带认证
```

### Python API

```python
from asyncio_socks_server import Server

server = Server(host="::", port=1080)
server.run()
```

使用 addon：

```python
from asyncio_socks_server import ChainRouter, Server, StatsServer

server = Server(
    addons=[
        StatsServer(host="127.0.0.1", port=9900),
        ChainRouter("10.0.0.5:1080"),
    ],
)
server.run()
```

Addon 顺序就是列表顺序。Hook API 见 [docs/addon-model.zh-CN.md](docs/addon-model.zh-CN.md)。

### 链式代理

每个节点只知道自己的下一跳：

```python
# Node A → B → C → Target
Server(addons=[ChainRouter("B:1080")])  # A
Server(addons=[ChainRouter("C:1080")])  # B
Server()                                 # C: direct
```

UDP 链式：

```python
# 入口节点
from asyncio_socks_server import UdpOverTcpEntry
server = Server(addons=[UdpOverTcpEntry("exit-host:9020")])

# 出口节点（独立 TCP 服务）
from asyncio_socks_server import UdpOverTcpExitServer
exit_srv = UdpOverTcpExitServer(host="::", port=9020)
exit_srv.run()
```

### 客户端库

```python
from asyncio_socks_server import connect, Address

conn = await connect(
    proxy_addr=Address("127.0.0.1", 1080),
    target_addr=Address("93.184.216.34", 443),
)
conn.writer.write(b"hello")
await conn.writer.drain()
data = await conn.reader.read(4096)
```

## Build

Python 3.12+。开发环境使用 [uv](https://docs.astral.sh/uv/)。

```shell
git clone https://github.com/Amaindex/asyncio-socks-server.git
cd asyncio-socks-server
uv sync
```

开发命令：

```shell
uv run ruff check .          # lint
uv run ruff format --check . # 格式检查
uv run pytest tests/ -v      # 测试（260 用例）
uv run pyright src/           # 类型检查
uv build                     # 包构建
```

## Public API

稳定导入面是包根：

```python
from asyncio_socks_server import (
    Addon,
    Address,
    ChainRouter,
    Connection,
    Direction,
    FileAuth,
    Flow,
    IPFilter,
    Logger,
    Server,
    StatsServer,
    TrafficCounter,
    UdpOverTcpEntry,
    UdpOverTcpExitServer,
    UdpRelayBase,
    connect,
)
```

子模块可以导入。兼容性承诺以包根导出为准。

## Configuration

不使用配置文件。

CLI 模式（基础代理）：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--host` | `::` | 监听地址 |
| `--port` | `1080` | 监听端口 |
| `--auth` | 无 | `username:password` |
| `--log-level` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |

需要 addon 或自定义行为时，直接在 Python 中实例化 `Server`。详见 [docs/addon-model.zh-CN.md](docs/addon-model.zh-CN.md)。

## Deployment

```shell
pip install asyncio-socks-server
```

Docker：

```shell
docker run --rm -p 1080:1080 amaindex/asyncio-socks-server
```

PyPI 和 Docker Hub 产物从 GitHub Release 发布。

## Release and CI

GitHub Actions 在 pull request 和 push to `main` 时运行 lint、format check、pyright、包构建和测试。测试覆盖 Python 3.12 和 3.13。

发布流程：

1. 从 tag（例如 `v1.0.0`）创建 GitHub Release。
2. Release workflow 构建并发布 Python package。
3. Docker workflow 构建 image；配置 Docker Hub 凭据后推送。

## Documentation

| 文档 | 内容 |
|------|------|
| [架构设计](docs/architecture.zh-CN.md) | 组件关系、数据流时序、UDP relay 设计、Flow context、设计决策 |
| [Addon 模型](docs/addon-model.zh-CN.md) | Hook API 参考、执行模型、链式代理原理、StatsServer、自定义 addon 示例 |
| [公共 API](docs/public-api.zh-CN.md) | 1.x 兼容面、包根导出、hook 契约、Stats API |

## License

MIT
