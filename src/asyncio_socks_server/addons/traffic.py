from __future__ import annotations

from asyncio_socks_server.addons.base import Addon
from asyncio_socks_server.core.types import Flow


class TrafficCounter(Addon):
    """Count bytes flowing through the proxy (TCP and UDP)."""

    def __init__(self):
        self.bytes_up: int = 0
        self.bytes_down: int = 0
        self.connections: int = 0

    async def on_connect(self, flow: Flow) -> None:
        self.connections += 1

    async def on_flow_close(self, flow: Flow) -> None:
        self.bytes_up += flow.bytes_up
        self.bytes_down += flow.bytes_down
