from __future__ import annotations

from asyncio_socks_server.addons.base import Addon
from asyncio_socks_server.client import client
from asyncio_socks_server.core.types import Address, Flow
from asyncio_socks_server.server.connection import Connection


class ChainRouter(Addon):
    """Route connections through a SOCKS5 proxy chain.

    Each instance represents one hop. The addon connects to next_hop
    via SOCKS5 and tunnels the connection through it.
    """

    def __init__(
        self,
        next_hop: str,
        username: str | None = None,
        password: str | None = None,
    ):
        host, _, port_str = next_hop.rpartition(":")
        self._proxy_addr = Address(host, int(port_str))
        self._username = username
        self._password = password

    async def on_connect(self, flow: Flow) -> Connection | None:
        conn = await client.connect(
            proxy_addr=self._proxy_addr,
            target_addr=flow.dst,
            username=self._username,
            password=self._password,
        )
        return conn
