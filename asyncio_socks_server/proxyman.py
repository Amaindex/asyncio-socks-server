import asyncio

from asyncio_socks_server.config import Config
from asyncio_socks_server.protocols import LocalTCP


class ProxyMan:
    def __init__(self, config: Config):
        self.config = config
        self.loop = asyncio.get_event_loop()
        self.server = None

    async def start_server(self):
        server = await self.loop.create_server(
            lambda: LocalTCP(self.config),
            self.config.LISTEN_HOST,
            self.config.LISTEN_PORT,
        )
        self.server = server

    async def close_server(self):
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
