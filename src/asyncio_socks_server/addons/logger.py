from __future__ import annotations

import logging

from asyncio_socks_server.addons.base import Addon
from asyncio_socks_server.core.logging import fmt_connection
from asyncio_socks_server.core.types import Direction, Flow


class Logger(Addon):
    """Detailed connection logging addon."""

    def __init__(self):
        self._logger = logging.getLogger("asyncio_socks_server.addon.logger")

    async def on_connect(self, flow: Flow) -> None:
        self._logger.info(f"{fmt_connection(flow.src, flow.dst)} | on_connect")

    async def on_data(
        self, direction: Direction, data: bytes, flow: Flow
    ) -> bytes | None:
        self._logger.debug(f"{direction} | {len(data)} bytes")
        return data

    async def on_error(self, error: Exception) -> None:
        self._logger.warning(f"error: {error}")
