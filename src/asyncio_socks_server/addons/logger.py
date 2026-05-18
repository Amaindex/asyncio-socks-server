from __future__ import annotations

import logging

from asyncio_socks_server.addons.base import Addon
from asyncio_socks_server.core.logging import fmt_event
from asyncio_socks_server.core.types import Direction, Flow


class Logger(Addon):
    """Detailed connection logging addon."""

    def __init__(self):
        self._logger = logging.getLogger("asyncio_socks_server.addon.logger")

    async def on_connect(self, flow: Flow) -> None:
        self._logger.info(
            fmt_event(
                "addon_connect",
                flow_id=flow.id,
                proto=flow.protocol,
                src=flow.src,
                dst=flow.dst,
            )
        )

    async def on_data(
        self, direction: Direction, data: bytes, flow: Flow
    ) -> bytes | None:
        self._logger.debug(
            fmt_event(
                "addon_data",
                flow_id=flow.id,
                proto=flow.protocol,
                direction=direction,
                bytes=len(data),
            )
        )
        return data

    async def on_error(self, error: Exception) -> None:
        self._logger.warning(
            fmt_event(
                "addon_error",
                error_type=type(error).__name__,
                error=str(error),
            )
        )
