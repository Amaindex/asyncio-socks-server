from __future__ import annotations

import asyncio

from asyncio_socks_server.addons.manager import AddonManager
from asyncio_socks_server.core.logging import get_logger
from asyncio_socks_server.core.types import Direction, Flow


async def _copy(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    addon_manager: AddonManager,
    direction: Direction,
    flow: Flow,
) -> None:
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            result = await addon_manager.dispatch_data(direction, data, flow)
            if result is None:
                continue
            writer.write(result)
            await writer.drain()
            n = len(result)
            if direction == Direction.UPSTREAM:
                flow.bytes_up += n
            else:
                flow.bytes_down += n
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


async def handle_tcp_relay(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    remote_reader: asyncio.StreamReader,
    remote_writer: asyncio.StreamWriter,
    addon_manager: AddonManager,
    flow: Flow,
) -> None:
    """Bidirectional TCP relay with addon on_data pipeline."""
    try:
        async with asyncio.TaskGroup() as tg:
            tg.create_task(
                _copy(
                    client_reader,
                    remote_writer,
                    addon_manager,
                    Direction.UPSTREAM,
                    flow,
                )
            )
            tg.create_task(
                _copy(
                    remote_reader,
                    client_writer,
                    addon_manager,
                    Direction.DOWNSTREAM,
                    flow,
                )
            )
    except ExceptionGroup as eg:
        get_logger().debug(f"tcp relay task group ended: {eg.exceptions}")
