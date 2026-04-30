from __future__ import annotations

from typing import TYPE_CHECKING

from .base import Addon

if TYPE_CHECKING:
    from asyncio_socks_server.core.types import Direction, Flow
    from asyncio_socks_server.server.connection import Connection
    from asyncio_socks_server.server.udp_relay import UdpRelayBase


def _is_overridden(addon: Addon, method_name: str) -> bool:
    base_method = getattr(Addon, method_name, None)
    return getattr(type(addon), method_name, None) is not base_method


class AddonManager:
    def __init__(self, addons: list[Addon] | None = None):
        self._addons: list[Addon] = addons or []

    # lifecycle

    async def dispatch_start(self) -> None:
        for addon in self._addons:
            if _is_overridden(addon, "on_start"):
                await addon.on_start()

    async def dispatch_stop(self) -> None:
        for addon in self._addons:
            if _is_overridden(addon, "on_stop"):
                await addon.on_stop()

    # competitive: first non-None wins

    async def dispatch_auth(self, username: str, password: str) -> bool | None:
        for addon in self._addons:
            if _is_overridden(addon, "on_auth"):
                result = await addon.on_auth(username, password)
                if result is not None:
                    return result
        return None

    async def dispatch_connect(self, flow: Flow) -> Connection | None:
        for addon in self._addons:
            if _is_overridden(addon, "on_connect"):
                result = await addon.on_connect(flow)
                if result is not None:
                    return result
        return None

    async def dispatch_udp_associate(self, flow: Flow) -> UdpRelayBase | None:
        for addon in self._addons:
            if _is_overridden(addon, "on_udp_associate"):
                result = await addon.on_udp_associate(flow)
                if result is not None:
                    return result
        return None

    # pipeline: chain outputs

    async def dispatch_data(
        self, direction: Direction, data: bytes, flow: Flow
    ) -> bytes | None:
        current: bytes | None = data
        for addon in self._addons:
            if _is_overridden(addon, "on_data"):
                if current is None:
                    break
                current = await addon.on_data(direction, current, flow)
        return current

    # observational: call all

    async def dispatch_flow_close(self, flow: Flow) -> None:
        for addon in self._addons:
            if _is_overridden(addon, "on_flow_close"):
                try:
                    await addon.on_flow_close(flow)
                except Exception:
                    pass

    async def dispatch_error(self, error: Exception) -> None:
        for addon in self._addons:
            if _is_overridden(addon, "on_error"):
                try:
                    await addon.on_error(error)
                except Exception:
                    pass  # observational hooks must not disrupt
