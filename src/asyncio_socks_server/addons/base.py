from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from asyncio_socks_server.core.types import Direction, Flow
    from asyncio_socks_server.server.connection import Connection
    from asyncio_socks_server.server.udp_relay import UdpRelayBase


class Addon:
    """Base addon class. All hook methods are optional async methods.

    Competitive hooks use None to abstain and non-None values to take over.
    The on_data pipeline uses returned bytes as the outgoing payload and None
    to drop the current chunk. Exceptions reject or abort the current operation.
    """

    async def on_start(self) -> None:
        """Called when the server starts."""

    async def on_stop(self) -> None:
        """Called when the server stops."""

    async def on_auth(self, username: str, password: str) -> bool | None:
        """Competitive: True=allow, False=deny, None=don't interfere."""

    async def on_connect(self, flow: Flow) -> Connection | None:
        """Competitive: return Connection to intercept, None=don't interfere."""

    async def on_udp_associate(self, flow: Flow) -> UdpRelayBase | None:
        """Competitive: return UdpRelayBase to intercept, None=don't interfere."""

    async def on_data(
        self, direction: Direction, data: bytes, flow: Flow
    ) -> bytes | None:
        """Pipeline: return bytes to write, None=drop this chunk."""

    async def on_flow_close(self, flow: Flow) -> None:
        """Observational: called when a flow (TCP or UDP) closes."""

    async def on_error(self, error: Exception) -> None:
        """Observational: just notify, doesn't affect flow."""
