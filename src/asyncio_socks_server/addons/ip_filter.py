from __future__ import annotations

import ipaddress

from asyncio_socks_server.addons.base import Addon
from asyncio_socks_server.core.types import Flow


class IPFilter(Addon):
    """Allow or deny connections based on source IP ranges.

    Either `allowed` or `blocked` can be provided (not both).
    If `allowed` is set, only listed IPs/ranges can connect.
    If `blocked` is set, listed IPs/ranges are denied.
    """

    def __init__(
        self,
        allowed: list[str] | None = None,
        blocked: list[str] | None = None,
    ):
        self._allowed = [ipaddress.ip_network(n) for n in (allowed or [])]
        self._blocked = [ipaddress.ip_network(n) for n in (blocked or [])]

    def _is_allowed(self, host: str) -> bool:
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return False

        if self._blocked:
            return not any(addr in net for net in self._blocked)
        if self._allowed:
            return any(addr in net for net in self._allowed)
        return True

    async def on_connect(self, flow: Flow) -> None:
        if not self._is_allowed(flow.src.host):
            raise ConnectionRefusedError(f"IP blocked: {flow.src.host}")
        return None
