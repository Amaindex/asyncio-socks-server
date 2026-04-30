from __future__ import annotations

import asyncio
import time
from typing import Callable

from asyncio_socks_server.core.protocol import build_udp_header, parse_udp_header
from asyncio_socks_server.core.socket import create_dualstack_udp_socket
from asyncio_socks_server.core.types import Address, Flow


def _normalize_host(host: str) -> str:
    """Strip IPv4-mapped IPv6 prefix for consistent routing table keys."""
    if host.startswith("::ffff:"):
        return host[7:]
    return host


def _map_addr_for_sendto(
    host: str, port: int
) -> tuple[str, int] | tuple[str, int, int, int]:
    """Return an address tuple suitable for the outbound socket's family.

    AF_INET6 sockets require IPv4-mapped format (::ffff:x.x.x.x) for IPv4 targets.
    """
    import ipaddress

    try:
        addr = ipaddress.ip_address(host)
        if isinstance(addr, ipaddress.IPv4Address):
            return (f"::ffff:{host}", port, 0, 0)
    except ValueError:
        pass
    return (host, port)


class UdpRelayBase:
    """Interface for UDP relay handlers used by the server and addon system."""

    async def start(self) -> Address:
        raise NotImplementedError

    def set_client_transport(self, transport: asyncio.DatagramTransport) -> None:
        raise NotImplementedError

    async def stop(self) -> None:
        raise NotImplementedError

    def handle_client_datagram(self, data: bytes, client_addr: tuple[str, int]) -> None:
        raise NotImplementedError


class UdpRelay(UdpRelayBase):
    """UDP relay using a shared outbound socket + bidirectional routing table.

    All clients share one outbound UDP socket. A routing table maps
    remote addresses back to client addresses for response routing.
    Entries expire after TTL seconds of inactivity.
    """

    def __init__(self, client_addr: Address, flow: Flow, ttl: float = 300.0):
        self._client_addr = client_addr
        self._ttl = ttl
        self._transport: asyncio.DatagramTransport | None = None
        self._route_map: dict[tuple[str, int], tuple[str, int]] = {}
        self._route_timestamps: dict[tuple[str, int], float] = {}
        self._ttl_task: asyncio.Task | None = None
        self._client_transport: asyncio.DatagramTransport | None = None
        self._bind_addr: Address | None = None
        self._flow = flow

    async def start(self) -> Address:
        loop = asyncio.get_running_loop()
        outbound_sock = create_dualstack_udp_socket("0.0.0.0", 0)
        outbound_sock.setblocking(False)
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _UdpProtocol(self._on_remote_data),
            sock=outbound_sock,
        )
        self._transport = transport
        sock = transport.get_extra_info("socket")
        sockname = sock.getsockname() if sock else ("::", 0)
        self._bind_addr = Address(sockname[0], sockname[1])
        self._ttl_task = asyncio.create_task(self._ttl_cleanup_loop())
        return self._bind_addr

    def set_client_transport(self, transport: asyncio.DatagramTransport) -> None:
        self._client_transport = transport

    async def stop(self) -> None:
        if self._ttl_task:
            self._ttl_task.cancel()
            try:
                await self._ttl_task
            except asyncio.CancelledError:
                pass
        if self._transport:
            self._transport.close()

    def handle_client_datagram(self, data: bytes, client_addr: tuple[str, int]) -> None:
        try:
            dst, _, payload = parse_udp_header(data)
        except Exception:
            return

        if not payload:
            return

        remote_key = (dst.host, dst.port)
        self._route_map[remote_key] = client_addr
        self._route_timestamps[remote_key] = time.monotonic()

        if self._transport:
            self._transport.sendto(payload, _map_addr_for_sendto(dst.host, dst.port))
            self._flow.bytes_up += len(payload)

    def _on_remote_data(self, data: bytes, remote_addr: tuple[str, int]) -> None:
        self._flow.bytes_down += len(data)
        remote_key = (_normalize_host(remote_addr[0]), remote_addr[1])
        client_addr = self._route_map.get(remote_key)
        if client_addr is None:
            return

        self._route_timestamps[remote_key] = time.monotonic()

        # Build SOCKS5 UDP reply header
        src_addr = Address(_normalize_host(remote_addr[0]), remote_addr[1])
        header = build_udp_header(src_addr)
        packet = header + data

        if self._client_transport:
            self._client_transport.sendto(packet, client_addr)

    async def _ttl_cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(60)
            now = time.monotonic()
            expired = [
                key
                for key, ts in self._route_timestamps.items()
                if now - ts > self._ttl
            ]
            for key in expired:
                self._route_map.pop(key, None)
                self._route_timestamps.pop(key, None)


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_data: Callable[[bytes, tuple[str, int]], None]) -> None:
        self._on_data = on_data
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self._on_data(data, addr)

    def error_received(self, exc: Exception) -> None:
        pass
