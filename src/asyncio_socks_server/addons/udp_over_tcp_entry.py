from __future__ import annotations

import asyncio

from asyncio_socks_server.addons.base import Addon
from asyncio_socks_server.core.protocol import build_udp_header, parse_udp_header
from asyncio_socks_server.core.types import Address, Flow
from asyncio_socks_server.server.udp_over_tcp import encode_udp_frame, read_udp_frame
from asyncio_socks_server.server.udp_relay import UdpRelayBase


class UdpOverTcpEntry(Addon):
    """Route UDP ASSOCIATE through a downstream SOCKS5 proxy via UDP-over-TCP.

    The bridge connects to next_hop via SOCKS5 TCP CONNECT, then tunnels
    SOCKS5 UDP datagrams as length-prefixed TCP frames.
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

    async def on_udp_associate(self, flow: Flow) -> UdpRelayBase | None:
        return _Bridge(self._proxy_addr, self._username, self._password, flow)


class _Bridge(UdpRelayBase):
    """UDP-over-TCP bridge: client-side UDP ↔ TCP frames ↔ downstream proxy."""

    def __init__(
        self,
        proxy_addr,
        username: str | None,
        password: str | None,
        flow: Flow,
    ):
        self._proxy_addr = proxy_addr
        self._username = username
        self._password = password
        self._tcp_reader: asyncio.StreamReader | None = None
        self._tcp_writer: asyncio.StreamWriter | None = None
        self._client_transport: asyncio.DatagramTransport | None = None
        self._pump_task: asyncio.Task | None = None
        self._route_map: dict[tuple[str, int], tuple[str, int]] = {}
        self._flow = flow

    async def start(self) -> Address:
        # Open a plain TCP connection to the downstream proxy.
        # We don't use SOCKS5 handshake here — this is just a raw TCP
        # connection that the downstream UdpOverTcpExit server accepts.
        self._tcp_reader, self._tcp_writer = await asyncio.open_connection(
            self._proxy_addr.host, self._proxy_addr.port
        )
        sock = self._tcp_writer.get_extra_info("socket")
        sockname = sock.getsockname() if sock else ("::", 0)

        # Start the TCP→client pump
        self._pump_task = asyncio.create_task(self._tcp_to_client())

        return Address(sockname[0], sockname[1])

    def set_client_transport(self, transport: asyncio.DatagramTransport) -> None:
        self._client_transport = transport

    async def stop(self) -> None:
        if self._pump_task:
            self._pump_task.cancel()
            try:
                await self._pump_task
            except asyncio.CancelledError:
                pass
        if self._tcp_writer:
            try:
                self._tcp_writer.close()
                await self._tcp_writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    def handle_client_datagram(self, data: bytes, client_addr: tuple[str, int]) -> None:
        if not self._tcp_writer:
            return
        try:
            dst, _, payload = parse_udp_header(data)
        except Exception:
            return
        if not payload:
            return

        # Record route: remote → client
        remote_key = (dst.host, dst.port)
        self._route_map[remote_key] = client_addr
        self._flow.bytes_up += len(payload)

        # Send as TCP frame (async but fire-and-forget via task)
        async def _send():
            try:
                frame = await encode_udp_frame(dst, payload)
                self._tcp_writer.write(frame)  # type: ignore[union-attr]
                await self._tcp_writer.drain()  # type: ignore[union-attr]
            except (ConnectionError, OSError):
                pass

        asyncio.create_task(_send())

    async def _tcp_to_client(self) -> None:
        try:
            while True:
                src_addr, payload = await read_udp_frame(self._tcp_reader)  # type: ignore[arg-type]
                self._flow.bytes_down += len(payload)
                # Find the client that sent to this remote
                remote_key = (src_addr.host, src_addr.port)
                client_addr = self._route_map.get(remote_key)
                if client_addr is None:
                    continue
                header = build_udp_header(src_addr)
                packet = header + payload
                if self._client_transport:
                    self._client_transport.sendto(packet, client_addr)
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
