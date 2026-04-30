from __future__ import annotations

import asyncio
import time

from asyncio_socks_server.core.logging import get_logger
from asyncio_socks_server.core.socket import (
    create_dualstack_tcp_socket,
    create_dualstack_udp_socket,
)
from asyncio_socks_server.core.types import Address
from asyncio_socks_server.server.udp_over_tcp import encode_udp_frame, read_udp_frame


def _normalize_host(host: str) -> str:
    if host.startswith("::ffff:"):
        return host[7:]
    return host


def _map_addr_for_sendto(
    host: str, port: int
) -> tuple[str, int] | tuple[str, int, int, int]:
    import ipaddress

    try:
        addr = ipaddress.ip_address(host)
        if isinstance(addr, ipaddress.IPv4Address):
            return (f"::ffff:{host}", port, 0, 0)
    except ValueError:
        pass
    return (host, port)


class UdpOverTcpExitServer:
    """Accepts TCP connections carrying UDP-over-TCP frames and relays to raw UDP.

    Used as the exit node in a UDP-over-TCP chain. Not an addon — it's a
    standalone TCP service that sits at the chain endpoint.
    """

    def __init__(self, host: str = "::", port: int = 0, ttl: float = 300.0):
        self.host = host
        self.port = port
        self._ttl = ttl
        self._shutdown_event = asyncio.Event()

    def run(self) -> None:
        asyncio.run(self._run())

    def request_shutdown(self) -> None:
        self._shutdown_event.set()

    async def _run(self) -> None:
        logger = get_logger()
        sock = create_dualstack_udp_socket("0.0.0.0", 0)
        sock.setblocking(False)
        loop = asyncio.get_running_loop()
        udp_transport: asyncio.DatagramTransport | None = None
        route_map: dict[tuple[str, int], asyncio.StreamWriter] = {}
        route_ts: dict[tuple[str, int], float] = {}

        # Shared outbound UDP socket
        class UdpProtocol(asyncio.DatagramProtocol):
            def connection_made(self, transport: asyncio.DatagramTransport) -> None:
                nonlocal udp_transport
                udp_transport = transport

            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                remote_key = (_normalize_host(addr[0]), addr[1])
                writer = route_map.get(remote_key)
                if writer is None:
                    return
                route_ts[remote_key] = time.monotonic()
                src_addr = Address(_normalize_host(addr[0]), addr[1])
                task = asyncio.create_task(_send_frame(writer, src_addr, data))
                task.add_done_callback(
                    lambda t: t.exception() if not t.cancelled() else None
                )

            def error_received(self, exc: Exception) -> None:
                pass

        async def _send_frame(
            writer: asyncio.StreamWriter, src_addr: Address, data: bytes
        ) -> None:
            try:
                frame = await encode_udp_frame(src_addr, data)
                writer.write(frame)
                await writer.drain()
            except (ConnectionError, OSError):
                pass

        _, _ = await loop.create_datagram_endpoint(UdpProtocol, sock=sock)

        # TTL cleanup task
        async def _ttl_cleanup():
            while True:
                await asyncio.sleep(60)
                now = time.monotonic()
                expired = [k for k, ts in route_ts.items() if now - ts > self._ttl]
                for k in expired:
                    route_map.pop(k, None)
                    route_ts.pop(k, None)

        ttl_task = asyncio.create_task(_ttl_cleanup())

        # TCP server
        tcp_sock = create_dualstack_tcp_socket(self.host, self.port)
        tcp_sock.setblocking(False)
        tcp_srv = await asyncio.start_server(
            lambda r, w: _handle_tcp(r, w, udp_transport, route_map, route_ts),
            sock=tcp_sock,
        )
        tcp_sockname = tcp_srv.sockets[0].getsockname()
        self.port = tcp_sockname[1]
        logger.info(f"udp-over-tcp exit started on {self.host}:{self.port}")

        try:
            await self._shutdown_event.wait()
        finally:
            ttl_task.cancel()
            try:
                await ttl_task
            except asyncio.CancelledError:
                pass
            tcp_srv.close()
            await tcp_srv.wait_closed()
            if udp_transport:
                udp_transport.close()
            logger.info("udp-over-tcp exit stopped")


async def _handle_tcp(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    udp_transport: asyncio.DatagramTransport | None,
    route_map: dict[tuple[str, int], asyncio.StreamWriter],
    route_ts: dict[tuple[str, int], float],
) -> None:
    try:
        while True:
            dst_addr, payload = await read_udp_frame(reader)
            remote_key = (dst_addr.host, dst_addr.port)
            route_map[remote_key] = writer
            route_ts[remote_key] = time.monotonic()
            if udp_transport:
                udp_transport.sendto(
                    payload, _map_addr_for_sendto(dst_addr.host, dst_addr.port)
                )
    except (asyncio.IncompleteReadError, ConnectionError, OSError):
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
